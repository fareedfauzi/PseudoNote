# -*- coding: utf-8 -*-
"""
IDB (NetNode) storage helpers and function context gathering for PseudoNote.
"""

import re

import idaapi
import ida_netnode
import ida_hexrays
import ida_nalt
import idc
import idautils

NETNODE_NAME = "$ pseudonote:readable_c"
_NETNODE_CACHE = None


def get_netnode(create=False):
    global _NETNODE_CACHE
    if _NETNODE_CACHE is None:
        try:
            node = ida_netnode.netnode(NETNODE_NAME, 0, False)
            if node and node != ida_netnode.BADNODE:
                _NETNODE_CACHE = node
        except: pass

    if _NETNODE_CACHE is None and create:
        try:
            _NETNODE_CACHE = ida_netnode.netnode(NETNODE_NAME, 0, True)
        except: pass

    return _NETNODE_CACHE


def save_to_idb(func_ea, content, tag=0):
    if content is None: return
    node = get_netnode(create=True)
    if not node: return
    try:
        node.setblob(content.encode('utf-8'), func_ea, tag)
    except: pass


def load_from_idb(func_ea, tag=0):
    node = get_netnode(create=False)
    if not node: return None
    try:
        data = node.getblob(func_ea, tag)
        if data: return data.decode('utf-8')
    except: pass
    return None


def gather_function_context(func_ea, max_callers=8, max_caller_lines=40):
    """
    Gather deep context for a function: callers, callees, and string references.
    Returns a dict with 'callers', 'callees_api', 'callees_internal', 'strings'.
    """
    context = {
        "callers": [],
        "callees_api": [],
        "callees_internal": [],
        "strings": [],
    }

    func = idaapi.get_func(func_ea)
    if not func:
        return context

    # --- Callers (XREFs TO) ---
    caller_eas = set()
    for xref in idautils.CodeRefsTo(func_ea, 0):
        caller_func = idaapi.get_func(xref)
        if caller_func and caller_func.start_ea != func_ea:
            caller_eas.add(caller_func.start_ea)

    for caller_ea in list(caller_eas)[:max_callers]:
        caller_name = idc.get_func_name(caller_ea)
        snippet = ""
        try:
            cfunc = ida_hexrays.decompile(caller_ea)
            if cfunc:
                lines = str(cfunc).split('\n')
                snippet = '\n'.join(lines[:max_caller_lines])
        except:
            pass

        context["callers"].append({
            "name": caller_name or f"sub_{caller_ea:X}",
            "address": f"0x{caller_ea:X}",
            "snippet": snippet
        })

    # --- Callees (XREFs FROM) ---
    seen_callees = set()
    for item_ea in idautils.FuncItems(func_ea):
        for xref_ea in idautils.CodeRefsFrom(item_ea, 0):
            callee_func = idaapi.get_func(xref_ea)
            if not callee_func or callee_func.start_ea == func_ea:
                continue
            callee_start = callee_func.start_ea
            if callee_start in seen_callees:
                continue
            seen_callees.add(callee_start)

            callee_name = idc.get_func_name(callee_start)
            if not callee_name:
                continue

            flags = idc.get_func_attr(callee_start, idc.FUNCATTR_FLAGS)
            is_library = bool(flags & idc.FUNC_LIB) if flags and flags != -1 else False
            is_thunk = bool(flags & idc.FUNC_THUNK) if flags and flags != -1 else False
            is_import = callee_name.startswith("__imp_")

            entry = {"name": callee_name, "address": f"0x{callee_start:X}"}

            if is_library or is_thunk or is_import:
                context["callees_api"].append(entry)
            else:
                context["callees_internal"].append(entry)

    # --- String References ---
    seen_strings = set()
    for item_ea in idautils.FuncItems(func_ea):
        for xref_ea in idautils.DataRefsFrom(item_ea):
            str_type = idc.get_str_type(xref_ea)
            if str_type is not None and str_type >= 0:
                s = idc.get_strlit_contents(xref_ea, -1, str_type)
                if s:
                    decoded = None
                    # Heuristic: Prioritize ASCII/UTF-8 unless explicitly Wide
                    is_wide = str_type in (ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_C_32)
                    
                    if is_wide:
                        try: decoded = s.decode('utf-16', errors='replace')
                        except: pass
                    
                    # If not wide or decoding failed, try UTF-8/ASCII
                    if not decoded:
                        try: decoded = s.decode('utf-8', errors='strict') # Strict checking for UTF-8 first
                        except: 
                            # Fallback to loose UTF-8
                            try: decoded = s.decode('utf-8', errors='replace')
                            except: decoded = str(s)

                    if decoded:
                         # Clean up string (remove nulls, strip whitespace)
                         decoded = decoded.replace('\x00', '').strip()
                         
                         # Filter out tiny garbage or accidental CJK from ASCII reinterpretation
                         # (If we got CJK chars but it wasn't marked as wide, it's suspicious)
                         if not is_wide and any(ord(c) > 0x4e00 and ord(c) < 0x9fff for c in decoded):
                             # Re-try forcibly as ASCII/Latin-1 if it looks like CJK noise
                             try: decoded = s.decode('latin-1', errors='replace').strip()
                             except: pass

                         if decoded and len(decoded) > 1 and decoded not in seen_strings:
                            seen_strings.add(decoded)
                            context["strings"].append(decoded)

    return context


def format_context_for_prompt(context):
    """Format gathered context into a string suitable for inclusion in AI prompts."""
    parts = []

    if context["callers"]:
        parts.append(f"## Callers — Who calls this function ({len(context['callers'])} references)")
        for i, caller in enumerate(context["callers"], 1):
            parts.append(f"### {i}. {caller['name']} ({caller['address']})")
            if caller["snippet"]:
                parts.append(f"```c\n{caller['snippet']}\n```")
            else:
                parts.append("(decompilation not available)")
        parts.append("")

    if context["callees_api"] or context["callees_internal"]:
        total = len(context["callees_api"]) + len(context["callees_internal"])
        parts.append(f"## Callees — What this function calls ({total} calls)")
        if context["callees_api"]:
            parts.append("### API / Library")
            for c in context["callees_api"]:
                parts.append(f"- {c['name']}")
        if context["callees_internal"]:
            parts.append("### Internal Functions")
            for c in context["callees_internal"]:
                parts.append(f"- {c['name']} ({c['address']})")
        parts.append("")

    if context["strings"]:
        parts.append(f"## String References ({len(context['strings'])})")
        for s in context["strings"]:
            parts.append(f'- "{s}"')
        parts.append("")

    return "\n".join(parts)


def format_context_for_display(context):
    """Format gathered context for display in the Function Details tab (compact, no code snippets)."""
    parts = []

    # Callers
    parts.append(f"## Callers ({len(context['callers'])})")
    if context["callers"]:
        for caller in context["callers"]:
            parts.append(f"- {caller['name']} ({caller['address']})")
    else:
        parts.append("- none")
    parts.append("")

    # Callees
    if context["callees_api"] or context["callees_internal"]:
        total = len(context["callees_api"]) + len(context["callees_internal"])
        parts.append(f"## Callees ({total})")
        if context["callees_api"]:
            for c in context["callees_api"]:
                parts.append(f"- {c['name']}")
        if context["callees_internal"]:
            for c in context["callees_internal"]:
                parts.append(f"- {c['name']} ({c['address']})")
    else:
        parts.append("## Callees")
        parts.append("- none")
    parts.append("")

    # Strings
    parts.append("## Strings")
    if context["strings"]:
        for s in context["strings"]:
            parts.append(f'- "{s}"')
    else:
        parts.append("- none")
    parts.append("")

    return "\n".join(parts)
