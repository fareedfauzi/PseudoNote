# -*- coding: utf-8 -*-
"""
IDA action handlers for PseudoNote (rename, comment, signature, struct, bulk rename).
"""

import re
import json
import functools

import idaapi
import ida_kernwin
import ida_hexrays
import idc
import ida_lines

from pseudonote.qt_compat import QtWidgets, QtGui
from pseudonote.config import CONFIG, LOGGER
import pseudonote.ai_client as _ai_mod
import pseudonote.chat as _chat
import pseudonote.view as _view_mod


def _get_ai_client():
    return _ai_mod.AI_CLIENT

# Conversation history cache for Ask AI chat (keyed by address or other convo id)
# Stores list of tuples: (role: 'user'|'ai', text)
ASK_AI_HISTORY = {}


# ---------------------------------------------------------------------------
# Rename Variables handler
# ---------------------------------------------------------------------------
def _pn_rename_callback(address, view, response):
    """Apply AI-suggested variable renames to the decompiled function."""
    if not response:
        print("[PseudoNote] Rename Variables: no response from AI.")
        return
    try:
        names = json.loads(response)
    except Exception as e:
        # Try to extract JSON if it's wrapped in markdown or other text
        try:
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                names = json.loads(response[start:end+1])
            else:
                raise e
        except:
            print(f"[PseudoNote] Rename Variables: failed to parse JSON response: {e}")
            return

    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        success = False
        # Try as local variable first
        if idaapi.IDA_SDK_VERSION < 760:
            lvars = {lvar.name: lvar for lvar in view.cfunc.lvars}
            if n in lvars:
                if view.rename_lvar(lvars[n], names[n], True):
                    success = True
        else:
            if ida_hexrays.rename_lvar(function_addr, n, names[n]):
                success = True
        
        # If not a local variable, try as a global name
        if not success:
            ea = idc.get_name_ea_simple(n)
            if ea != idaapi.BADADDR:
                if idc.set_name(ea, names[n], idc.SN_AUTO):
                    success = True
        
        if success:
            replaced.append(n)

    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(fr'\b{n}\b', names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
    print(f"[PseudoNote] Rename Variables: {len(replaced)} item(s) renamed.")


class RenameVariablesHandler(idaapi.action_handler_t):
    """Ask AI to suggest better variable names and apply them automatically."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not decompiler_output or not v: return 0
        
        _view_mod.show_ai_progress("Renaming Variables")
        prompt = (
            "You are an expert reverse engineer. Review the C function code provided below:\n\n{decompiler_output}\n\n"
            "Identify variables with generic or unhelpful names (e.g., v1, a2, result, qword_1234, dword_5678). "
            "Propose more descriptive names based on their usage, context, and data flow. "
            "Output ONLY a valid JSON object mapping the original variable names (keys) to the suggested new names (values). "
            "Do NOT include any explanations or markdown formatting outside the JSON."
        ).format(decompiler_output=str(decompiler_output))
        
        def wrapped_cb(response, **kwargs):
            try: _pn_rename_callback(address=idaapi.get_screen_ea(), view=v, response=response)
            finally: _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, additional_options={"max_completion_tokens": 8192})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Rename Function (Code) handler
# ---------------------------------------------------------------------------
class RenameFunctionHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function name based on code logic and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
        
        prefix = CONFIG.function_prefix if CONFIG.use_rename_prefix else ""
        _view_mod.show_ai_progress("Naming Function (Code)")
        
        prompt = (
            "Analyze the following C function code:\n"
            f"{str(cfunc)}\n"
            "Suggest a concise new name for this function. "
            f"Only reply with the new function name, prefixed with '{prefix}' if appropriate."
        )
        def callback(response, **kwargs):
            try:
                if not response: return
                clean_resp = response.strip().replace("`", "").replace("'", "").replace("\"", "")
                if not clean_resp: return
                new_name = clean_resp.split()[0]
                func = idaapi.get_func(ea)
                if not func: return

                if getattr(CONFIG, 'rename_append_address', False):
                    use_0x = getattr(CONFIG, 'rename_use_0x', False)
                    addr_str = f"{func.start_ea:X}"
                    if use_0x:
                        new_name = f"{new_name}_0x{addr_str}"
                    else:
                        new_name = f"{new_name}_{addr_str}"

                old_name = idc.get_func_name(func.start_ea)
                if new_name == old_name: return
                if idc.set_name(func.start_ea, new_name, idc.SN_AUTO):
                    from pseudonote.idb_storage import save_to_idb
                    save_to_idb(func.start_ea, "renamed_by_pseudonote", tag=83)
                    if vdui: vdui.refresh_view(True)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Rename Function (Malware) handler
# ---------------------------------------------------------------------------
class RenameMalwareFunctionHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function name in malware analysis context and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
        
        prefix = CONFIG.function_prefix if CONFIG.use_rename_prefix else ""
        _view_mod.show_ai_progress("Naming Function (Malware)")
        
        prompt = (
            "Analyze the following C function code in the context of malware reverse engineering:\n"
            f"{str(cfunc)}\n"
            "Suggest a concise new name for this function. "
            f"Only reply with the new function name, prefixed with '{prefix}' if appropriate."
        )
        def callback(response, **kwargs):
            try:
                if not response: return
                clean_resp = response.strip().replace("`", "").replace("'", "").replace("\"", "")
                if not clean_resp: return
                new_name = clean_resp.split()[0]
                func = idaapi.get_func(ea)
                if not func: return

                if getattr(CONFIG, 'rename_append_address', False):
                    use_0x = getattr(CONFIG, 'rename_use_0x', False)
                    addr_str = f"{func.start_ea:X}"
                    if use_0x:
                        new_name = f"{new_name}_0x{addr_str}"
                    else:
                        new_name = f"{new_name}_{addr_str}"

                old_name = idc.get_func_name(func.start_ea)
                if new_name == old_name: return
                if idc.set_name(func.start_ea, new_name, idc.SN_AUTO):
                    from pseudonote.idb_storage import save_to_idb
                    save_to_idb(func.start_ea, "renamed_by_pseudonote", tag=83)
                    if vdui: vdui.refresh_view(True)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS





# ---------------------------------------------------------------------------
# Suggest Function Signature Handler
# ---------------------------------------------------------------------------
class SuggestFunctionSignatureHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function signature and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        try: cfunc = ida_hexrays.decompile(ea)
        except: return 0
             
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
            
        _view_mod.show_ai_progress("Suggesting Signature")
        prompt = (
            "Analyze the following C function code:\n"
            f"{str(cfunc)}\n\n"
            "Suggest a valid C function prototype (signature) for this function.\n"
            "Infer the return type, calling convention, function name, and argument types/names based on usage.\n"
            "Return ONLY the C signature string (e.g. `int __fastcall MyFunc(char *a1, int a2)`).\n"
            "Do not include semicolon or body."
        )
        
        def callback(response, **kwargs):
            try:
                if not response: return
                clean_sig = response.strip().split('{')[0].strip().rstrip(';')
                func = idaapi.get_func(ea)
                if not func: return
                
                msg = f"AI Suggested Signature:\n\n{clean_sig}\n\nApply this signature?"
                if ida_kernwin.ask_yn(1, msg) == 1:
                    if idc.SetType(func.start_ea, clean_sig + ";"):
                        if vdui: vdui.refresh_view(True)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


# ---------------------------------------------------------------------------
# Comment Handler (AI)
# ---------------------------------------------------------------------------
def get_commentable_lines(cfunc):
    """
    Extracts information for each line of decompiled pseudocode.
    Returns: List of tuples: (lineIndex, lineText, comment_address, comment_placement, has_user_comment)
    """
    result = []
    pseudocode_lines = cfunc.get_pseudocode()

    place_comments_above = True 

    for idx, line in enumerate(pseudocode_lines):
        try:
            line_text = idaapi.tag_remove(line.line)
        except:
            line_text = str(line.line)

        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        phead_addr = None
        phead_place = None
        ptail_addr = None
        ptail_place = None

        has_user_comment = False
        comment_address = None
        comment_placement = 0

        try:
            found = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
            if found:
                if not place_comments_above:
                    phead, ptail = ptail, phead

                if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                    try:
                        has_user_comment |= (cfunc.get_user_cmt(phead.loc, True) is not None)
                    except: pass
                    phead_addr = phead.loc.ea
                    phead_place = phead.loc.itp
                
                if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                    try:
                        has_user_comment |= (cfunc.get_user_cmt(ptail.loc, True) is not None)
                    except: pass
                    ptail_addr = ptail.loc.ea
                    ptail_place = ptail.loc.itp

                if phead_addr is not None:
                    comment_address = phead_addr
                    comment_placement = phead_place
                elif ptail_addr is not None:
                    comment_address = ptail_addr
                    comment_placement = ptail_place
        except:
            pass

        result.append((idx, idaapi.tag_remove(line_text), comment_address, comment_placement, has_user_comment))

    return result

def format_commentable_lines(commentable_lines):
    output = []
    for idx, text, comment_address, comment_placement, has_user_comment in commentable_lines:
        prefix = "+" if comment_address is not None and not has_user_comment else ""
        output.append(f"{prefix}{idx}\t{text}")
    return "\n".join(output)

def _pn_comment_callback(cfunc, pseudocode_lines, view, response):
    if not response:
        print("[PseudoNote] Comments: no response from AI.")
        return

    try:
        content = response.strip()
        if "```" in content:
            matches = re.findall(r"```(?:json)?\n(.*?)```", content, re.DOTALL)
            if matches:
                content = matches[0]
            else:
                parts = content.split("```")
                if len(parts) >= 3: content = parts[1]
        
        items = json.loads(content)
    except Exception as exc:
        print(f"[PseudoNote] Comment callback JSON failure: {exc}")
        return

    applied_count = 0
    for line_key, raw_comment in items.items():
        try:
            line_index = int(line_key)
        except ValueError:
            continue

        if line_index < 0 or line_index >= len(pseudocode_lines):
            continue

        comment_address = pseudocode_lines[line_index][2]
        comment_placement = pseudocode_lines[line_index][3]
        if comment_placement is None:
            comment_placement = idaapi.ITP_SEMI

        if comment_address is None or comment_address == idaapi.BADADDR:
            continue

        comment_text = str(raw_comment).strip()
        if not comment_text:
            continue

        # Prepend a newline for better visual spacing (as requested by user)
        comment_text = "\n" + comment_text

        target = idaapi.treeloc_t()
        target.ea = int(comment_address)
        target.itp = comment_placement
        cfunc.set_user_cmt(target, comment_text)
        applied_count += 1

    if applied_count > 0:
        cfunc.save_user_cmts()
        cfunc.del_orphan_cmts()
        if view:
            view.refresh_view(True)
        print(f"[PseudoNote] Applied {applied_count} comments.")
    else:
        print("[PseudoNote] No comments were applied.")

class CommentHandler(idaapi.action_handler_t):
    """Ask AI to add helpful comments to the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        try: cfunc = ida_hexrays.decompile(ea)
        except: return 0
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not v: return 0

        _view_mod.show_ai_progress("Commenting Code")
        pseudocode_lines = get_commentable_lines(cfunc)
        formatted_lines = format_commentable_lines(pseudocode_lines)
        prompt = (
            "You are a reverse-engineering assistant adding helpful pseudocode comments.\n"
            "- Output format (strict): exactly one JSON object mapping integer lineNumber -> string comment.\n"
            "  * No Markdown, no code fences, no explanations outside the JSON object.\n"
            "  * If no comments are warranted, return {}.\n"
            "- Scope: Only annotate lines that start with '+' in the listing below.\n"
            "- Guidance: Explain intent, side-effects, or non-obvious control flow. Skip trivial operations.\n"
            "- Style: Keep comments concise (one sentence when possible).\n"
            "\n"
            "```C\n"
            f"{formatted_lines}\n"
            "```"
        )
        def wrapped_cb(response, **kwargs):
            try: _pn_comment_callback(cfunc=cfunc, pseudocode_lines=pseudocode_lines, view=v, response=response)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, additional_options={"max_completion_tokens": 8192})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DeleteCommentsHandler(idaapi.action_handler_t):
    """Delete all AI-generated comments from the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        try:
            cfunc = ida_hexrays.decompile(ea)
        except:
            print("[PseudoNote] Could not decompile function.")
            return 0
            
        if not cfunc:
            print("[PseudoNote] No pseudocode available.")
            return 0

        # Ask for confirmation
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Are you sure you want to delete ALL comments in this function?") != idaapi.ASKBTN_YES:
             return 0

        pseudocode_lines = cfunc.get_pseudocode()
        deleted_count = 0
        
        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        for line in pseudocode_lines:
            try:
                if cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail):
                    if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                        if cfunc.get_user_cmt(phead.loc, 1):
                            cfunc.set_user_cmt(phead.loc, "")
                            deleted_count += 1
                    if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                        if cfunc.get_user_cmt(ptail.loc, 1):
                            cfunc.set_user_cmt(ptail.loc, "")
                            deleted_count += 1
            except:
                continue

        cfunc.save_user_cmts()
        cfunc.del_orphan_cmts()
        
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if v:
            v.refresh_view(True)
            
        print(f"[PseudoNote] Comments deleted.")
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


# ---------------------------------------------------------------------------
# ASM Section Comment Handler (IDA Disassembly View)
# ---------------------------------------------------------------------------

def _get_asm_sections(start_ea, end_ea):
    """
    Return a list of (ea, label, [insn_text, ...]) tuples for the address
    range [start_ea, end_ea).  A new section starts at start_ea and at every
    address that is a jump/branch target or has a named label.
    """
    import idautils
    sections = []
    current_label = None
    current_ea = None
    current_insns = []

    # Collect all branch-target addresses inside the range
    jump_targets = set()
    for head in idautils.Heads(start_ea, end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            if start_ea <= ref < end_ea:
                jump_targets.add(ref)

    for head in idautils.Heads(start_ea, end_ea):
        is_section_start = (
            head == start_ea
            or head in jump_targets
            or bool(idc.get_name(head))
        )
        if is_section_start:
            if current_ea is not None and current_insns:
                sections.append((current_ea, current_label, current_insns))
            current_ea = head
            current_label = idc.get_name(head) or f"loc_{head:X}"
            current_insns = []
        disasm = idc.generate_disasm_line(head, 0)
        if disasm:
            current_insns.append(disasm)

    if current_ea is not None and current_insns:
        sections.append((current_ea, current_label, current_insns))

    return sections


def _resolve_asm_range(ea):
    """
    Try to resolve a (start_ea, end_ea, context_name) for the given address.
    Priority:
      1. Active selection in the disassembly widget
      2. Enclosing function bounds
    Returns None if neither is available.
    """
    # 1. Try active selection
    ok, sel_start, sel_end = idaapi.read_range_selection(None)
    if ok and sel_start != idaapi.BADADDR and sel_end != idaapi.BADADDR and sel_end > sel_start:
        return sel_start, sel_end, f"selection {hex(sel_start)}–{hex(sel_end)}"

    # 2. Fall back to enclosing function
    func = idaapi.get_func(ea)
    if func:
        name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
        return func.start_ea, func.end_ea, name

    return None


class AsmCommentHandler(idaapi.action_handler_t):
    """Add concise section-level comments to the IDA disassembly view using AI.
    Works on a user selection (for shellcode) or the enclosing function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        import json as _json
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0

        ea = idaapi.get_screen_ea()
        result = _resolve_asm_range(ea)
        if not result:
            print("[PseudoNote] No selection and no function found. "
                  "Select a range of instructions first, or place the cursor inside a defined function.")
            return 0

        start_ea, end_ea, context_name = result
        sections = _get_asm_sections(start_ea, end_ea)
        if not sections:
            print("[PseudoNote] Could not collect disassembly sections in range.")
            return 0

        # Build compact representation for the AI (cap each section at 12 lines)
        lines = []
        for i, (sec_ea, label, insns) in enumerate(sections):
            snippet = "\n  ".join(insns[:12])
            if len(insns) > 12:
                snippet += f"\n  ... ({len(insns) - 12} more)"
            lines.append(f"Section {i+1} [{hex(sec_ea)}] {label}:\n  {snippet}")

        asm_text = "\n\n".join(lines)

        prompt = (
            f"You are an expert reverse engineer analyzing `{context_name}`.\n\n"
            "Below are the logical sections of its disassembly. "
            "For each section provide a VERY SHORT description (≤6 words, plain English, no punctuation).\n\n"
            f"{asm_text}\n\n"
            "Output ONLY valid JSON — a list of objects with keys \"section\" (1-based int) and \"comment\" (string).\n"
            "Example: [{\"section\": 1, \"comment\": \"init stack frame\"}, {\"section\": 2, \"comment\": \"validate argument\"}]\n"
            "No markdown, no extra text."
        )

        _view_mod.show_ai_progress("Annotating Disassembly Sections...")

        def done_cb(response, **kwargs):
            _view_mod.hide_ai_progress()
            if not response:
                print("[PseudoNote] No response from AI.")
                return
            try:
                text = response.strip()
                # Strip optional markdown fences
                if text.startswith("```"):
                    text = "\n".join(text.split("\n")[1:])
                if text.endswith("```"):
                    text = text[:text.rfind("```")]
                text = text.strip()

                items = _json.loads(text)
                applied = 0
                for item in items:
                    idx = item.get("section", 0) - 1
                    cmt = item.get("comment", "").strip()
                    if not cmt or idx < 0 or idx >= len(sections):
                        continue
                    sec_ea = sections[idx][0]
                    idc.set_cmt(sec_ea, cmt, 0)
                    applied += 1

                print(f"[PseudoNote] Applied {applied} section comment(s) to {context_name}.")
                idaapi.request_refresh(idaapi.IWID_DISASM)
            except Exception as e:
                print(f"[PseudoNote] ASM comment parse error: {e}\nRaw: {response[:300]}")

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, done_cb, on_chunk=chunk_cb,
                                    additional_options={"max_completion_tokens": 2048})
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class DeleteAsmCommentsHandler(idaapi.action_handler_t):
    """Delete all regular (non-repeatable) IDA comments in the selected range or enclosing function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        import idautils
        ea = idaapi.get_screen_ea()
        result = _resolve_asm_range(ea)
        if not result:
            print("[PseudoNote] No selection and no function found.")
            return 0

        start_ea, end_ea, context_name = result

        if idaapi.ask_yn(idaapi.ASKBTN_NO,
                         f"Delete all IDA-view comments in {context_name}?") != idaapi.ASKBTN_YES:
            return 0

        deleted = 0
        for head in idautils.Heads(start_ea, end_ea):
            if idc.get_cmt(head, 0):   # regular comment
                idc.set_cmt(head, "", 0)
                deleted += 1
            if idc.get_cmt(head, 1):   # repeatable comment
                idc.set_cmt(head, "", 1)
                deleted += 1

        print(f"[PseudoNote] Deleted {deleted} comment(s) from {context_name}.")
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET




# ---------------------------------------------------------------------------
# Structure Analysis Handler & Dialog
# ---------------------------------------------------------------------------
class StructAnalysisDialog(QtWidgets.QDialog):
    def __init__(self, c_struct, on_apply_callback=None, parent=None):
        super(StructAnalysisDialog, self).__init__(parent)
        self.setWindowTitle("Structure Analysis (AI)")
        self.resize(600, 500)
        
        self.on_apply_callback = on_apply_callback
        
        layout = QtWidgets.QVBoxLayout()
        
        # Editor
        self.editor = QtWidgets.QTextEdit()
        self.editor.setPlainText(c_struct)
        self.editor.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.editor)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        
        copy_btn = QtWidgets.QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(copy_btn)
        
        import_btn = QtWidgets.QPushButton("Import to IDA")
        import_btn.clicked.connect(self.import_to_ida)
        btn_layout.addWidget(import_btn)
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        
    def copy_to_clipboard(self):
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(self.editor.toPlainText())
        print("[PseudoNote] Copied to clipboard.")

    def import_to_ida(self):
        c_code = self.editor.toPlainText()
        try:
            # Check for struct name using regex
            match = re.search(r'struct\s+(\w+)', c_code)
            struct_name = match.group(1) if match else "unknown_struct"
            
            # Simple parse using idc.parse_decls which adds to Local Types
            err = idc.parse_decls(c_code, 0)
            if err == 0:
                msg = f"Structure '{struct_name}' imported to Local Types successfully."
                # If callback provided, ask to apply
                if self.on_apply_callback:
                    reply = QtWidgets.QMessageBox.question(
                        self, "Apply Type", 
                        f"{msg}\n\nDo you want to apply this type to the variable?", 
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
                    )
                    if reply == QtWidgets.QMessageBox.Yes:
                        self.on_apply_callback(struct_name)
                        QtWidgets.QMessageBox.information(self, "Applied", "Variable type updated.")
                else:
                    QtWidgets.QMessageBox.information(self, "Success", msg + "\n(Open Shift+F1 to view)")
            else:
                 QtWidgets.QMessageBox.warning(self, "Import Failed", f"IDA failed to parse the C code (Error code: {err}).\nCheck text for syntax errors.")
        except Exception as e:
             QtWidgets.QMessageBox.critical(self, "Error", f"Exception during import: {e}")


class StructAnalysisHandler(idaapi.action_handler_t):
    """Analyze a variable usage to infer a C structure."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        widget = ctx.widget
        wtype = ctx.widget_type
        
        target_name = ""
        target_code = "" 
        vdui = None
        target_lvar_name = None
        
        if wtype == idaapi.BWN_PSEUDOCODE:
            vdui = ida_hexrays.get_widget_vdui(widget)
            if not vdui: return 0
            
            # Check item under cursor
            item = vdui.item
            if item:
                # Case 1: Cursor on a local variable expression (usage)
                if item.citype == ida_hexrays.VDI_EXPR and item.e:
                    if item.e.op == ida_hexrays.cot_var:
                        lvar = vdui.cfunc.get_lvars()[item.e.v.idx]
                        target_name = lvar.name
                        target_lvar_name = lvar.name
                    elif item.e.op == ida_hexrays.cot_obj:
                         name = idc.get_name(item.e.obj_ea)
                         if name: target_name = name
                
                # Case 2: Cursor on local var declaration (e.g. at top of function)
                elif item.citype == ida_hexrays.VDI_LVAR and item.l:
                    target_name = item.l.name
                    target_lvar_name = item.l.name
            
            if not target_name:
                print("[PseudoNote] Please right-click directly on a variable name.")
                return 0
            
            # Get function code
            try:
                target_code = str(vdui.cfunc)
            except:
                pass
                
        else:
            print("[PseudoNote] Structure analysis currently supports Pseudocode view only.")
            return 0
            
        if not target_name or not target_code: return 0
            
        _view_mod.show_ai_progress(f"Analyzing Struct: {target_name}")
        # Prepare Prompt
        prompt = (
            f"Analyze the C code below. Focus on the usage of variable `{target_name}`.\n"
            f"Infer the most likely C structure definition that `{target_name}` represents (or points to).\n"
            "Analyze all dereferences (e.g. `v5 + 16`, `v5->field_10`) to find fields.\n"
            "Return ONLY the C struct definition valid for an IDA header input.\n"
            "Start the struct name with `Struct_{target_name}` or a descriptive name.\n\n"
            "```c\n"
            f"{target_code}\n"
            "```"
        )
        
        def wrapped_cb(response, **kwargs):
            _view_mod.hide_ai_progress()
            try: 
                self.handle_response(target_name=target_name, vdui=vdui, lvar_name=target_lvar_name, response=response)
            except Exception as e:
                print(f"[PseudoNote] Struct Analysis Error: {e}")

        if AI_CLIENT:
            total_chars = [0]
            def chunk_cb(t):
                total_chars[0] += len(t)
                _view_mod.update_ai_progress_details(total_chars[0])

            AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, on_status=_view_mod.update_ai_progress_details, additional_options={"max_completion_tokens": 8192})
        return 1

    def handle_response(self, target_name, vdui, lvar_name, response):
        if not response: 
            print("[PseudoNote] Struct Analysis: No response from AI.")
            return
        
        # Extract C code from AI response
        c_struct = response.strip()
        if "```" in c_struct:
            parts = c_struct.split("```")
            for i in range(1, len(parts), 2):
                p = parts[i].strip()
                if p:
                    # Strip language tags if present
                    lines = p.split('\n')
                    if lines and lines[0].strip().lower() in ["c", "cpp"]:
                        c_struct = "\n".join(lines[1:]).strip()
                    else:
                        c_struct = p
                    break
        
        # Define apply callback to update the variable type in IDA
        def on_apply(type_name):
            if not vdui or not lvar_name: return False
            try:
                for lvar in vdui.cfunc.get_lvars():
                    if lvar.name == lvar_name:
                        new_type = idaapi.tinfo_t()
                        # parse_decl expects "TYPE NAME;" snippet to infer the type
                        if idaapi.parse_decl(new_type, None, f"{type_name} dummy;", 0):
                            if vdui.set_lvar_type(lvar, new_type):
                                vdui.refresh_view(True)
                                return True
            except Exception as e:
                print(f"[PseudoNote] Failed to apply struct type: {e}")
            return False

        # Create and show the result dialog
        dlg = StructAnalysisDialog(c_struct, on_apply_callback=on_apply)
        dlg.exec_()

    def update(self, ctx):
        """Enable this action only for the Pseudocode view (where structure analysis is supported)."""
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

# ---------------------------------------------------------------------------
# Bulk Rename Handler
# ---------------------------------------------------------------------------
class BulkRenameHandler(idaapi.action_handler_t):
    """Launch the Bulk Function Renamer Dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None

    def activate(self, ctx):
        if not CONFIG.active_provider:
            print("[PseudoNote] AI Provider not configured.")
            return 0
            
        try:
            from pseudonote import renamer
            
            self.dlg = renamer.BulkRenamer(CONFIG, parent=None)
            self.dlg.show()
        except Exception as e:
            print(f"[PseudoNote] Error launching Bulk Renamer: {e}")
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Ask AI (Chat) Handler
# ---------------------------------------------------------------------------
class AskAIHandler(idaapi.action_handler_t):
    """Open a chat interface to ask questions about the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        _chat.show_chat(idaapi.get_screen_ea())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



class SettingsHandler(idaapi.action_handler_t):
    """Open the API Settings dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # We need to reach the view or at least the config
        # The view usually has the on_settings method
        import pseudonote.view as vm
        if vm._view_instance:
            vm._view_instance.on_settings()
        else:
            # Fallback if view not open: open a standalone dialog
            d = vm.SettingsDialog(CONFIG)
            d.exec_()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ShellcodeAnalystHandler(idaapi.action_handler_t):
    """Open the Shellcode Analysis dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # We need to get the view module lazily
        import pseudonote.view as _view_mod
        
        # Gather data from selection if possible
        hex_data = ""
        asm_data = ""
        
        selection, start_ea, end_ea = idaapi.read_range_selection(None)
        if not selection:
            # Fallback to current item if no selection
            start_ea = idaapi.get_screen_ea()
            end_ea = idc.next_head(start_ea)
        
        if start_ea != idaapi.BADADDR:
            try:
                # Gather bytes
                bytes_count = end_ea - start_ea
                if 0 < bytes_count < 10000: # Safety limit
                    blob = idaapi.get_bytes(start_ea, bytes_count)
                    if blob:
                        hex_data = blob.hex(" ").upper()
                
                # Gather assembly
                items = []
                curr = start_ea
                while curr < end_ea and curr != idaapi.BADADDR:
                    items.append(curr)
                    curr = idc.next_head(curr, end_ea)
                
                asm_lines = []
                for ea in items:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        asm_lines.append(line)
                asm_data = "\n".join(asm_lines)

                # BUG FIX: If we only got one line of assembly but the range is multiple bytes,
                # and it's not explicitly code, it's likely we just hit the start of a data blob.
                # In this case, clear asm_data to force fallback to hex_data (which is complete).
                if len(asm_lines) == 1 and (end_ea - start_ea) > 1:
                    flags = idaapi.get_full_flags(start_ea)
                    if not idc.is_code(flags):
                        asm_data = ""
            except:
                pass

        dialog = _view_mod.ShellcodeAnalystDialog(hex_data, asm_data)
        dialog.show()
        # Keep a reference to prevent GC if needed
        if not hasattr(_view_mod, "_shellcode_analyst_dialogs"):
            _view_mod._shellcode_analyst_dialogs = []
        _view_mod._shellcode_analyst_dialogs.append(dialog)
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_DISABLE_FOR_WIDGET
        return idaapi.AST_ENABLE_ALWAYS
