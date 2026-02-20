# -*- coding: utf-8 -*-
"""
Pseudocode and disassembly highlighting hooks for PseudoNote.
"""

import re

import idaapi
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_segment


HIGHLIGHT_COLOR = 0xE0D8FF  # Light Pink
highlight_plugin_enabled = False

# The Hexrays_Hooks subclass is created lazily via _create_highlight_hooks()
# because ida_hexrays.Hexrays_Hooks may not be fully functional at module parse time.
_HighlightHooksClass = None
_highlight_hooks_instance = None

_highlight_func_call_pattern = re.compile(
    r"\b(?!(?:if|for|while|switch|return|sizeof|catch|else)\b)[a-zA-Z_][a-zA-Z0-9_:]*\s*\(",
    re.IGNORECASE
)
_highlight_prefix_pattern = re.compile(
    r"\b(fn_|wrap_|sub_)[a-zA-Z0-9_]*",
    re.IGNORECASE
)


def _create_highlight_hooks():
    """Create and install the Hexrays_Hooks for pseudocode highlighting."""
    global _HighlightHooksClass, _highlight_hooks_instance

    if _highlight_hooks_instance is not None:
        return _highlight_hooks_instance

    if not ida_hexrays.init_hexrays_plugin():
        print("[PseudoNote] Hex-Rays not available, cannot install highlight hooks")
        return None

    # Define the class HERE, after Hex-Rays is confirmed available
    class _PseudoNoteHighlightHooks(ida_hexrays.Hexrays_Hooks):
        def __init__(self):
            ida_hexrays.Hexrays_Hooks.__init__(self)

        def _apply_highlight(self, vu, pc):
            if pc and highlight_plugin_enabled and len(pc) < 5000:
                for sl in pc:
                    line = sl.line
                    clean_line = ida_lines.tag_remove(line).strip()
                    if _highlight_func_call_pattern.search(clean_line) or \
                       _highlight_prefix_pattern.search(clean_line) or \
                       "goto" in clean_line:
                        sl.bgcolor = HIGHLIGHT_COLOR
            return

        def text_ready(self, vu):
            if highlight_plugin_enabled:
                pc = vu.cfunc.get_pseudocode()
                if pc:
                    self._apply_highlight(vu, pc)
            return 0

    _HighlightHooksClass = _PseudoNoteHighlightHooks
    _highlight_hooks_instance = _PseudoNoteHighlightHooks()
    _highlight_hooks_instance.hook()
    print("[PseudoNote] Highlight hooks installed successfully")
    return _highlight_hooks_instance


class GraphLinearHighlightHooks(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def _highlight_disassembly_calls(self, ea):
        disasm_line = ida_lines.generate_disasm_line(ea, 0)
        lower_line = disasm_line.lower()
        if "call" in lower_line or "jmp" in lower_line or _highlight_prefix_pattern.search(disasm_line):
            idaapi.set_item_color(ea, HIGHLIGHT_COLOR)

    def _remove_highlight(self, ea):
        idaapi.set_item_color(ea, 0xFFFFFFFF)

    def refresh_view(self):
        seg = ida_segment.getseg(idaapi.get_screen_ea())
        if not seg:
            return

        start = seg.start_ea
        end = seg.end_ea
        if highlight_plugin_enabled:
            for ea in range(start, end):
                if idaapi.is_code(idaapi.get_full_flags(ea)):
                    self._highlight_disassembly_calls(ea)
        else:
            for ea in range(start, end):
                if idaapi.is_code(idaapi.get_full_flags(ea)):
                    self._remove_highlight(ea)


# --- Toggle handlers ---

class toggle_highlight_on_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        enable_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) == idaapi.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class toggle_highlight_off_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        disable_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) == idaapi.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class toggle_disasm_highlight_on_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        enable_disasm_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class toggle_disasm_highlight_off_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        disable_disasm_highlighting()
        return 1

    def update(self, ctx):
        if idaapi.get_widget_type(ctx.widget) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


# --- Enable / Disable functions ---

def enable_highlighting():
    global highlight_plugin_enabled
    highlight_plugin_enabled = True
    _create_highlight_hooks()
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        vu.refresh_ctext()
    ida_kernwin.msg("[PseudoNote] Highlighting Enabled (Pseudocode)\n")


def disable_highlighting():
    global highlight_plugin_enabled
    highlight_plugin_enabled = False
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        vu.refresh_ctext()
    ida_kernwin.msg("[PseudoNote] Highlighting Disabled (Pseudocode)\n")


def enable_disasm_highlighting():
    global highlight_plugin_enabled
    highlight_plugin_enabled = True
    ida_kernwin.msg("[PseudoNote] Highlighting Enabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()


def disable_disasm_highlighting():
    global highlight_plugin_enabled
    highlight_plugin_enabled = False
    ida_kernwin.msg("[PseudoNote] Highlighting Disabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()
