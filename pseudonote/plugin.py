# -*- coding: utf-8 -*-
"""
PseudoNotePlugin — the main IDA plugin_t subclass.
"""
import idaapi
import ida_hexrays

from pseudonote.qt_compat import QtWidgets
from pseudonote.config import CONFIG
from pseudonote.ai_client import SimpleAI
import pseudonote.ai_client as _ai_mod
from pseudonote.highlight import (
    _create_highlight_hooks,
    toggle_highlight_on_handler,
    toggle_highlight_off_handler,
    toggle_disasm_highlight_on_handler,
    toggle_disasm_highlight_off_handler,
)
from pseudonote.handlers import (
    RenameVariablesHandler,
    RenameFunctionHandler,
    RenameMalwareFunctionHandler,
    SuggestFunctionSignatureHandler,
    CommentHandler,
    DeleteCommentsHandler,
    StructAnalysisHandler,
    BulkRenameHandler,
)

# These will be imported lazily to avoid circular imports
_view_module = None

def _get_view_module():
    global _view_module
    if _view_module is None:
        import pseudonote.view as _vm
        _view_module = _vm
    return _view_module


class PseudoNotePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "PseudoNote: AI Assistant for IDA Pro"
    help = "Generate readable code and comments with AI"
    wanted_name = "PseudoNote"
    wanted_hotkey = "Ctrl-Shift-G"

    def __init__(self):
        super(PseudoNotePlugin, self).__init__()
        self.view = None
        self.hooks = None
        self.config = CONFIG
        self.ctx_hooks = None
        self.highlight_hooks = None

    def init(self):
        if not QtWidgets:
            return idaapi.PLUGIN_SKIP

        vm = _get_view_module()
        vm.plugin_instance = self

        _ai_mod.AI_CLIENT = SimpleAI(self.config)

        # Register Highlighter Actions (Pseudocode)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:highlight_on", "Enable Highlighting (Pseudocode)",
            toggle_highlight_on_handler(), "",
            "Enable function call highlighting in pseudocode", 199
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:highlight_off", "Disable Highlighting (Pseudocode)",
            toggle_highlight_off_handler(), "",
            "Disable function call highlighting in pseudocode", 199
        ))
        # Register Highlighter Actions (Disasm)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:disasm_highlight_on", "Enable Highlighting (Graph/Linear)",
            toggle_disasm_highlight_on_handler(), "",
            "Enable function call highlighting in Graph/Linear view", 199
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:disasm_highlight_off", "Disable Highlighting (Graph/Linear)",
            toggle_disasm_highlight_off_handler(), "",
            "Disable function call highlighting in Graph/Linear view", 199
        ))

        if ida_hexrays.init_hexrays_plugin():
            self.highlight_hooks = _create_highlight_hooks()
        else:
            print("[PseudoNote] Hex-Rays not available at init time, hooks will be installed on first enable")
            self.highlight_hooks = None

        print("-" * 60)
        print("PseudoNote initialized.")
        print("Use Ctrl+Shift+G or Edit -> PseudoNote to open.")
        print("-" * 60)

        action_desc = idaapi.action_desc_t(
            "pseudonote:action",
            "Show PseudoNote Panes",
            vm.PseudoNoteHandler(),
            "Ctrl+Alt+G",
            "Open PseudoNote AI Assistant",
            199
        )
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Show PseudoNote Panes", "pseudonote:action", idaapi.SETMENU_APP)

        list_action_desc = idaapi.action_desc_t(
            "pseudonote:list",
            "View saved Codes and Notes",
            vm.SavedNotesHandler(),
            "Ctrl+Alt+L",
            "List all functions with saved PseudoNotes",
            58
        )
        idaapi.register_action(list_action_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/View saved Codes and Notes", "pseudonote:list", idaapi.SETMENU_APP)

        rename_func_desc = idaapi.action_desc_t(
            "pseudonote:rename_function",
            "Rename Function (Code)",
            RenameFunctionHandler(),
            "Ctrl+Alt+N",
            "Use AI to rename the current function based on its code logic",
            203
        )
        idaapi.register_action(rename_func_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Rename Function (Code)", "pseudonote:rename_function", idaapi.SETMENU_APP)

        rename_malware_desc = idaapi.action_desc_t(
            "pseudonote:rename_function_malware",
            "Rename Function (Malware)",
            RenameMalwareFunctionHandler(),
            "Ctrl+Alt+M",
            "Use AI to rename the current function in a malware analysis context",
            204
        )
        idaapi.register_action(rename_malware_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Rename Function (Malware)", "pseudonote:rename_function_malware", idaapi.SETMENU_APP)

        rename_vars_desc = idaapi.action_desc_t(
            "pseudonote:rename_variables",
            "Rename Variables",
            RenameVariablesHandler(),
            "Ctrl+Alt+R",
            "Use AI to rename variables in the current function",
            19
        )
        idaapi.register_action(rename_vars_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Rename Variables", "pseudonote:rename_variables", idaapi.SETMENU_APP)

        # Suggest Function Signature Action
        sugg_sig_desc = idaapi.action_desc_t(
            "pseudonote:suggest_function_signature",
            "Function Signature",
            SuggestFunctionSignatureHandler(),
            "Ctrl+Alt+S",
            "Ask AI to infer and apply a function signature",
            138
        )
        idaapi.register_action(sugg_sig_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Function Signature", "pseudonote:suggest_function_signature", idaapi.SETMENU_APP)

        comment_handler_desc = idaapi.action_desc_t(
            "pseudonote:add_comments",
            "Add Comments",
            CommentHandler(),
            "Ctrl+Alt+C",
            "Ask AI to add helpful comments to the current function",
            45
        )
        idaapi.register_action(comment_handler_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Add Comments", "pseudonote:add_comments", idaapi.SETMENU_APP)

        delete_comments_desc = idaapi.action_desc_t(
            "pseudonote:delete_comments",
            "Delete Comments",
            DeleteCommentsHandler(),
            "Ctrl+Alt+D",
            "Delete all comments from the current function",
            45
        )
        idaapi.register_action(delete_comments_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Delete Comments", "pseudonote:delete_comments", idaapi.SETMENU_APP)

        # Structure Analysis Action
        struct_action_desc = idaapi.action_desc_t(
            "pseudonote:analyze_struct", "Analyze Structure",
            StructAnalysisHandler(), "",
            "Analyze variable usage to infer structure", 101
        )
        idaapi.register_action(struct_action_desc)

        # Bulk Rename Functions Action
        bulk_rename_desc = idaapi.action_desc_t(
            "pseudonote:bulk_rename",
            "Bulk Rename Functions",
            BulkRenameHandler(),
            "Ctrl+Shift+R",
            "Rename multiple functions using AI strategies",
            205
        )
        idaapi.register_action(bulk_rename_desc)

        self.ctx_hooks = vm.ContextMenuHooks()
        self.ctx_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open_view()

    def term(self):
        if self.ctx_hooks:
            self.ctx_hooks.unhook()
            self.ctx_hooks = None

        # Detach all menu items
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Show PseudoNote Panes", "pseudonote:action")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Rename Variables", "pseudonote:rename_variables")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Rename Function (Code)", "pseudonote:rename_function")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Rename Function (Malware)", "pseudonote:rename_function_malware")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Function Signature", "pseudonote:suggest_function_signature")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Add Comments", "pseudonote:add_comments")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Delete Comments", "pseudonote:delete_comments")

        # Unregister all actions
        for action_id in [
            "pseudonote:action", "pseudonote:list",
            "pseudonote:rename_variables", "pseudonote:rename_function",
            "pseudonote:rename_function_malware", "pseudonote:suggest_function_signature",
            "pseudonote:add_comments", "pseudonote:delete_comments",
            "pseudonote:analyze_struct", "pseudonote:bulk_rename",
            "pseudonote:highlight_on", "pseudonote:highlight_off",
            "pseudonote:disasm_highlight_on", "pseudonote:disasm_highlight_off",
        ]:
            idaapi.unregister_action(action_id)

    def open_view(self):
        vm = _get_view_module()
        if not self.view:
            self.view = vm.PseudoNoteView(self.config)
        self.view.Show("PseudoNote")

    def Unregister(self):
        if self.view:
            self.view.Close()
            self.view = None
