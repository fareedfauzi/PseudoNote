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
    toggle_highlight_handler,
    toggle_disasm_highlight_handler,
)
from pseudonote.xrefs import DnspyXrefsHandler
from pseudonote.handlers import (
    RenameVariablesHandler,
    RenameFunctionHandler,
    RenameMalwareFunctionHandler,
    SuggestFunctionPrototypeHandler,
    CommentHandler,
    DeleteCommentsHandler,
    AsmCommentHandler,
    DeleteAsmCommentsHandler,
    StructAnalysisHandler,
    BulkRenameHandler,
    SettingsHandler,
    AskAIHandler,
    ShellcodeAnalystHandler,
    BulkVarRenameHandler,
    BulkAnalyzeHandler,
    SearchBytesVTHandler,
    SearchStringHandler,
    SearchBytesCyberChefHandler,
    FlossStringsHandler,
    AdvancedCopyHandler,
)
from pseudonote.deep_analyzer import DeepAnalyzerHandler
from pseudonote.summarizer import SummarizerHandler

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
        # Register Highlighter Actions (Pseudocode)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:toggle_highlight", "Toggle Call Highlight (Pseudocode)",
            toggle_highlight_handler(), "Ctrl+Alt+H",
            "Toggle function call highlighting in pseudocode", 48
        ))
        # Register Highlighter Actions (Disasm)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:toggle_disasm_highlight", "Toggle Call Highlight (Graph/Linear)",
            toggle_disasm_highlight_handler(), "Ctrl+Shift+H",
            "Toggle function call highlighting in Graph/Linear view", 48
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
            109
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

        # Register Settings Action
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:settings",
            "Configure Settings...",
            SettingsHandler(),
            "Ctrl+Alt+P",
            "Configure AI Provider and Performance settings",
            147
        ))
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Configure Settings...", "pseudonote:settings", idaapi.SETMENU_APP)

        rename_func_desc = idaapi.action_desc_t(
            "pseudonote:rename_function",
            "Rename Function (Code)",
            RenameFunctionHandler(),
            "Ctrl+Alt+N",
            "Use AI to rename the current function based on its code logic",
            204
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
            203
        )
        idaapi.register_action(rename_vars_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Rename Variables", "pseudonote:rename_variables", idaapi.SETMENU_APP)

        # Suggest Function Prototype Action
        sugg_sig_desc = idaapi.action_desc_t(
            "pseudonote:suggest_function_prototype",
            "Function Prototype",
            SuggestFunctionPrototypeHandler(),
            "Ctrl+Alt+S",
            "Ask AI to infer and apply a function prototype",
            138
        )
        idaapi.register_action(sugg_sig_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Function Prototype", "pseudonote:suggest_function_prototype", idaapi.SETMENU_APP)

        comment_handler_desc = idaapi.action_desc_t(
            "pseudonote:add_comments",
            "Add Comments",
            CommentHandler(),
            "Ctrl+Alt+C",
            "Ask AI to add helpful comments to the current function",
            45
        )
        idaapi.register_action(comment_handler_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Add Comments (Pseudocode)", "pseudonote:add_comments", idaapi.SETMENU_APP)

        asm_comment_handler_desc = idaapi.action_desc_t(
            "pseudonote:add_asm_comments",
            "Add Section Comments (IDA-View)",
            AsmCommentHandler(),
            "Ctrl+Shift+C",
            "Ask AI to add concise section comments to the disassembly",
            45
        )
        idaapi.register_action(asm_comment_handler_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Add Section Comments (IDA-View)", "pseudonote:add_asm_comments", idaapi.SETMENU_APP)

        del_asm_comments_desc = idaapi.action_desc_t(
            "pseudonote:delete_asm_comments",
            "Delete IDA-View Comments",
            DeleteAsmCommentsHandler(),
            "Ctrl+Shift+D",
            "Delete all IDA-view comments in the selected range or enclosing function",
            45
        )
        idaapi.register_action(del_asm_comments_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Delete Comments (IDA-View)", "pseudonote:delete_asm_comments", idaapi.SETMENU_APP)

        # Shellcode Analysis (Static)
        shell_analyst_desc = idaapi.action_desc_t(
            "pseudonote:shellcode_analyst",
            "Shellcode Analysis (Static)",
            ShellcodeAnalystHandler(),
            "Ctrl+Shift+E",
            "Open the static shellcode analysis window",
            124
        )
        idaapi.register_action(shell_analyst_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Shellcode Analysis (Static)", "pseudonote:shellcode_analyst", idaapi.SETMENU_APP)

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

        xrefs_desc = idaapi.action_desc_t(
            "pseudonote:dnspy_xrefs",
            "Call Tree",
            DnspyXrefsHandler(),
            "Ctrl+Alt+X",
            "View interactive dnSpy style call hierarchy",
            73
        )
        idaapi.register_action(xrefs_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Call Tree...", "pseudonote:dnspy_xrefs", idaapi.SETMENU_APP)

        # Structure Analysis Action
        struct_action_desc = idaapi.action_desc_t(
            "pseudonote:analyze_struct", "Struct editor",
            StructAnalysisHandler(), "Ctrl+Alt+E",
            "Analyze variable usage to infer structure", 101
        )
        idaapi.register_action(struct_action_desc)

        # Bulk Rename Functions Action
        bulk_rename_desc = idaapi.action_desc_t(
            "pseudonote:bulk_rename",
            "Bulk Functions Renamer",
            BulkRenameHandler(),
            "Ctrl+Shift+R",
            "Rename multiple functions using AI strategies",
            205
        )
        idaapi.register_action(bulk_rename_desc)
        
        # Bulk Function Analyzer Action
        bulk_analyze_desc = idaapi.action_desc_t(
            "pseudonote:bulk_analyze",
            "Bulk Function Analyzer",
            BulkAnalyzeHandler(),
            "Ctrl+Shift+A",
            "Open the AI bulk function analysis and tagging window",
            110
        )
        idaapi.register_action(bulk_analyze_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Bulk Function Analyzer", "pseudonote:bulk_analyze", idaapi.SETMENU_APP)

        # Deep Analyzer Action
        deep_analyzer_desc = idaapi.action_desc_t(
            "pseudonote:deep_analyzer",
            "Bulk Deep Analyzer",
            DeepAnalyzerHandler(),
            "Ctrl+Shift+S",
            "Automated bottom-up recursive function analysis and summarization",
            122
        )
        idaapi.register_action(deep_analyzer_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Deep Analyzer", "pseudonote:deep_analyzer", idaapi.SETMENU_APP)

        # Summarizer Action
        summarizer_desc = idaapi.action_desc_t(
            "pseudonote:summarizer",
            "Summarizer",
            SummarizerHandler(),
            "Ctrl+Alt+Z",
            "A light version of Deep Analyzer to summarize the entire function chain",
            122
        )
        idaapi.register_action(summarizer_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Summarizer", "pseudonote:summarizer", idaapi.SETMENU_APP)

        # Bulk Variable Renamer Action
        bulk_var_rename_desc = idaapi.action_desc_t(
            "pseudonote:bulk_var_rename",
            "Bulk Variable Renamer",
            BulkVarRenameHandler(),
            "Ctrl+Shift+V",
            "Rename local variables in bulk using AI",
            206
        )
        idaapi.register_action(bulk_var_rename_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Bulk Variable Renamer", "pseudonote:bulk_var_rename", idaapi.SETMENU_APP)
        
        # FLOSS Strings Discovery Action
        floss_strings_desc = idaapi.action_desc_t(
            "pseudonote:floss_strings",
            "FLOSS Strings Discovery",
            FlossStringsHandler(),
            "Ctrl+Shift+F",
            "Discover strings built dynamically (Stack, Tight, Decoded) using FLOSS",
            183
        )
        idaapi.register_action(floss_strings_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/FLOSS Strings Discovery", "pseudonote:floss_strings", idaapi.SETMENU_APP)

        ask_chat_desc = idaapi.action_desc_t(
            "pseudonote:ask_chat",
            "Ask Chat (AI)",
            AskAIHandler(),
            "Ctrl+Alt+A",
            "Open a chat to ask AI about the current function",
            124
        )
        idaapi.register_action(ask_chat_desc)
        idaapi.attach_action_to_menu("Edit/Plugins/PseudoNote/Ask Chat (AI)", "pseudonote:ask_chat", idaapi.SETMENU_APP)

        # Register Search Utils Actions
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_bytes_vt", "Search bytes in VirusTotal",
            SearchBytesVTHandler(), "",
            "Search highlighted bytes in VirusTotal", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_bytes_cyberchef", "Add bytes to CyberChef input",
            SearchBytesCyberChefHandler(), "",
            "Add highlighted bytes to CyberChef input", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_str_vt", "Search string in VirusTotal",
            SearchStringHandler("vt"), "",
            "Search string in VirusTotal", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_str_google", "Search string in Google",
            SearchStringHandler("google"), "",
            "Search string in Google", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_str_github", "Search string in GitHub",
            SearchStringHandler("github"), "",
            "Search string in GitHub", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_str_msdn", "Search string (WinAPI) in MSDN",
            SearchStringHandler("msdn"), "",
            "Search string (WinAPI) in MSDN Documentation", 128
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote:search_str_cyberchef", "Add strings to CyberChef input",
            SearchStringHandler("cyberchef"), "",
            "Add string to CyberChef input", 128
        ))
        
        # Advanced Copy Actions
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_yara_raw", "Copy Hex Bytes", AdvancedCopyHandler("yara_raw"), "", "Copy selected bytes as hex string", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_yara_rule", "Generate Yara Rule for the bytes", AdvancedCopyHandler("yara_rule"), "", "Generate a simple Yara rule from selected bytes", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_yara_mask", "Copy Hex (Mask Targets/Relocs)", AdvancedCopyHandler("yara_mask"), "", "Copy selected bytes masking jumps and memory references", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_yara_no_imm", "Copy Hex (Mask Immediates)", AdvancedCopyHandler("yara_no_imm"), "", "Copy selected bytes masking immediates and addresses", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_yara_opcodes", "Copy Hex (Opcodes Only)", AdvancedCopyHandler("yara_opcodes"), "", "Copy selected bytes masking everything but opcodes", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_python", "Copy Python byte literal", AdvancedCopyHandler("python"), "", 'Copy selected bytes as python string', 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_c_array", "Copy C/C++ array", AdvancedCopyHandler("c_array"), "", "Copy selected bytes as a C array", 31))
        idaapi.register_action(idaapi.action_desc_t("pseudonote:copy_disasm", "Copy Disassembly Text", AdvancedCopyHandler("disasm"), "", "Copy selected disassembly lines", 31))

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
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Function Prototype", "pseudonote:suggest_function_prototype")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Add Comments (Pseudocode)", "pseudonote:add_comments")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Add Section Comments (IDA-View)", "pseudonote:add_asm_comments")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Delete Comments (IDA-View)", "pseudonote:delete_asm_comments")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Shellcode Analysis (Static)", "pseudonote:shellcode_analyst")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Delete Comments", "pseudonote:delete_comments")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Ask Chat (AI)", "pseudonote:ask_chat")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Bulk Variable Renamer", "pseudonote:bulk_var_rename")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Deep Analyzer", "pseudonote:deep_analyzer")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/Summarizer", "pseudonote:summarizer")
        idaapi.detach_action_from_menu("Edit/Plugins/PseudoNote/FLOSS Strings Discovery", "pseudonote:floss_strings")

        # Unregister all actions
        for action_id in [
            "pseudonote:action", "pseudonote:list",
            "pseudonote:rename_variables", "pseudonote:rename_function",
            "pseudonote:rename_function_malware", "pseudonote:suggest_function_prototype",
            "pseudonote:add_comments", "pseudonote:delete_comments",
            "pseudonote:add_asm_comments", "pseudonote:delete_asm_comments",
            "pseudonote:shellcode_analyst",
            "pseudonote:analyze_struct", "pseudonote:bulk_rename",
            "pseudonote:bulk_var_rename",
            "pseudonote:toggle_highlight", "pseudonote:toggle_disasm_highlight",
            "pseudonote:ask_chat", "pseudonote:deep_analyzer", "pseudonote:summarizer", "pseudonote:floss_strings",
            "pseudonote:search_bytes_vt", "pseudonote:search_str_vt",
            "pseudonote:search_str_google", "pseudonote:search_str_github",
            "pseudonote:search_str_msdn", "pseudonote:search_bytes_cyberchef",
            "pseudonote:search_str_cyberchef", "pseudonote:copy_yara_raw",
            "pseudonote:copy_yara_rule", "pseudonote:copy_yara_mask",
            "pseudonote:copy_yara_no_imm", "pseudonote:copy_yara_opcodes",
            "pseudonote:copy_python", "pseudonote:copy_c_array", "pseudonote:copy_disasm",
        ]:
            idaapi.unregister_action(action_id)

    def open_view(self, ea=idaapi.BADADDR):
        vm = _get_view_module()
        if not self.view:
            self.view = vm.PseudoNoteView(self.config)
        self.view._target_ea = ea if ea != idaapi.BADADDR else idaapi.get_screen_ea()
        self.view.Show("PseudoNote")
        if ea != idaapi.BADADDR:
            self.view.refresh_ui(force=True, target_ea=ea)

    def Unregister(self):
        if self.view:
            self.view.Close()
            self.view = None
