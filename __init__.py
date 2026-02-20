# -*- coding: utf-8 -*-
"""
PseudoNote - AI Assistant for IDA Pro
Package initializer. Imports all submodules so they are accessible from the package.
"""

from pseudonote.qt_compat import *
from pseudonote.config import CONFIG, LOGGER
from pseudonote.ai_client import SimpleAI, AI_CLIENT
from pseudonote.highlight import (
    enable_highlighting, disable_highlighting,
    enable_disasm_highlighting, disable_disasm_highlighting,
    toggle_highlight_on_handler, toggle_highlight_off_handler,
    toggle_disasm_highlight_on_handler, toggle_disasm_highlight_off_handler,
    _create_highlight_hooks,
)
from pseudonote.idb_storage import (
    get_netnode, save_to_idb, load_from_idb,
    gather_function_context, format_context_for_prompt, format_context_for_display,
)
from pseudonote.handlers import (
    RenameVariablesHandler, RenameFunctionHandler,
    RenameMalwareFunctionHandler, SuggestFunctionSignatureHandler,
    CommentHandler, DeleteCommentsHandler,
    StructAnalysisHandler, StructAnalysisDialog,
    BulkRenameHandler,
)
from pseudonote.plugin import PseudoNotePlugin
