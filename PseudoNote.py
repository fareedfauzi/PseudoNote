# -*- coding: utf-8 -*-
"""
PseudoNote — IDA Pro AI Assistant Plugin (entry point).
This file is placed in IDA's plugins/ directory and delegates to the
pseudonote package.
"""
from pseudonote.plugin import PseudoNotePlugin

def PLUGIN_ENTRY():
    return PseudoNotePlugin()
