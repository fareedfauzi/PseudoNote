# -*- coding: utf-8 -*-
"""
Qt compatibility layer for PseudoNote.
Handles PyQt5 / PySide2 / PySide6 differences.
"""

import importlib

QtWidgets = None
QtCore = None
QtGui = None
QtPrintSupport = None

def _try_import(backend):
    global QtWidgets, QtCore, QtGui, QtPrintSupport
    try:
        QtWidgets = importlib.import_module(f"{backend}.QtWidgets")
        QtCore = importlib.import_module(f"{backend}.QtCore")
        QtGui = importlib.import_module(f"{backend}.QtGui")
    except ImportError:
        return False
        
    try:
        QtPrintSupport = importlib.import_module(f"{backend}.QtPrintSupport")
    except ImportError:
        QtPrintSupport = None
        
    return True

if not _try_import("PyQt5"):
    if not _try_import("PySide2"):
        if not _try_import("PySide6"):
            if not _try_import("PyQt6"):
                print("[PseudoNote] Qt not found (PyQt5, PySide2, PySide6 or PyQt6 required).")

# Flattening for easier imports
def _export_module_safe(mod):
    if mod:
        for k in dir(mod):
            if not k.startswith('__'):
                try:
                    globals()[k] = getattr(mod, k)
                except Exception:
                    pass

_export_module_safe(QtWidgets)
_export_module_safe(QtGui)
_export_module_safe(QtCore)
_export_module_safe(QtPrintSupport)


def get_text_width(fm, text):
    if hasattr(fm, "horizontalAdvance"):
        return fm.horizontalAdvance(text)
    return fm.width(text)


def set_tab_stop_width(editor, width):
    if hasattr(editor, "setTabStopDistance"):
        editor.setTabStopDistance(width)
    else:
        editor.setTabStopWidth(width)


def qt_cast_flags(flags, flag_type):
    """Cast flags safely. Handle PySide6 bitwise operation warnings."""
    def to_int(f):
        if hasattr(f, 'value'): # PySide6
            return f.value
        try:
            return int(f)
        except:
            return f

    if isinstance(flags, (list, tuple)):
        res = 0
        for f in flags:
            val = to_int(f)
            if isinstance(val, int):
                res |= val
        flags = res
    else:
        flags = to_int(flags)
        
    if flag_type is not None:
        try:
            # In PySide6, calling the flag type with int returns the flag object
            return flag_type(flags)
        except:
            # Fallback to int if the type is not a proper Enum/Flag or fails
            pass
    return flags


# ---------- QRegExp compatibility shim for PySide6 / PyQt6 ----------
if QtWidgets and not hasattr(QtCore, "QRegExp"):
    class QRegExpWrapper(QtCore.QRegularExpression):
        def __init__(self, pattern="", options=0, syntax=0):
            if isinstance(pattern, QtCore.QRegularExpression):
                super().__init__(pattern)
            else:
                super().__init__(pattern)
                if options & 1:  # CaseInsensitive
                    self.setPatternOptions(self.patternOptions() | QtCore.QRegularExpression.CaseInsensitiveOption)
            self._last_match = None

        def indexIn(self, text, offset=0):
            self._last_match = self.match(text, offset)
            if self._last_match.hasMatch():
                return self._last_match.capturedStart()
            return -1

        def matchedLength(self):
            if self._last_match:
                return self._last_match.capturedLength()
            return -1

        def setCaseSensitivity(self, cs):
            if cs == QtCore.Qt.CaseInsensitive:
                self.setPatternOptions(self.patternOptions() | QtCore.QRegularExpression.CaseInsensitiveOption)
            else:
                self.setPatternOptions(self.patternOptions() & ~QtCore.QRegularExpression.CaseInsensitiveOption)

    QtCore.QRegExp = QRegExpWrapper

# ---------- Signal/Slot compatibility ----------
if QtCore:
    Signal = getattr(QtCore, "pyqtSignal", getattr(QtCore, "Signal", None))
    Slot = getattr(QtCore, "pyqtSlot", getattr(QtCore, "Slot", None))
else:
    Signal = None
    Slot = None

# ---------- Optional AI libraries ----------
try:
    import openai
    import httpx
except ImportError:
    openai = None
    print("[PseudoNote] OpenAI or httpx not found. AI features will be disabled.")

try:
    import anthropic
except ImportError:
    anthropic = None

try:
    import google.generativeai as genai
except ImportError:
    genai = None
