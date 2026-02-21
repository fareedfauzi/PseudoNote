# -*- coding: utf-8 -*-
"""
Qt compatibility layer for PseudoNote.
Handles PyQt5 / PySide2 / PySide6 differences.
"""

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except ImportError:
    try:
        from PySide2 import QtWidgets, QtCore, QtGui
    except ImportError:
        try:
            from PySide6 import QtWidgets, QtCore, QtGui
        except ImportError:
            QtWidgets = None
            QtCore = None
            QtGui = None
            print("[PseudoNote] Qt not found (PyQt5, PySide2 or PySide6 required).")

# Flattening for easier imports
if QtWidgets:
    # We use __dict__.update to avoid massive explicit lists
    # This makes 'from pseudonote.qt_compat import QPushButton' work
    globals().update({k: v for k, v in QtWidgets.__dict__.items() if not k.startswith('__')})
if QtGui:
    globals().update({k: v for k, v in QtGui.__dict__.items() if not k.startswith('__')})
if QtCore:
    globals().update({k: v for k, v in QtCore.__dict__.items() if not k.startswith('__')})


def get_text_width(fm, text):
    if hasattr(fm, "horizontalAdvance"):
        return fm.horizontalAdvance(text)
    return fm.width(text)


def set_tab_stop_width(editor, width):
    if hasattr(editor, "setTabStopDistance"):
        editor.setTabStopDistance(width)
    else:
        editor.setTabStopWidth(width)


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

# ---------- Signal compatibility ----------
if QtCore:
    Signal = getattr(QtCore, "pyqtSignal", getattr(QtCore, "Signal", None))
else:
    Signal = None

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
