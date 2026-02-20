# -*- coding: utf-8 -*-
"""
Custom code and markdown editor widgets for PseudoNote.
"""

import re

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, get_text_width


if QtWidgets:
    class LineNumberArea(QtWidgets.QWidget):
        def __init__(self, editor):
            super(LineNumberArea, self).__init__(editor)
            self.codeEditor = editor

        def sizeHint(self):
            return QtCore.QSize(self.codeEditor.lineNumberAreaWidth(), 0)

        def paintEvent(self, event):
            self.codeEditor.lineNumberAreaPaintEvent(event)


    class CodeEditor(QtWidgets.QPlainTextEdit):
        def __init__(self):
            super(CodeEditor, self).__init__()
            self.lineNumberArea = LineNumberArea(self)
            self.blockCountChanged.connect(self.updateLineNumberAreaWidth)
            self.updateRequest.connect(self.updateLineNumberArea)
            self.cursorPositionChanged.connect(self.highlightCurrentLine)
            self.updateLineNumberAreaWidth(0)
            self.highlightCurrentLine()

        def lineNumberAreaWidth(self):
            digits = 1
            max_val = max(1, self.blockCount())
            while max_val >= 10:
                max_val //= 10
                digits += 1
            space = 3 + get_text_width(self.fontMetrics(), '9') * digits + 5
            return space

        def updateLineNumberAreaWidth(self, _):
            self.setViewportMargins(self.lineNumberAreaWidth(), 0, 0, 0)

        def updateLineNumberArea(self, rect, dy):
            if dy:
                self.lineNumberArea.scroll(0, dy)
            else:
                self.lineNumberArea.update(0, rect.y(), self.lineNumberArea.width(), rect.height())
            if rect.contains(self.viewport().rect()):
                self.updateLineNumberAreaWidth(0)

        def resizeEvent(self, event):
            super(CodeEditor, self).resizeEvent(event)
            cr = self.contentsRect()
            self.lineNumberArea.setGeometry(QtCore.QRect(cr.left(), cr.top(), self.lineNumberAreaWidth(), cr.height()))

        def lineNumberAreaPaintEvent(self, event):
            painter = QtGui.QPainter(self.lineNumberArea)
            painter.fillRect(event.rect(), QtGui.QColor("#252526"))

            block = self.firstVisibleBlock()
            blockNumber = block.blockNumber()
            top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
            bottom = top + int(self.blockBoundingRect(block).height())

            while block.isValid() and top <= event.rect().bottom():
                if block.isVisible() and bottom >= event.rect().top():
                    number = str(blockNumber + 1)
                    painter.setPen(QtGui.QColor("#858585"))
                    painter.drawText(0, top, self.lineNumberArea.width() - 5, self.fontMetrics().height(),
                                     QtCore.Qt.AlignRight, number)
                block = block.next()
                top = bottom
                bottom = top + int(self.blockBoundingRect(block).height())
                blockNumber += 1

        def highlightCurrentLine(self):
            extraSelections = []
            if not self.isReadOnly():
                selection = QtWidgets.QTextEdit.ExtraSelection()
                lineColor = QtGui.QColor("#2a2d2e")
                selection.format.setBackground(lineColor)
                selection.format.setProperty(QtGui.QTextFormat.FullWidthSelection, True)
                selection.cursor = self.textCursor()
                selection.cursor.clearSelection()
                extraSelections.append(selection)
            self.setExtraSelections(extraSelections)


    class MarkdownEditor(CodeEditor):
        def keyPressEvent(self, event):
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                cursor = self.textCursor()
                block = cursor.block()
                text = block.text()


                task_pat = r'^(\s*)([-*+])\s+\[([ xX]?)\]\s+'

                bullet_pat = r'^(\s*)([-*+])\s+'

                num_pat = r'^(\s*)(\d+)(\.)\s+'

                match = re.match(task_pat, text)
                if match:
                    prefix = match.group(1)
                    bullet = match.group(2)
                    content = text[match.end():].strip()
                    if not content:
                        self.terminate_list(cursor)
                    else:
                        self.continue_list(cursor, f"{prefix}{bullet} [ ] ")
                    return

                match = re.match(bullet_pat, text)
                if match:
                    prefix = match.group(1)
                    bullet = match.group(2)
                    content = text[match.end():].strip()
                    if not content:
                        self.terminate_list(cursor)
                    else:
                        self.continue_list(cursor, f"{prefix}{bullet} ")
                    return

                match = re.match(num_pat, text)
                if match:
                    prefix = match.group(1)
                    num = int(match.group(2))
                    dot = match.group(3)
                    content = text[match.end():].strip()
                    if not content:
                         self.terminate_list(cursor)
                    else:
                         self.continue_list(cursor, f"{prefix}{num + 1}{dot} ")
                    return

            super().keyPressEvent(event)

        def continue_list(self, cursor, text):
            cursor.insertBlock()
            cursor.insertText(text)
            self.ensureCursorVisible()

        def terminate_list(self, cursor):
            cursor.beginEditBlock()
            cursor.select(QtGui.QTextCursor.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.insertBlock()
            cursor.endEditBlock()
            self.ensureCursorVisible()
else:
    LineNumberArea = None
    CodeEditor = None
    MarkdownEditor = None
