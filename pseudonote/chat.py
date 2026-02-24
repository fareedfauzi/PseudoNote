# -*- coding: utf-8 -*-
"""
AI Chat interface for PseudoNote.
Provides a dockable widget to chat with AI about the current function.
"""

import re
import html
import functools
import os

import idaapi
import ida_kernwin
import ida_hexrays
import idc

import json
from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, Signal, qt_cast_flags
from pseudonote.config import CONFIG, LOGGER
import pseudonote.ai_client as _ai_mod
from pseudonote.idb_storage import save_to_idb, load_from_idb

CHAT_HISTORY_TAG = 90

def get_ida_colors():
    """Get theme-aware colors from IDA's palette."""
    app = QtWidgets.QApplication.instance()
    palette = app.palette()

    return {
        "window": palette.color(QtGui.QPalette.Window).name(),
        "window_text": palette.color(QtGui.QPalette.WindowText).name(),
        "base": palette.color(QtGui.QPalette.Base).name(),
        "alt_base": palette.color(QtGui.QPalette.AlternateBase).name(),
        "text": palette.color(QtGui.QPalette.Text).name(),
        "button": palette.color(QtGui.QPalette.Button).name(),
        "button_text": palette.color(QtGui.QPalette.ButtonText).name(),
        "highlight": palette.color(QtGui.QPalette.Highlight).name(),
        "highlight_text": palette.color(QtGui.QPalette.HighlightedText).name(),
        "mid": palette.color(QtGui.QPalette.Mid).name(),
        "dark": palette.color(QtGui.QPalette.Dark).name(),
        "light": palette.color(QtGui.QPalette.Light).name(),
        "link": palette.color(QtGui.QPalette.Link).name(),
    }

def markdown_to_html(text):
    """
    Parse Markdown using Qt's native QTextDocument engine for 'proper' results.
    This handles complex structures like lists and nested formatting much better than regex.
    """
    colors = get_ida_colors()
    
    # We use a QTextDocument to convert Markdown to a clean, theme-aware HTML.
    doc = QtGui.QTextDocument()
    
    # 1. Define a CSS stylesheet that matches IDA's theme for the parsed content
    # Note: QTextDocument supports a limited subset of CSS.
    style = f"""
        body {{ 
            color: {colors['text']}; 
            line-height: 1.4;
        }}
        h1, h2, h3 {{ 
            color: {colors['highlight']}; 
            font-weight: bold;
            margin-top: 12px;
            margin-bottom: 4px;
        }}
        h1 {{ font-size: 1.2em; }}
        h2 {{ font-size: 1.1em; border-bottom: 1px solid {colors['mid']}; }}
        h3 {{ font-size: 1.0em; }}
        
        /* Technical terms / Inline code */
        code {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['link']};
            background-color: transparent;
            font-weight: bold;
        }}
        
        /* Code blocks: Mono with subtle indent, no boxes */
        pre {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['text']};
            margin: 10px 0;
            padding-left: 10px;
        }}
        
        /* Lists: Proper alignment and spacing */
        li {{ margin-bottom: 2px; }}
        ul, ol {{ margin-left: 15px; padding-left: 5px; }}
        
        a {{ color: {colors['link']}; text-decoration: none; }}
    """
    
    doc.setDefaultStyleSheet(style)
    
    # 2. Native Markdown parsing (Qt 5.14+)
    # This is the "proper" way to handle the conversion.
    doc.setMarkdown(text)
    
    # 3. Handle specific formatting tweaks that setMarkdown might miss in translation
    html_content = doc.toHtml()
    
    # Fix potential 'boxy' behavior in generic HTML generation
    html_content = html_content.replace('border: 1px solid', 'border: none')
    
    return html_content

class ChatBubble(QtWidgets.QWidget):
    def __init__(self, text, is_user=True, parent=None):
        super(ChatBubble, self).__init__(parent)
        self.is_user = is_user
        self.setup_ui(text)

    def setup_ui(self, text):
        colors = get_ida_colors()
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        
        main_layout = QtWidgets.QHBoxLayout(self)
        main_layout.setContentsMargins(10, 4, 10, 4)
        main_layout.setSpacing(0)

        # Bubble Container
        self.bubble = QtWidgets.QFrame()
        bubble_layout = QtWidgets.QVBoxLayout(self.bubble)
        bubble_layout.setContentsMargins(20, 15, 20, 15)
        bubble_layout.setSpacing(4)

        self.label = QtWidgets.QLabel()
        self.label.setWordWrap(True)
        
        # Aesthetic font selection: Try 'Inter', fallback to system default
        font = QtGui.QFont("Inter", 10)
        if QtGui.QFontInfo(font).family().lower() != "inter":
            font = QtWidgets.QApplication.font()
            font.setPointSize(10)
        self.label.setFont(font)

        # PySide6 bitwise flag handling
        flags_val = [QtCore.Qt.TextSelectableByMouse, QtCore.Qt.LinksAccessibleByMouse]
        flags = qt_cast_flags(flags_val, QtCore.Qt.TextInteractionFlag)
        self.label.setTextInteractionFlags(flags)
        self.label.setOpenExternalLinks(True)

        if self.is_user:
            self.label.setText(text)
            self.bubble.setStyleSheet(f"""
                QFrame {{
                    background-color: {colors['highlight']};
                    border-radius: 20px;
                    border-bottom-right-radius: 4px;
                }}
                QLabel {{
                    color: {colors['highlight_text']};
                    background: transparent;
                }}
            """)
            main_layout.addStretch()
            main_layout.addWidget(self.bubble)
        else:
            self.label.setTextFormat(QtCore.Qt.RichText)
            # Use the "Proper" Markdown Parser
            self.label.setText(markdown_to_html(text))
            
            self.bubble.setStyleSheet(f"""
                QFrame {{
                    background-color: #ffffff;
                    border-radius: 20px;
                    border-bottom-left-radius: 4px;
                }}
                QLabel {{
                    color: {colors['text']};
                    background: transparent;
                }}
            """)
            main_layout.addWidget(self.bubble)
            main_layout.addStretch()

        bubble_layout.addWidget(self.label)
        
        # Premium sizing for better readability
        self.bubble.setMinimumWidth(450)
        self.bubble.setMaximumWidth(1800) 

class ChatInput(QtWidgets.QWidget):
    submitted = Signal(str)

    def __init__(self, parent=None):
        super(ChatInput, self).__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        input_layout = QtWidgets.QHBoxLayout(self)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(10)

        colors = get_ida_colors()
        self.input_box = QtWidgets.QPlainTextEdit()
        self.input_box.setPlaceholderText("Ask AI about this function...")
        self.input_box.setMaximumHeight(100)
        self.input_box.setMinimumHeight(45)
        self.input_box.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {colors['base']};
                color: {colors['text']};
                border: 1.5px solid {colors['mid']};
                border-radius: 20px;
                padding-left: 15px;
                padding-right: 15px;
                padding-top: 10px;
                font-size: 13px;
            }}
            QPlainTextEdit:focus {{
                border-color: {colors['highlight']};
            }}
        """)
        self.input_box.installEventFilter(self)

        self.send_btn = QtWidgets.QPushButton("↑")
        self.send_btn.setFixedSize(32, 32)
        self.send_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {colors['highlight']};
                color: {colors['highlight_text']};
                border-radius: 16px;
                font-size: 18px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {colors['light']};
            }}
            QPushButton:disabled {{
                background-color: {colors['mid']};
            }}
        """)
        self.send_btn.clicked.connect(self.submit)

        input_layout.addWidget(self.input_box)
        input_layout.addWidget(self.send_btn)

    def eventFilter(self, obj, event):
        if obj is self.input_box and event.type() == QtCore.QEvent.KeyPress:
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if not (event.modifiers() & QtCore.Qt.ShiftModifier):
                    self.submit()
                    return True
        return super(ChatInput, self).eventFilter(obj, event)

    def submit(self):
        text = self.input_box.toPlainText().strip()
        if text:
            self.submitted.emit(text)
            self.input_box.clear()

    def setEnabled(self, enabled):
        self.input_box.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def setFocus(self):
        self.input_box.setFocus()

class IDAChatForm(ida_kernwin.PluginForm):
    def __init__(self, address, function_name, decompiled_code):
        super(IDAChatForm, self).__init__()
        self.address = address
        self.function_name = function_name
        self.decompiled_code = decompiled_code
        
        # System prompt always reflects the current state of decompilation
        self.system_prompt = {"role": "system", "content": f"You are a helpful reverse-engineering assistant analyzes `{function_name}`. Source:\n\n```c\n{decompiled_code}\n```"}
        
        # Load messages from IDB
        self.history = []
        saved_history = load_from_idb(self.address, tag=CHAT_HISTORY_TAG)
        if saved_history:
            try:
                self.history = json.loads(saved_history)
            except Exception as e:
                LOGGER.error(f"Failed to load chat history: {e}")
        
        if not self.history:
            self.history = [self.system_prompt]
        else:
            # Sync the system prompt to the first element
            self.history[0] = self.system_prompt

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.setup_ui()

    def setup_ui(self):
        colors = get_ida_colors()
        self.parent.setStyleSheet(f"background-color: {colors['window']};")
        
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']};")
        h_layout = QtWidgets.QHBoxLayout(header)
        h_layout.setContentsMargins(20, 10, 20, 10)
        
        title_label = QtWidgets.QLabel(f'<span style="font-size: 13px; color: {colors["window_text"]};">Analyzing: </span><b style="font-size: 14px; color: {colors["highlight"]}; font-family: monospace;">{self.function_name}</b>')
        h_layout.addWidget(title_label)
        h_layout.addStretch()
        
        clear_btn = QtWidgets.QPushButton("Clear Conversation")
        clear_btn.setFlat(True)
        clear_btn.setStyleSheet(f"QPushButton {{ color: {colors['mid']}; font-weight: bold; font-size: 14px; }} QPushButton:hover {{ color: {colors['highlight']}; text-decoration: underline; }}")
        clear_btn.clicked.connect(self.clear_chat)
        h_layout.addWidget(clear_btn)
        
        layout.addWidget(header)

        # Chat History
        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll.setStyleSheet("background: transparent;")
        
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(5, 5, 5, 5)
        self.scroll_layout.addStretch()
        
        self.scroll.setWidget(self.scroll_content)
        layout.addWidget(self.scroll, stretch=1)

        # "Asking AI" Indicator with Progress Bar
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setMinimumHeight(40)
        self.typing_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        indicator_layout = QtWidgets.QHBoxLayout(self.typing_container)
        indicator_layout.setContentsMargins(15, 0, 15, 0)
        indicator_layout.setSpacing(10)

        self.typing_indicator = QtWidgets.QLabel("Thinking...")
        self.typing_indicator.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-weight: bold; font-size: 11px;")
        indicator_layout.addWidget(self.typing_indicator)

        self.chat_progress = QtWidgets.QProgressBar()
        self.chat_progress.setRange(0, 0) # Marquee
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        self.chat_progress.setStyleSheet(f"""
            QProgressBar {{ background-color: {colors['window']}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {colors['highlight']}; border-radius: 2px; }}
        """)
        indicator_layout.addWidget(self.chat_progress, 1)

        self.progress_details = QtWidgets.QLabel("")
        self.progress_details.setStyleSheet(f"color: {colors['text']}; font-size: 10px; font-family: monospace;")
        indicator_layout.addWidget(self.progress_details)

        self.typing_container.setVisible(False)
        layout.addWidget(self.typing_container)
        
        # Internal state for tracking chunks
        self._received_chars = 0

        # Input Area
        input_container = QtWidgets.QFrame()
        input_container.setStyleSheet(f"background-color: {colors['window']}; border: none;")
        input_layout = QtWidgets.QVBoxLayout(input_container)
        input_layout.setContentsMargins(15, 10, 15, 15)
        
        self.input_box = ChatInput()
        self.input_box.submitted.connect(self.send_message)
        input_layout.addWidget(self.input_box)
        layout.addWidget(input_container)

        # Initial or Restored messages
        if len(self.history) <= 1:
            welcome_msg = (
                f"I've analyzed this function `{self.function_name}`. How can I help you understand its logic?\n\n"
                "*Note: I am an analysis assistant. I cannot directly perform IDA actions like renaming, "
                "commenting, or patching code in the IDB.*"
            )
            self.add_message(welcome_msg, is_user=False)
        else:
            for msg in self.history[1:]: # Skip system prompt
                content = msg.get('content', '')
                role = msg.get('role', '')
                self.add_message(content, is_user=(role == 'user'))

    def add_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def save_history(self):
        """Persist chat history to IDB."""
        try:
            save_to_idb(self.address, json.dumps(self.history), tag=CHAT_HISTORY_TAG)
        except Exception as e:
            LOGGER.error(f"Failed to save chat history: {e}")

    def clear_chat(self):
        if not ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Clear chat?") == idaapi.ASKBTN_YES:
            return
        while self.scroll_layout.count() > 1:
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.scroll_layout.addStretch()
        self.history = [self.history[0]]
        self.save_history()
        self.add_message("Chat cleared.", is_user=False)

    def send_message(self, text):
        self.add_message(text, is_user=True)
        self.history.append({"role": "user", "content": text})
        self.save_history()
        
        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_message("Error: AI Client not initialized.", is_user=False)
            return

        self.input_box.setEnabled(False)
        self.typing_container.setVisible(True)
        self._received_chars = 0
        self.progress_details.setText("Connecting...")
        
        # Ensure UI updates immediately
        QtWidgets.QApplication.processEvents()

        def on_chunk(text):
            self._received_chars += len(text)
            self.progress_details.setText(f"Streaming: {self._received_chars} chars")

        AI_CLIENT.query_model_async(self.history, self.handle_response, on_chunk=on_chunk)

    def handle_response(self, response, **kwargs):
        finish_reason = kwargs.get("finish_reason", "stop")
        
        if finish_reason == "length" and response:
            # We don't hide typing indicator if continuing
            self.progress_details.setText(f"Continuing... ({len(response)} chars so far)")
            QtWidgets.QApplication.processEvents()
            
            AI_CLIENT = _ai_mod.AI_CLIENT
            
            # Temporary history for continuation prompt
            # We don't want to pollute real history yet
            cont_history = self.history + [{"role": "assistant", "content": response}]
            cont_prompt = "The previous response was cut off. Please continue from exactly where you left off. Do not repeat what you already said."
            cont_history.append({"role": "user", "content": cont_prompt})
            
            def on_c_chunk(text):
                self._received_chars += len(text)
                self.progress_details.setText(f"Streaming (Continued): {self._received_chars} chars")

            def on_c_fin(new_resp, **c_kwargs):
                full_resp = response + (new_resp or "")
                self.handle_response(full_resp, **c_kwargs)

            AI_CLIENT.query_model_async(cont_history, on_c_fin, on_chunk=on_c_chunk)
            return

        self.typing_container.setVisible(False)
        self.progress_details.setText("")
        self.input_box.setEnabled(True)
        self.input_box.setFocus()
        
        if response:
            self.history.append({"role": "assistant", "content": response})
            self.add_message(response, is_user=False)
            self.save_history()
        else:
            self.add_message("Error: No response from AI.", is_user=False)

    def OnClose(self, form):
        pass

def show_chat(address):
    """Open or focus the chat widget for a given function."""
    func = idaapi.get_func(address)
    if not func:
        print("[PseudoNote] No function at current address.")
        return

    name = idc.get_func_name(func.start_ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            print("[PseudoNote] Failed to decompile function.")
            return
        code = str(cfunc)
    except:
        print("[PseudoNote] Error during decompilation.")
        return

    title = f"PseudoNote Chat: {name}"
    widget = ida_kernwin.find_widget(title)
    if widget:
        ida_kernwin.activate_widget(widget, True)
    else:
        form = IDAChatForm(func.start_ea, name, code)
        form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_PERSIST)
