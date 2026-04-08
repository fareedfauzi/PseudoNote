# -*- coding: utf-8 -*-
"""
AI Chat interface for multiple functions in a chain.
Allows users to select specific functions from a call graph and chat about them.
"""

import idaapi
import ida_funcs
import idautils
import idc
import html
import time
import json
import threading
from pseudonote.qt_compat import (
    QtWidgets, QtCore, QtGui, QThread, Signal, Slot, QDialog,
    QVBoxLayout, QHBoxLayout, QSplitter, QTextBrowser, QPushButton,
    QLabel, QProgressBar, QSpinBox, QGroupBox, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox
)
import pseudonote.ai_client as _ai_mod
from pseudonote.config import CONFIG, LOGGER
from pseudonote.deep_analyzer import build_call_graph, FuncNode, STYLES_ANALYZER
from pseudonote.renamer import get_code_fast
from pseudonote.chat import ChatBubble, ChatInput, get_ida_colors, get_chat_font
from pseudonote.idb_storage import save_to_idb, load_from_idb

CHAIN_CHAT_HISTORY_TAG = 97

class ChatChainWorker(QThread):
    log_signal = Signal(str, str)
    finished_signal = Signal(object)
    
    def __init__(self, entry_ea, max_depth, max_funcs):
        super().__init__()
        self.entry_ea = entry_ea
        self.max_depth = max_depth
        self.max_funcs = max_funcs
        self._stop = False
        
    def stop(self):
        self._stop = True
        
    def run(self):
        self.log_signal.emit(f"Building function graph from 0x{self.entry_ea:X}...", "info")
        
        # Temporarily restrict graph builder
        old_max_depth = getattr(CONFIG, 'max_graph_depth', 15)
        old_max_nodes = getattr(CONFIG, 'max_graph_nodes', 500)
        
        CONFIG.max_graph_depth = self.max_depth
        CONFIG.max_graph_nodes = max(500, self.max_funcs * 3) 

        try:
            graph = build_call_graph(self.entry_ea, stop_checker=lambda: self._stop, log_fn=lambda m, l: self.log_signal.emit(m, l))
        finally:
            CONFIG.max_graph_depth = old_max_depth
            CONFIG.max_graph_nodes = old_max_nodes
            
        if self._stop: return
        
        if not graph:
            self.log_signal.emit("No function graph could be built.", "err")
            print(f"[PseudoNote] ERROR: build_call_graph returned empty for 0x{self.entry_ea:X}")
            return
            
        print(f"[PseudoNote] Graph discovery for 0x{self.entry_ea:X} found {len(graph)} total nodes.")
        self.log_signal.emit(f"Found {len(graph)} total functions.", "ok")
        self.finished_signal.emit(graph)

class ChatChainDialog(QtWidgets.QDialog):
    def __init__(self, entry_ea=None):
        super().__init__(None)
        self.setWindowTitle("Ask Chat (Multiple Functions Chain)")
        self.resize(1200, 800)
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowMaximizeButtonHint | QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.setStyleSheet(STYLES_ANALYZER)
        
        self.entry_ea = entry_ea or idc.get_screen_ea()
        self.graph = {}
        self.worker = None
        self.history = []
        
        self.setup_ui()
        self.on_use_current_function()
        self.load_history()

    def setup_ui(self):
        colors = get_ida_colors()
        self.setStyleSheet(f"background-color: {colors['window']};")
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Header Panel
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']}; border-bottom: 1px solid {colors['mid']};")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(15, 10, 15, 10)
        
        entry_row = QHBoxLayout()
        self.entry_label = QLabel("Entry:")
        self.entry_label.setStyleSheet(f"color: {colors['window_text']}; font-weight: bold;")
        entry_row.addWidget(self.entry_label)
        
        self.entry_edit = QLineEdit()
        self.entry_edit.setReadOnly(True)
        self.entry_edit.setFrame(False)
        self.entry_edit.setStyleSheet(f"color: {colors['highlight']}; font-family: monospace; font-size: 13px; background: transparent;")
        entry_row.addWidget(self.entry_edit, 1)
        
        clear_btn = QPushButton("Clear History")
        clear_btn.setFlat(True)
        clear_btn.setStyleSheet(f"QPushButton {{ color: {colors['mid']}; font-weight: bold; font-size: 11px; }} QPushButton:hover {{ color: {colors['highlight']}; text-decoration: underline; }}")
        clear_btn.clicked.connect(self.clear_chat)
        entry_row.addWidget(clear_btn)
        header_layout.addLayout(entry_row)
        
        config_row = QHBoxLayout()
        load_btn = QPushButton("Current Func")
        load_btn.clicked.connect(self.on_use_current_function)
        config_row.addWidget(load_btn)
        
        config_row.addWidget(QLabel("Depth:"))
        self.depth_sp = QSpinBox()
        self.depth_sp.setRange(1, 20)
        self.depth_sp.setValue(10)
        config_row.addWidget(self.depth_sp)
        
        config_row.addWidget(QLabel("Max Funcs:"))
        self.func_sp = QSpinBox()
        self.func_sp.setRange(1, 1000)
        self.func_sp.setValue(100)
        config_row.addWidget(self.func_sp)
        
        self.build_btn = QPushButton("Load Functions List")
        self.build_btn.setObjectName("primary")
        self.build_btn.clicked.connect(self.start_build)
        config_row.addWidget(self.build_btn)
        header_layout.addLayout(config_row)
        
        main_layout.addWidget(header)

        # Main Splitter
        self.splitter = QSplitter(QtCore.Qt.Horizontal)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {colors['mid']}; }}")
        
        # Left Side (Selector)
        left_widget = QtWidgets.QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(10, 10, 10, 10)
        
        self.func_table = QTableWidget(0, 4)
        self.func_table.setHorizontalHeaderLabels(["", "Address", "Function Name", "Depth"])
        self.func_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.func_table.setColumnWidth(0, 30)
        self.func_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.func_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.func_table.setStyleSheet(STYLES_ANALYZER)
        left_layout.addWidget(self.func_table)
        
        sel_btn_layout = QHBoxLayout()
        all_btn = QPushButton("Select All")
        all_btn.clicked.connect(lambda: self.set_all_checks(True))
        none_btn = QPushButton("Deselect All")
        none_btn.clicked.connect(lambda: self.set_all_checks(False))
        sel_btn_layout.addWidget(all_btn)
        sel_btn_layout.addWidget(none_btn)
        left_layout.addLayout(sel_btn_layout)
        
        self.splitter.addWidget(left_widget)
        
        # Right Side (Chat)
        right_widget = QtWidgets.QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        self.chat_area = QtWidgets.QScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.chat_area.setStyleSheet(f"background-color: {colors['window']};")
        
        self.chat_content = QtWidgets.QWidget()
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(10, 10, 10, 10)
        self.chat_layout.setSpacing(10)
        self.chat_layout.addStretch() # Push messages to top
        
        self.chat_area.setWidget(self.chat_content)
        right_layout.addWidget(self.chat_area, 1)
        
        # Typing indicator
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setVisible(False)
        self.typing_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        ti_layout = QHBoxLayout(self.typing_container)
        ti_layout.setContentsMargins(15, 8, 15, 8)
        
        self.typing_lbl = QLabel("AI is thinking...")
        self.typing_lbl.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-size: 11px;")
        ti_layout.addWidget(self.typing_lbl)
        self.chat_progress = QProgressBar()
        self.chat_progress.setRange(0, 0)
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        ti_layout.addWidget(self.chat_progress)
        right_layout.addWidget(self.typing_container)
        
        self.chat_input = ChatInput()
        self.chat_input.submitted.connect(self.on_chat_submit)
        
        input_wrap = QtWidgets.QWidget()
        input_wrap_layout = QVBoxLayout(input_wrap)
        input_wrap_layout.setContentsMargins(15, 10, 15, 15)
        input_wrap_layout.addWidget(self.chat_input)
        right_layout.addWidget(input_wrap)
        
        self.splitter.addWidget(right_widget)
        self.splitter.setSizes([400, 800])
        main_layout.addWidget(self.splitter, 1)
        
        # Log/Status Area
        self.status_bar = QHBoxLayout()
        self.status_bar.setContentsMargins(10, 2, 10, 2)
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color: {colors['mid']}; font-size: 10px;")
        self.status_bar.addWidget(self.status_lbl)
        main_layout.addLayout(self.status_bar)

    def on_use_current_function(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            # Update text always to ensure UI is in sync
            self.entry_edit.setText(f"0x{f.start_ea:X} - {idc.get_func_name(f.start_ea)}")
            
            if self.entry_ea != f.start_ea:
                self.save_history() # Save old history
                self.entry_ea = f.start_ea
                self.history = [] # Reset local state
                
                # Clear chat bubbles (Keep the stretch at the bottom)
                while self.chat_layout.count() > 1:
                    item = self.chat_layout.takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()
                
                self.load_history() # Load new history
        else:
            self.status_lbl.setText("No function at cursor.")

    def start_build(self):
        if self.worker and self.worker.isRunning():
            return
            
        self.build_btn.setEnabled(False)
        self.func_table.setRowCount(0)
        self.status_lbl.setText("Building graph...")
        
        self.worker = ChatChainWorker(self.entry_ea, self.depth_sp.value(), self.func_sp.value())
        self.worker.log_signal.connect(lambda m, l: self.status_lbl.setText(m))
        self.worker.finished_signal.connect(self.on_graph_built)
        self.worker.start()

    def on_graph_built(self, graph):
        self.build_btn.setEnabled(True)
        self.graph = graph

        print(f"[PseudoNote] on_graph_built received {len(graph)} nodes.")
        
        nodes = []
        for ea, n in graph.items():
            is_lib = getattr(n, 'is_library', False)
            depth = getattr(n, 'depth', -1)
            
            if len(nodes) < 5:
                print(f"[PseudoNote] Node 0x{ea:X}: depth={depth}, is_lib={is_lib}, type={type(n)}")
                
            if not is_lib or depth == 0:
                nodes.append(n)

        nodes.sort(key=lambda n: getattr(n, 'depth', 0))
        
        if not nodes and graph:
            print(f"[PseudoNote] Fallback triggered. Graph size: {len(graph)}")
            nodes = list(graph.values())
            nodes.sort(key=lambda n: getattr(n, 'depth', 0))

        self.func_table.setRowCount(len(nodes))
        for i, node in enumerate(nodes):
            # Checkbox
            cb_container = QtWidgets.QWidget()
            cb_layout = QHBoxLayout(cb_container)
            cb_layout.setContentsMargins(5, 0, 0, 0)
            cb = QCheckBox()
            cb.setChecked(True)
            cb_layout.addWidget(cb)
            cb_layout.setAlignment(QtCore.Qt.AlignCenter)
            self.func_table.setCellWidget(i, 0, cb_container)
            
            # Address
            addr_item = QTableWidgetItem(f"0x{node.ea:X}")
            addr_item.setData(QtCore.Qt.UserRole, node.ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 1, addr_item)
            
            # Name
            name_item = QTableWidgetItem(node.name)
            name_item.setFlags(name_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 2, name_item)
            
            # Depth
            depth_item = QTableWidgetItem(str(node.depth))
            depth_item.setFlags(depth_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 3, depth_item)
            
        self.status_lbl.setText(f"Graph built: {len(nodes)} functions available.")

    def set_all_checks(self, checked):
        for i in range(self.func_table.rowCount()):
            cw = self.func_table.cellWidget(i, 0)
            if cw:
                cb = cw.findChild(QCheckBox)
                if cb:
                    cb.setChecked(checked)

    def get_selected_eas(self):
        eas = []
        for i in range(self.func_table.rowCount()):
            cw = self.func_table.cellWidget(i, 0)
            if cw:
                cb = cw.findChild(QCheckBox)
                if cb and cb.isChecked():
                    item = self.func_table.item(i, 1)
                    if item:
                        eas.append(item.data(QtCore.Qt.UserRole))
        return eas

    def on_chat_submit(self, text):
        selected_eas = self.get_selected_eas()
        if not selected_eas:
            QtWidgets.QMessageBox.warning(self, "Selection", "Please select at least one function to talk about.")
            return

        # Add user message to UI
        self.add_chat_message(text, is_user=True)
        
        # Prepare context if history is empty
        if not self.history:
            self.status_lbl.setText("Gathering decompiled code...")
            
            code_blocks = []
            def _gather_code():
                for ea in selected_eas:
                    # Request more code (30k chars) to ensure full function logic is captured
                    c = get_code_fast(ea, max_len=30000) 
                    if c:
                        name = idc.get_func_name(ea) or f"sub_{ea:X}"
                        code_blocks.append(f"### Function: {name} (0x{ea:X})\n```c\n{c}\n```\n")
            
            idaapi.execute_sync(_gather_code, idaapi.MFF_READ)
            
            if not code_blocks:
                self.add_chat_message("Error: Could not retrieve code.", is_user=False)
                return

            self.pending_question = text
            self.start_context_injection(code_blocks)
        else:
            self.history.append({"role": "user", "content": text})
            self.query_ai()

    def start_context_injection(self, blocks):
        """Send code blocks in chunks to avoid context/token overflow errors."""
        self.chunk_size = 25000 # Max characters per message part
        self.blocks_to_send = blocks
        self.current_block_idx = 0
        
        # Initial system persona
        self.history = [{"role": "system", "content": "You are a professional reverse engineering assistant. I will provide you with several function implementations in multiple parts. Please acknowledge each part with 'OK' and do not provide analysis until I ask a question."}]
        
        self.send_next_context_chunk()

    def send_next_context_chunk(self):
        if self.current_block_idx < len(self.blocks_to_send):
            current_chunk_text = ""
            count = 0
            while self.current_block_idx < len(self.blocks_to_send):
                block = self.blocks_to_send[self.current_block_idx]
                # If adding this block exceeds chunk size, and we already have some content, break
                if len(current_chunk_text) + len(block) > self.chunk_size and current_chunk_text != "":
                    break
                current_chunk_text += block + "\n"
                self.current_block_idx += 1
                count += 1
            
            progress = f" (Part {self.current_block_idx}/{len(self.blocks_to_send)})"
            self.status_lbl.setText(f"Injecting context...{progress}")
            
            prompt = f"System Context Update - Functions Data (Part {self.current_block_idx} of {len(self.blocks_to_send)}):\n\n{current_chunk_text}\n\nPlease acknowledge with 'OK'."
            self.history.append({"role": "user", "content": prompt})
            
            self.chat_input.setEnabled(False)
            self.typing_container.setVisible(True)
            
            AI_CLIENT = _ai_mod.AI_CLIENT
            if AI_CLIENT:
                AI_CLIENT.query_model_async(self.history, self.on_context_chunk_received)
            else:
                self.add_chat_message("Error: AI Client disconnected.", is_user=False)
        else:
            # All blocks sent! Now send the actual user question
            self.status_lbl.setText("All context injected. Analyzing question...")
            self.history.append({"role": "user", "content": self.pending_question})
            self.query_ai()

    def on_context_chunk_received(self, response, **kwargs):
        if response:
            self.history.append({"role": "assistant", "content": response})
            # Continue to next chunk
            self.send_next_context_chunk()
        else:
            self.add_chat_message("Error during context injection sequence.", is_user=False)
            self.typing_container.setVisible(False)
            self.chat_input.setEnabled(True)

    def query_ai(self):
        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_chat_message("Error: AI Client not configured.", is_user=False)
            return

        self.chat_input.setEnabled(False)
        self.typing_container.setVisible(True)
        self.status_lbl.setText("AI is processing...")
        
        def fin_cb(response, **kwargs):
            self.typing_container.setVisible(False)
            self.chat_input.setEnabled(True)
            self.chat_input.setFocus()
            
            if response:
                self.history.append({"role": "assistant", "content": response})
                self.add_chat_message(response, is_user=False)
                self.status_lbl.setText("Analysis complete.")
            else:
                self.add_chat_message("Error: No response from AI.", is_user=False)
                self.status_lbl.setText("AI Error.")

        AI_CLIENT.query_model_async(self.history, fin_cb)

    def add_chat_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        # Prevent bubbles from taking 100% width on wide displays (fix aesthetics)
        bubble.bubble.setMinimumWidth(10)
        # Dynamic resizing with a reasonable cap
        max_w = min(800, int(self.chat_area.width() * 0.8)) if self.chat_area.width() > 200 else 400
        bubble.bubble.setMaximumWidth(max_w)
        
        # Insert before the stretch (which is at index count-1)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def clear_chat(self):
        if not QtWidgets.QMessageBox.question(self, "Clear Chat", "Clear entire conversation history?") == QtWidgets.QMessageBox.Yes:
            return
        
        # Keep only the stretch
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        self.history = []
        self.save_history()
        self.load_history() # Reload (will show welcome or stay empty)
        self.status_lbl.setText("History cleared.")

    def save_history(self):
        if not self.history or self.entry_ea == idaapi.BADADDR:
            return
        try:
            data = json.dumps(self.history)
            save_to_idb(self.entry_ea, data, tag=CHAIN_CHAT_HISTORY_TAG)
        except Exception as e:
            print(f"[PseudoNote] Error saving history: {e}")

    def load_history(self):
        if self.entry_ea == idaapi.BADADDR:
            return
        try:
            data = load_from_idb(self.entry_ea, tag=CHAIN_CHAT_HISTORY_TAG)
            if data:
                self.history = json.loads(data)
                # Populate UI (skip system messages)
                for msg in self.history:
                    if msg['role'] in ('user', 'assistant'):
                        # Check if it was a system context update message (skip those)
                        if "System Context Update" not in msg['content']:
                            self.add_chat_message(msg['content'], is_user=(msg['role'] == 'user'))
                self.status_lbl.setText("History loaded from IDB.")
            else:
                # Show welcome message for new chain
                welcome = "I'm ready to analyze this function chain. Please build the graph, select the functions you're interested in, and ask your first question!"
                self.add_chat_message(welcome, is_user=False)
                # We don't save history yet, wait for first real message
        except Exception as e:
            print(f"[PseudoNote] Error loading history: {e}")

    def scroll_to_bottom(self):
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())

    def closeEvent(self, event):
        self.save_history() # Ensure state is saved on close
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        super().closeEvent(event)

class ChatChainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None
        
    def activate(self, ctx):
        ea = ctx.cur_ea if ctx.cur_ea != idaapi.BADADDR else idaapi.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if not f:
            print("No function selected.")
            return 1
            
        self.dlg = ChatChainDialog(f.start_ea)
        self.dlg.show()
        return 1
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
