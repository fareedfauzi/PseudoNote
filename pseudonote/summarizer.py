import idaapi
import ida_funcs
import idautils
import idc
import html
import time
from pseudonote.qt_compat import (
    QtWidgets, QtCore, QtGui, QThread, Signal, Slot, QDialog,
    QVBoxLayout, QHBoxLayout, QSplitter, QTextBrowser, QPushButton,
    QLabel, QProgressBar, QSpinBox, QGroupBox, QLineEdit, QTabWidget
)
import threading
import pseudonote.ai_client as _ai_mod
from pseudonote.config import CONFIG
from pseudonote.deep_analyzer import build_call_graph, FuncNode, STYLES_ANALYZER
from pseudonote.renamer import get_code_fast
from pseudonote.idb_storage import save_to_idb, load_from_idb

class SummarizerWorker(QThread):
    log_signal = Signal(str, str)
    char_count_signal = Signal(int, int)
    finished_signal = Signal(str)
    
    def __init__(self, entry_ea, max_depth, max_funcs):
        super().__init__()
        self.entry_ea = entry_ea
        self.max_depth = max_depth
        self.max_funcs = max_funcs
        self._stop = False
        
    def stop(self):
        self._stop = True
        _ai_mod.AI_CANCEL_REQUESTED = True
        
    def run(self):
        AI_CLIENT = _ai_mod.SimpleAI(CONFIG)
        if not AI_CLIENT.client:
            self.log_signal.emit("AI Client not configured.", "err")
            return
            
        self.log_signal.emit(f"Building function graph from 0x{self.entry_ea:X}...", "info")
        
        # Temporarily restrict graph builder
        old_max_depth = getattr(CONFIG, 'max_graph_depth', 15)
        old_max_nodes = getattr(CONFIG, 'max_graph_nodes', 500)
        
        # Give 3x leeway because library functions count against max_graph_nodes in build_call_graph
        CONFIG.max_graph_depth = self.max_depth
        CONFIG.max_graph_nodes = max(500, self.max_funcs * 3) 

        try:
            graph = build_call_graph(self.entry_ea, stop_checker=lambda: self._stop, log_fn=lambda m, l: self.log_signal.emit(m, l))
        finally:
            # Restore config
            CONFIG.max_graph_depth = old_max_depth
            CONFIG.max_graph_nodes = old_max_nodes
            
        if self._stop: return
        
        if not graph:
            self.log_signal.emit("No function graph could be built.", "err")
            return
            
        nodes = [n for n in graph.values() if not getattr(n, 'is_library', False)]
        nodes.sort(key=lambda n: n.depth)
        
        # Step 2: Gather decompiled code, filtering trivial functions
        filtered_nodes = []
        code_blocks = []
        
        def _sync_gather():
            for n in nodes:
                if self._stop: break
                
                # Filter out pure thunks/nullsubs by name heuristic quickly
                if n.name.startswith("nullsub_") or "thunk" in n.name.lower():
                    continue

                if getattr(n, 'depth', 0) > self.max_depth:
                    continue

                c = get_code_fast(n.ea)
                if not c:
                    continue
                    
                lines = c.splitlines()
                # Skip trivially small functions (usually just padding/returns) unless it's the target entry point
                if len(lines) < 4 and getattr(n, 'depth', 0) > 0:
                    continue

                filtered_nodes.append(n)
                code_blocks.append(f"### Function: {n.name} (0x{n.ea:X}), Depth: {n.depth}\n```c\n{c}\n```\n")

                if len(filtered_nodes) >= self.max_funcs:
                    break
        
        self.log_signal.emit(f"Filtering and gathering decompiled code...", "info")
        idaapi.execute_sync(_sync_gather, idaapi.MFF_READ)
        if self._stop: return
        
        if not code_blocks:
            self.log_signal.emit("No decompiled code could be extracted after filtering.", "err")
            return
            
        total_funcs = len(code_blocks)
        self.log_signal.emit(f"Final Selection: {total_funcs} functions to summarize.", "ok")
        
        # Step 3: Chunking (Max 30 functions per prompt to avoid token overflow)
        CHUNK_SIZE = 30
        chunks = [code_blocks[i:i + CHUNK_SIZE] for i in range(0, len(code_blocks), CHUNK_SIZE)]
        
        raw_chunk_reports = []
        self.full_response = ""
        
        for i, chunk in enumerate(chunks):
            if self._stop: break
            
            chunk_context = "\n".join(chunk)
            chunk_label = f" (Part {i+1} of {len(chunks)})" if len(chunks) > 1 else ""
            
            prompt = (
                "You are an expert reverse engineer.\n"
                f"I will provide you with the decompiled C code of a function chain{chunk_label}.\n"
                "Purely read the codes of the functions using bottom-up context to understand dependencies and top-down logic for execution flow.\n"
                "Do NOT provide function renames, variable renames, or indicators/tagging.\n"
                "Return a comprehensive Markdown report summarizing exactly what the functions in this chunk do.\n\n"
                "## Output Format Requirements:\n"
                "Use the following structure:\n"
                f"## Overview{chunk_label}\n[High-level summary of these functions]\n\n"
                "## Key Operations\n- [Bullet points of major behaviors/actions taken]\n\n"
                "## Execution Flow (Top-Down)\n[Step-by-step logical explanation of the execution flow]\n\n"
                "Do NOT output anything other than the markdown report.\n\n"
                "## Code Context\n"
                f"{chunk_context}"
            )
            
            self.log_signal.emit(f"Querying AI for summary{chunk_label}...", "info")
            
            chunk_res = []
            query_done = threading.Event()
            
            def chunk_cb(t):
                chunk_res.append(t)
                # Only stream live to the UI if there is exactly 1 chunk (no synthesis needed)
                if len(chunks) == 1:
                    self.full_response += t
                    self.char_count_signal.emit(len(self.full_response), 0)
                
            def fin_cb(response, finish_reason="stop", **kwargs):
                if not response and not chunk_res:
                    self.log_signal.emit(f"AI returned empty for{chunk_label}.", "err")
                query_done.set()

            AI_CLIENT.query_model_async(prompt, fin_cb, on_chunk=chunk_cb, on_status=lambda t, m="": None)
            
            while not query_done.wait(0.5):
                if self._stop: break
                
            raw_chunk_reports.append("".join(chunk_res))
        
        if self._stop: return
        
        # Step 4: Map-Reduce Synthesis (only if multiple chunks)
        if len(chunks) > 1:
            self.log_signal.emit("Synthesizing final overview from all chunks...", "info")
            
            synthesis_prompt = (
                "You are an expert reverse engineer.\n"
                "I provided an AI with multiple chunks of a massive function chain, and it generated the following partial summaries.\n"
                "Your task is to merge all of these partial summaries into ONE SINGLE, cohesive, and comprehensive final markdown report representing the entire component's capabilities.\n\n"
                "## Output Format Requirements:\n"
                "Use the following structure:\n"
                "## Overview\n[Unified high-level summary of the entire chain]\n\n"
                "## Key Operations\n- [Merged bullet points covering all major actions identified across all chunks, removing redundancies]\n\n"
                "## Execution Flow (Top-Down)\n[Logical end-to-end explanation combining the flow from all chunks smoothly]\n\n"
                "Do NOT output anything other than the markdown report.\n\n"
                "## Partial Summaries to Merge:\n\n"
            )
            for i, r in enumerate(raw_chunk_reports):
                synthesis_prompt += f"--- PART {i+1} ---\n{r}\n\n"
                
            self.full_response = "" # Reset for synthesis stream
            query_done = threading.Event()
            
            def synthesis_chunk_cb(t):
                self.full_response += t
                self.char_count_signal.emit(len(self.full_response), 0)
                
            def synthesis_fin_cb(response, finish_reason="stop", **kwargs):
                if not response and not self.full_response.strip():
                    self.log_signal.emit("AI failed to synthesize final report.", "err")
                query_done.set()
                
            AI_CLIENT.query_model_async(synthesis_prompt, synthesis_fin_cb, on_chunk=synthesis_chunk_cb, on_status=lambda t, m="": None)
            
            while not query_done.wait(0.5):
                if self._stop: break

        if self._stop: return
        self.log_signal.emit("Analysis complete.", "ok")
        self.finished_signal.emit(self.full_response)

class SummarizerDialog(QtWidgets.QDialog):
    def __init__(self, entry_ea):
        super().__init__(None) # No parent so it acts as top-level
        self.entry_ea = entry_ea
        self.setWindowTitle("Function Chain Summarizer")
        self.resize(1100, 750)
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowMaximizeButtonHint | QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        self.setStyleSheet(STYLES_ANALYZER)
        
        self.worker = None
        self._stop_requested = False
        self.setup_ui()
        self.on_use_current_function()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QHBoxLayout()
        title = QLabel("Function Chain Summarizer")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        subtitle = QLabel("Lightweight execution flow parsing and AI summarization.")
        subtitle.setStyleSheet("color: #636366; font-size: 11px; margin-left:8px;")
        header.addWidget(subtitle)
        header.addStretch()
        layout.addLayout(header)

        # Target Section
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout(target_group)
        target_layout.setContentsMargins(14, 12, 14, 14)
        target_layout.setSpacing(12)

        entry_lbl = QLabel("Entry")
        entry_lbl.setFixedWidth(50)

        self.entry_edit = QLineEdit()
        self.entry_edit.setReadOnly(True)
        self.entry_edit.setFont(QtGui.QFont("Consolas", 10))
        
        self.entry_change_btn = QPushButton("Load Current Function")
        self.entry_change_btn.setObjectName("primary")
        self.entry_change_btn.clicked.connect(self.on_use_current_function)

        target_layout.addWidget(entry_lbl)
        target_layout.addWidget(self.entry_edit, 1)
        target_layout.addWidget(self.entry_change_btn)

        # Configs inside Target
        opt_layout = QHBoxLayout()
        opt_layout.addWidget(QLabel("Max Depth:"))
        self.depth_sp = QSpinBox()
        self.depth_sp.setRange(1, 20)
        self.depth_sp.setValue(5)
        opt_layout.addWidget(self.depth_sp)
        
        opt_layout.addWidget(QLabel("Max Functions:"))
        self.func_sp = QSpinBox()
        self.func_sp.setRange(1, 1000)
        self.func_sp.setValue(500)
        opt_layout.addWidget(self.func_sp)
        target_layout.addLayout(opt_layout)
        
        layout.addWidget(target_group)

        # Action Bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        self.start_btn = QPushButton("Start Summarizer")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.start_analysis)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_analysis)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("status_msg")

        action_bar.addWidget(self.start_btn)
        action_bar.addWidget(self.stop_btn)
        action_bar.addStretch()
        action_bar.addWidget(self.status_label)
        layout.addLayout(action_bar)

        # Activity Section
        self.activity_group = QGroupBox("Activity")
        self.activity_group.setVisible(False)
        progress_area = QVBoxLayout(self.activity_group)
        progress_area.setContentsMargins(14, 18, 14, 14)
        progress_area.setSpacing(10)

        stage_row = QHBoxLayout()
        stage_row.setSpacing(10)
        self.cur_stage_lbl = QLabel("Progress:")
        self.cur_stage_lbl.setStyleSheet("color: #636366; font-size: 9pt; font-weight: bold; min-width: 100px;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(22)
        self.progress_bar.setFormat("Initializing...")
        
        stage_row.addWidget(self.cur_stage_lbl)
        stage_row.addWidget(self.progress_bar, 1)
        progress_area.addLayout(stage_row)
        layout.addWidget(self.activity_group)

        # Results area (Tabs)
        self.tabs = QTabWidget()
        
        self.result_viewer = QTextBrowser()
        self.result_viewer.setOpenExternalLinks(True)
        self.result_viewer.setStyleSheet("border: none; font-size: 11pt;")
        self.tabs.addTab(self.result_viewer, "Summarizer Report")

        self.log_viewer = QTextBrowser()
        self.log_viewer.setStyleSheet("font-size: 10pt; border: none;")
        self.tabs.addTab(self.log_viewer, "Execution Log")

        layout.addWidget(self.tabs, 1)

    def on_use_current_function(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            self.entry_ea = f.start_ea
            name = idc.get_func_name(self.entry_ea)
            self.entry_edit.setText(f"0x{self.entry_ea:X} - {name}")
            self.append_log(f"Target locked onto {name}", "ok")
            
            existing_summary = load_from_idb(self.entry_ea, tag=91)
            if existing_summary:
                self.result_viewer.setMarkdown(existing_summary)
                self.append_log("Loaded previously saved summary from IDB.", "ok")
                self.tabs.setCurrentIndex(0)
            else:
                self.result_viewer.clear()
        else:
            self.append_log("No function found at cursor.", "warn")

    def append_log(self, message, level="info"):
        colors = {'info': '#636366', 'ok': '#248A3D', 'warn': '#C67E00', 'err': '#CC3333'}
        prefixes = {'info': '[INFO]', 'ok': '[OK]  ', 'warn': '[WARN]', 'err': '[ERR] '}
        
        color = colors.get(level, '#d4d4d4')
        prefix = prefixes.get(level, '[INFO]')
        ts = time.strftime("%H:%M:%S")
        full_message = f"{prefix} {message}"
        
        self.log_viewer.append(f'<span style="color:{color};">[{ts}] {html.escape(str(full_message))}</span>')
        self.log_viewer.verticalScrollBar().setValue(self.log_viewer.verticalScrollBar().maximum())

        if level == "info" or level == "ok":
            self.progress_bar.setFormat(message)
            self.status_label.setText(message)

    def stop_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.activity_group.setVisible(False)
        self.status_label.setText("Stopped by user.")
        self.append_log("Cancelled by user.", "warn")

    def start_analysis(self):
        if self.entry_ea is None or self.entry_ea == idaapi.BADADDR:
            self.append_log("Invalid entry point. Please load a valid function.", "err")
            return
            
        self.log_viewer.clear()
        self.result_viewer.clear()
        self.tabs.setCurrentIndex(0) # Focus report tab
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.activity_group.setVisible(True)
        self.progress_bar.setRange(0, 0) # Indeterminate
        
        self.worker = SummarizerWorker(self.entry_ea, self.depth_sp.value(), self.func_sp.value())
        self.worker.log_signal.connect(self.append_log)
        self.worker.char_count_signal.connect(lambda c, m: self.update_result())
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def update_result(self):
        if self.worker:
            self.result_viewer.setMarkdown(self.worker.full_response)
            vbar = self.result_viewer.verticalScrollBar()
            vbar.setValue(vbar.maximum())

    def on_finished(self, response):
        self.activity_group.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if response:
            self.result_viewer.setMarkdown(response)
            save_to_idb(self.entry_ea, response, tag=91)
            self.append_log("Summary saved to IDB permanently.", "ok")
        self.status_label.setText("Analysis Complete.")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        super().closeEvent(event)

class SummarizerHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None
        
    def activate(self, ctx):
        ea = ctx.cur_ea if ctx.cur_ea != idaapi.BADADDR else idaapi.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if not f:
            print("No function selected.")
            return 1
            
        self.dlg = SummarizerDialog(f.start_ea)
        self.dlg.show()
        return 1
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
