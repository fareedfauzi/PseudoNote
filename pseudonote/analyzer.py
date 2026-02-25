# -*- coding: utf-8 -*-
import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment
import json, os, re, time, threading, csv
from pseudonote.qt_compat import QtWidgets, QtGui, QtCore, Signal
from pseudonote.config import CONFIG, LOGGER
from pseudonote.qt_compat import (
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, 
    QSpinBox, QProgressBar, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QHeaderView, QAbstractItemView, QMenu, QAction, QMessageBox, QInputDialog,
    QDialog, QDialogButtonBox, QGroupBox, QFileDialog,
    QApplication, QThread, QTimer, QAbstractTableModel,
    QModelIndex, QTableView, QColor, QFont, QIcon, QSize,
    QBrush, QPainter, QPalette, QKeySequence, QTextEdit,
    QWidget, QSplitter, QSpacerItem
)
import ida_kernwin
import pseudonote.view as _view

from pseudonote.renamer import (
    STYLES, is_valid_seg, is_sys_func, get_code_fast, 
    get_strings_fast, get_calls_fast, ai_request
)
from pseudonote.ai_client import SimpleAI
import pseudonote.ai_client as _ai_mod
from pseudonote.idb_storage import save_to_idb, load_from_idb

Qt = QtCore.Qt

class FuncData:
    __slots__ = ['ea', 'name', 'demangled', 'tag', 'confidence', 'indicators', 'tag_reason', 'status', 'checked', 'code', 'strings', 'calls', 'callers', 'callees']
    def __init__(self, ea, name):
        self.ea, self.name, self.tag, self.tag_reason, self.status, self.checked = ea, name, '', '', 'Pending', True
        self.confidence = 0
        self.indicators = ''
        self.demangled = None
        if name.startswith('??') or name.startswith('_Z'):
            self.demangled = ida_name.demangle_name(name, 0)
        self.code = self.strings = self.calls = self.callers = self.callees = None

class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['', 'Address', 'Function Name', 'Tag', 'Confidence', 'Indicators', 'Reason', 'Status']
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.funcs, self.filtered, self.filter_text = [], [], ''
        self.sort_col = 3 # Default to Tag
        self.sort_ord = Qt.AscendingOrder

    def set_data(self, funcs):
        self.beginResetModel()
        self.funcs = funcs
        self._apply_filter()
        self.endResetModel()

    def append_data(self, funcs):
        # Filter out duplicates if already in self.funcs
        existing_eas = {f.ea for f in self.funcs}
        new_funcs = [f for f in funcs if f.ea not in existing_eas]
        if not new_funcs: return
        
        self.beginResetModel()
        self.funcs.extend(new_funcs)
        self._apply_filter()
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.funcs, self.filtered = [], []
        self.endResetModel()

    def _apply_filter(self):
        if not self.filter_text:
            self.filtered = list(range(len(self.funcs)))
        else:
            ft = self.filter_text.lower()
            res = []
            for i, f in enumerate(self.funcs):
                if ft in f.name.lower() or ft in f'{f.ea:x}':
                    res.append(i)
                elif f.demangled and ft in f.demangled.lower():
                    res.append(i)
                elif f.tag and ft in f.tag.lower():
                    res.append(i)
                elif f.indicators and ft in f.indicators.lower():
                    res.append(i)
                elif f.tag_reason and ft in f.tag_reason.lower():
                    res.append(i)
            self.filtered = res
        
        # Maintain active sorting
        self.sort(self.sort_col, self.sort_ord)

    def set_filter(self, t):
        self.beginResetModel()
        self.filter_text = t
        self._apply_filter()
        self.endResetModel()

    def rowCount(self, p=QModelIndex()): return len(self.filtered)
    def columnCount(self, p=QModelIndex()): return 8
    def headerData(self, s, o, r=Qt.DisplayRole): return self.HEADERS[s] if r==Qt.DisplayRole and o==Qt.Horizontal else None

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self.filtered): return None
        f = self.funcs[self.filtered[idx.row()]]
        c = idx.column()
        
        if role == Qt.DisplayRole:
            if c==1: return f'{f.ea:X}'
            elif c==2: return f.demangled or f.name
            elif c==3: return f.tag.upper() if f.tag else ''
            elif c==4: return f"{f.confidence}%" if f.confidence else ''
            elif c==5: return f.indicators
            elif c==6: return f.tag_reason
            elif c==7: return f.status
            
        elif role == Qt.CheckStateRole and c==0:
            return Qt.Checked if f.checked else Qt.Unchecked
            
        elif role == Qt.TextAlignmentRole:
            if c==0: return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ForegroundRole:
            if c == 3: # Tag colors
                t = f.tag.lower()
                if t == 'malicious': return QColor('#FF3B30')
                if t == 'suspicious': return QColor('#FF9500')
                if t == 'benign': return QColor('#8E8E93')
            
            if c == 4: # Confidence colors
                if f.confidence >= 80: return QColor('#34C759')
                if f.confidence >= 50: return QColor('#FF9500')
                if f.confidence > 0: return QColor('#FF3B30')

            if c == 7: # Status colors
                if f.status == 'OK': return QColor('#34C759')
                if f.status == 'Cached': return QColor('#34C759')
                if f.status == 'Skip': return QColor('#8E8E93')
                if f.status == 'Pending': return QColor('#FF9500')
            
        return None

    def setData(self, idx, value, role=Qt.EditRole):
        if idx.isValid() and role == Qt.CheckStateRole and idx.column() == 0:
            val = value.value if hasattr(value, 'value') else value
            chk = Qt.Checked.value if hasattr(Qt.Checked, 'value') else Qt.Checked
            f = self.funcs[self.filtered[idx.row()]]
            f.checked = (val == chk)
            self.dataChanged.emit(idx, idx, [Qt.CheckStateRole])
            return True
        return False

    def flags(self, idx):
        f_enabled = Qt.ItemIsEnabled
        f_selectable = Qt.ItemIsSelectable
        f_check = Qt.ItemIsUserCheckable
        
        if hasattr(f_enabled, 'value'):
            val = f_enabled.value | f_selectable.value
            if idx.column() == 0: val |= f_check.value
            try: return Qt.ItemFlag(val)
            except: return val
        else:
            base = f_enabled | f_selectable
            if idx.column() == 0: base |= f_check
            return base

    def get_func(self, row): return self.funcs[self.filtered[row]] if 0<=row<len(self.filtered) else None
    
    def refresh_rows(self, indices):
        if not indices: return
        rows = [self.filtered.index(i) for i in indices if i in self.filtered]
        if rows:
            self.dataChanged.emit(self.index(min(rows), 0), self.index(max(rows), 7))

    def sort(self, col, ord=Qt.AscendingOrder):
        self.beginResetModel()
        self.sort_col = col
        self.sort_ord = ord
        
        reverse = (ord == Qt.DescendingOrder)
        
        if col == 1: # Address
            self.filtered.sort(key=lambda i: self.funcs[i].ea, reverse=reverse)
        elif col == 2: # Name
            self.filtered.sort(key=lambda i: (self.funcs[i].demangled or self.funcs[i].name).lower(), reverse=reverse)
        elif col == 3: # Tag
            self.filtered.sort(key=self._tag_sort_key, reverse=reverse)
        elif col == 4: # Confidence
            self.filtered.sort(key=lambda i: self.funcs[i].confidence, reverse=reverse)
        elif col == 7: # Status
            self.filtered.sort(key=lambda i: self.funcs[i].status.lower(), reverse=reverse)
            
        self.endResetModel()

    def _tag_sort_key(self, idx_val):
        f = self.funcs[idx_val]
        t = f.tag.lower() if f.tag else ''
        if t == 'malicious': return 0
        if t == 'suspicious': return 1
        if t == 'benign': return 2
        return 3

    def toggle_all(self, chk):
        for i in self.filtered:
            self.funcs[i].checked = chk
        if self.filtered:
            self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))

    def select_by_tag(self, tag):
        tag = tag.lower()
        for i in self.filtered:
            f = self.funcs[i]
            if f.tag and f.tag.lower() == tag:
                f.checked = True
            else:
                f.checked = False
        if self.filtered:
            self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))

    def get_checked(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked]
    def total(self): return len(self.funcs)

class AnalyzeWorker(QThread):
    batch_done = Signal(list)
    progress = Signal(int, int)
    finished = Signal(int)
    log = Signal(str, str)
    update_status = Signal(str)

    def __init__(self, cfg, items, include_context):
        super().__init__()
        self.cfg = cfg
        self.items = items
        self.include_context = include_context
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        done = 0
        total = len(self.items)
        
        # Use batch_size from config, default to 1 for high accuracy tagging
        batch_size = self.cfg.get('batch_size', 1)
        
        batches = [self.items[i:i+batch_size] for i in range(0, total, batch_size)]

        for i, batch in enumerate(batches):
            if not self.running: break

            # Cooldown logic to avoid rate limits
            if i > 0:
                cd = self.cfg.get('cooldown_seconds', 0)
                if cd > 0:
                    # Animated count decrease: update every 0.2s for smoothness
                    for s in range(cd * 10, 0, -2):
                        if not self.running: break
                        self.update_status.emit(f"Cooling down ({s/10.0:.1f}s)")
                        time.sleep(0.2)
                    if not self.running: break
                self.update_status.emit("Analyzing")

            results = self.process_batch(batch)
            self.batch_done.emit(results)
            done += len(batch)
            self.progress.emit(done, total)

        self.finished.emit(done)

    def process_batch(self, batch):
        results = []
        for idx, func in batch:
            if not self.running or _ai_mod.AI_CANCEL_REQUESTED: break
            
            # Fetch Context if enabled
            caller_ctx = ""
            callee_ctx = ""
            if self.include_context:
                callers, callees = self.get_context(func.ea)
                if callers:
                    caller_ctx = "\nCALLERS CONTEXT:\n" + "\n".join(callers)
                if callees:
                    callee_ctx = "\nCALLEES CONTEXT:\n" + "\n".join(callees)

            # Fetch existing code if not already present
            if not func.code:
                # Increased to 50k to handle 1000+ lines (avg 40-50 chars/line)
                func.code = get_code_fast(func.ea, 50000, asm_max=1000)
                func.strings = get_strings_fast(func.ea)
                func.calls = get_calls_fast(func.ea)

            if not func.code:
                results.append((idx, func, 'benign', 0, '', 'No code found'))
                continue

            sys_prompt = """You are an expert malware analyst performing static analysis of decompiled functions.

Classify the function using EXACTLY one of these tags:
- malicious: Clear evidence of harmful intent (shellcode, process injection, registry persistence,
  credential harvesting, C2 communication, encryption of user data, privilege escalation,
  anti-analysis/anti-debug, file destruction)
- suspicious: Ambiguous behavior that warrants investigation (unusual API combinations,
  obfuscated logic, dynamic code loading, network + file I/O together, excessive unnamed
  sub_* calls that obscure intent, uncommon system calls)
- benign: Standard utility behavior with no indicators of malicious intent (math, string
  manipulation, UI rendering, logging, configuration parsing, known library patterns)

CONFIDENCE RULES:
- 80-100: Strong evidence, multiple corroborating indicators
- 50-79: Some evidence but ambiguous or incomplete context
- 0-49: Very little context, mostly unnamed sub_* calls, low certainty

            INDICATOR RULES:
            - List only concrete observed artifacts, not assumptions
            - Each item must be 2-4 words maximum
            - Maximum 5 items
            - Each item must start with a Capital letter (Title Case)
            - Do NOT wrap items in quotes of any kind
            - Separate items with commas only
            - Examples: AES S-box, VirtualAllocEx Call, RDTSC Timing Check,
              Base64 Decode Loop, HTTP User-Agent String, Registry Persistence,
              XOR Decryption Loop, CreateRemoteThread Call, Anti-Debug Check
            - If no clear indicators found, write: No Clear Indicators

IMPORTANT RULES:
- If function body consists mostly of unnamed sub_XXXXX calls with no strings or known APIs,
  tag as suspicious, confidence <= 40, and note lack of context in REASON.
- Base classification ONLY on observable evidence in code, strings, and calls provided.
- Do NOT assume malicious intent from complexity alone.
- Do NOT assume benign intent from simplicity alone.

OUTPUT FORMAT (strictly follow, no extra text before or after):
TAG: malicious|suspicious|benign
CONFIDENCE: 0-100
INDICATORS: item1, item2, item3
REASON: 2-3 sentences citing specific evidence including API names, strings, and behaviors observed."""
            prompt = f"Function Name: {func.name}\nAddress: {hex(func.ea)}\n"
            prompt += f"Code:\n```\n{func.code}\n```\n"
            if func.strings: prompt += f"Strings: {func.strings}\n"
            if func.calls:
                named = [c for c in func.calls if not c.startswith('sub_')]
                unnamed_count = len([c for c in func.calls if c.startswith('sub_')])
                if named:
                    prompt += f"Named API/function calls: {named}\n"
                if unnamed_count:
                    prompt += f"Unnamed sub_* calls: {unnamed_count} (context unavailable)\n"
            prompt += caller_ctx + callee_ctx

            try:
                self._resp_len = 0
                def _chunk(t):
                    self._resp_len += len(t)
                    ida_kernwin.execute_sync(lambda: _view.update_ai_progress_details(self._resp_len), ida_kernwin.MFF_WRITE)
                
                ida_kernwin.execute_sync(lambda: _view.show_ai_progress(f"Analyzing {func.name}"), ida_kernwin.MFF_WRITE)
                try:
                    resp = ai_request(self.cfg, prompt, sys_prompt, logger=lambda m: self.log.emit(m, 'info'), on_chunk=_chunk)
                finally:
                    ida_kernwin.execute_sync(_view.hide_ai_progress, ida_kernwin.MFF_WRITE)
                
                tag, confidence, indicators, reason = self.parse_tag_response(resp)
                results.append((idx, func, tag, confidence, indicators, reason))
            except Exception as e:
                self.log.emit(f"Error analyzing {hex(func.ea)}: {str(e)}", 'err')
                results.append((idx, func, 'benign', 0, '', 'Error during analysis'))
        
        return results

    def parse_tag_response(self, resp):
        if not resp: return 'benign', 0, '', 'Empty response from AI'
        
        tag = 'benign'
        confidence = 0
        indicators = ''
        reason = 'Failed to parse reason'
        
        tag_match = re.search(r'TAG:\s*(malicious|suspicious|benign)', resp, re.IGNORECASE)
        conf_match = re.search(r'CONFIDENCE:\s*\D*(\d+)', resp, re.IGNORECASE)
        ind_match = re.search(r'INDICATORS:\s*(.*)', resp, re.IGNORECASE)
        reason_match = re.search(
            r'REASON:\s*(.*?)(?=\n(?:TAG|CONFIDENCE|INDICATORS):|$)',
            resp,
            re.IGNORECASE | re.DOTALL
        )
        
        if tag_match:
            tag = tag_match.group(1).lower()
        else:
            self.log.emit(f"Warning: Failed to parse tag. Raw: {resp[:80]}", 'warn')
        
        if conf_match:
            confidence = max(0, min(100, int(conf_match.group(1))))
        else:
            self.log.emit("Warning: Failed to parse confidence. Defaulting to 0.", 'warn')
        
        # Robust indicator parsing
        ind_match = re.search(r'INDICATORS?:\s*(.*)', resp, re.IGNORECASE)
        if ind_match:
            raw = ind_match.group(1).strip().strip('*').strip()
            # Strip any surrounding or inline quotes the AI may add
            raw = raw.replace('"', '').replace("'", '').replace('`', '')
            # Split by comma, Title Case each item, rejoin
            items = [item.strip().title() for item in raw.split(',') if item.strip()]
            indicators = ', '.join(items)
        
        if reason_match:
            reason = reason_match.group(1).strip()
        
        return tag, confidence, indicators, reason

    def get_context(self, ea):
        callers = []
        callees = []
        
        def _fetch():
            # Callers
            c_count = 0
            for xref in idautils.CodeRefsTo(ea, True):
                if c_count >= 3: break
                caller_ea = xref
                name = idc.get_func_name(caller_ea)
                if not name or is_sys_func(name): continue
                code = get_code_fast(caller_ea, 300)
                if code:
                    callers.append(f"// Caller: {name}\n{code}")
                    c_count += 1
            
            # Callees
            e_count = 0
            f = ida_funcs.get_func(ea)
            if f:
                for item in idautils.FuncItems(ea):
                    if e_count >= 3: break
                    for xref in idautils.CodeRefsFrom(item, False):
                        if e_count >= 3: break
                        callee_ea = xref
                        name = idc.get_func_name(callee_ea)
                        if not name or is_sys_func(name) or name.startswith('sub_'): continue
                        code = get_code_fast(callee_ea, 400)
                        if code:
                            if len(code) > 300:
                                code = code[:300] + "..."
                            callees.append(f"// Callee: {name}\n{code}")
                            e_count += 1
                            
        idaapi.execute_sync(_fetch, idaapi.MFF_READ)
        return callers, callees

class StreamingSummaryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Holistic Behavioral Summary")
        self.resize(900, 700)
        self.setStyleSheet(STYLES)
        
        layout = QVBoxLayout(self)
        self.viewer = QTextEdit()
        self.viewer.setReadOnly(True)
        # Use a nice mono font
        f = QFont("Consolas", 11) if os.name == 'nt' else QFont("Monospace", 11)
        self.viewer.setFont(f)
        layout.addWidget(self.viewer)
        
        self.raw_text = ""
        
        btns = QHBoxLayout()
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.raw_text))
        btns.addWidget(self.copy_btn)
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        btns.addWidget(self.close_btn)
        layout.addLayout(btns)

    def append_chunk(self, partial):
        self.raw_text += partial
        # Streaming as plain text for responsiveness
        self.viewer.setPlainText(self.raw_text)
        self.viewer.moveCursor(QtGui.QTextCursor.End)

    def finalize(self, full_text):
        self.raw_text = full_text
        # Final render as Markdown
        if hasattr(self.viewer, 'setMarkdown'):
            self.viewer.setMarkdown(full_text)
        else:
            self.viewer.setHtml(full_text) # Fallback
        self.copy_btn.setEnabled(True)
        self.close_btn.setText("Done")

class BulkAnalyzer(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pn_config = CONFIG
        self.workers = []
        self.is_loading = False
        self.setup_ui()
        self.worker = None

    def setup_ui(self):
        self.setWindowTitle('PseudoNote: Bulk Function Analyzer')
        self.resize(1400, 950)
        self.setStyleSheet(STYLES)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # Toolbar
        tb = QHBoxLayout()
        self.load_btn = QPushButton('Load sub_*')
        self.load_btn.setObjectName("primary")
        self.load_btn.clicked.connect(lambda: self.load_funcs(prefix='sub_'))
        tb.addWidget(self.load_btn)
        
        load_custom_btn = QPushButton("Load")
        load_custom_btn.setObjectName("primary")
        load_custom_btn.clicked.connect(self.load_pattern)
        tb.addWidget(load_custom_btn)

        self.load_input = QLineEdit()
        self.load_input.setPlaceholderText("Search substring...")
        self.load_input.setFixedWidth(300)
        self.load_input.returnPressed.connect(self.load_pattern)
        tb.addWidget(self.load_input)

        tb.addStretch()
        
        settings_btn = QPushButton("Settings")
        settings_btn.setObjectName("secondary")
        settings_btn.clicked.connect(self.open_settings)
        tb.addWidget(settings_btn)
        
        layout.addLayout(tb)

        # Row 2: Context Selection
        ctx_layout = QHBoxLayout()
        self.include_ctx_cb = QCheckBox("Include callers/callees context (slower)")
        self.include_ctx_cb.setChecked(False)
        ctx_layout.addWidget(self.include_ctx_cb)
        ctx_layout.addStretch()
        layout.addLayout(ctx_layout)

        # Filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter Table:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Search in current list...')
        self.filter_edit.textChanged.connect(lambda t: self.model.set_filter(t))
        filter_layout.addWidget(self.filter_edit)
        layout.addLayout(filter_layout)

        # Table
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True) # Enable sorting by header click
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        
        h = self.table.horizontalHeader()
        self.table.setColumnWidth(0, 30)   # checkbox
        self.table.setColumnWidth(1, 100)  # address
        self.table.setColumnWidth(2, 200)  # function name
        self.table.setColumnWidth(3, 90)   # tag
        self.table.setColumnWidth(4, 100)  # confidence
        self.table.setColumnWidth(5, 220)  # indicators
        self.table.setColumnWidth(7, 70)   # status
        
        # Allow interactive resizing but stretch Reason
        h.setSectionResizeMode(QHeaderView.Interactive)
        h.setSectionResizeMode(6, QHeaderView.Stretch) # Maximize Reason
        h.setStretchLastSection(False)
        
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(self.on_table_double_click)
        layout.addWidget(self.table)

        self.model.dataChanged.connect(self.update_button_states)
        self.model.modelReset.connect(self.update_button_states)

        # Selection Toolbar (Between table and log)
        sel_row = QHBoxLayout()
        self.sel_all_btn = QPushButton('Select All')
        self.sel_all_btn.clicked.connect(lambda: self.model.toggle_all(True))
        sel_row.addWidget(self.sel_all_btn)
        
        self.sel_none_btn = QPushButton('Select None')
        self.sel_none_btn.clicked.connect(lambda: self.model.toggle_all(False))
        sel_row.addWidget(self.sel_none_btn)

        # Separator
        sep = QLabel("|")
        sep.setStyleSheet("color: gray; margin: 0 5px;")
        sel_row.addWidget(sep)
        
        self.sel_mal_btn = QPushButton('Select Malicious')
        self.sel_mal_btn.clicked.connect(lambda: self.model.select_by_tag('malicious'))
        sel_row.addWidget(self.sel_mal_btn)

        self.sel_susp_btn = QPushButton('Select Suspicious')
        self.sel_susp_btn.clicked.connect(lambda: self.model.select_by_tag('suspicious'))
        sel_row.addWidget(self.sel_susp_btn)

        self.sel_ben_btn = QPushButton('Select Benign')
        self.sel_ben_btn.clicked.connect(lambda: self.model.select_by_tag('benign'))
        sel_row.addWidget(self.sel_ben_btn)
        
        sel_row.addStretch()
        layout.addLayout(sel_row)

        # Logs & Progress
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(130)
        layout.addWidget(self.log)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(True)
        self.progress.setFormat("%p% (%v/%m)")
        layout.addWidget(self.progress)

        # Actions
        actions = QHBoxLayout()
        self.analyze_btn = QPushButton('Analyze + Tag')
        self.analyze_btn.setObjectName("primary")
        self.analyze_btn.clicked.connect(self.start_analyze)
        actions.addWidget(self.analyze_btn)

        self.summarize_btn = QPushButton('Summarize Selected')
        self.summarize_btn.setObjectName("primary")
        self.summarize_btn.clicked.connect(self.summarize_selected)
        actions.addWidget(self.summarize_btn)

        self.forward_btn = QPushButton('Forward to Renamer')
        self.forward_btn.setObjectName("secondary")
        self.forward_btn.setToolTip("Forward ticked functions to the Bulk Renamer tool")
        self.forward_btn.clicked.connect(self.forward_to_renamer)
        actions.addWidget(self.forward_btn)

        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self.stop_all)
        self.stop_btn.setEnabled(False)
        actions.addWidget(self.stop_btn)

        actions.addStretch()
        
        self.unload_btn = QPushButton('Unload Table')
        self.unload_btn.setObjectName("danger")
        self.unload_btn.clicked.connect(self.unload_table)
        actions.addWidget(self.unload_btn)

        self.export_btn = QPushButton('Export CSV')
        self.export_btn.setObjectName("secondary")
        self.export_btn.setToolTip("Export the current table data to a CSV file")
        self.export_btn.clicked.connect(self.export_csv)
        actions.addWidget(self.export_btn)

        layout.addLayout(actions)
        self.update_button_states()

    def check_sub_ratio(self, items):
        # Only scan functions where code is already cached
        # If fewer than 10 have cached code, skip the check entirely
        cached = [(idx, f) for idx, f in items if f.code]
        if len(cached) < 10:
            return True
        
        total_calls = 0
        unnamed_calls = 0
        for idx, f in cached:
            calls = re.findall(r'\bsub_[0-9A-Fa-f]+\b', f.code or '')
            unnamed_calls += len(calls)
            named_calls = get_calls_fast(f.ea) or []
            total_calls += len(calls) + len(named_calls)
        
        if total_calls > 0 and unnamed_calls / total_calls > 0.4:
            pct = int(unnamed_calls / total_calls * 100)
            res = QMessageBox.warning(self, "Low Context Warning",
                f"{pct}% of function calls in your selection are still "
                f"unnamed (sub_*).\n\n"
                f"This will significantly reduce tagging and indicator accuracy.\n"
                f"Consider running Bulk Renamer first for better results.\n\n"
                f"Continue anyway?",
                QMessageBox.Ok | QMessageBox.Cancel)
            val = res.value if hasattr(res, 'value') else res
            ok_val = QMessageBox.Ok.value if hasattr(QMessageBox.Ok, 'value') else QMessageBox.Ok
            return val == ok_val
        return True

    def show_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid(): return
        
        func = self.model.get_func(idx.row())
        if not func: return
        
        menu = QMenu(self)
        menu.setStyleSheet(STYLES)
        
        pseudocode_action = menu.addAction("View Pseudocode")
        def _view_pseudo():
            idaapi.jumpto(func.ea)
            # Find the pseudocode window if already open or open new
            idaapi.open_pseudocode(func.ea, 0)
        pseudocode_action.triggered.connect(_view_pseudo)
        
        menu.addSeparator()
        reanalyze_action = menu.addAction("Re-analyze this function")
        
        def _reanalyze():
            if not hasattr(self, '_last_cfg') or not self._last_cfg:
                QMessageBox.warning(self, 'Warning', 
                    'No previous analysis config found. Run Analyze + Tag first.')
                return
            
            # Reset cancel flag
            _ai_mod.AI_CANCEL_REQUESTED = False
            
            # Single item worker
            func_index = self.model.filtered[self.table.indexAt(pos).row()]
            single_item = [(func_index, func)]
            w = AnalyzeWorker(
                self._last_cfg, 
                single_item, 
                self.include_ctx_cb.isChecked()
            )
            w.batch_done.connect(self.on_batch_done)
            w.finished.connect(self.on_worker_finished)
            w.log.connect(self.add_log)
            w.update_status.connect(self.on_update_status)
            self.workers.append(w)
            self.add_log(f"Re-analyzing {func.name}...", 'info')
            w.start()
        
        reanalyze_action.triggered.connect(_reanalyze)
        
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def on_table_double_click(self, idx):
        if not idx.isValid(): return
        func = self.model.get_func(idx.row())
        if not func or not func.tag_reason: return
        
        # Show detail dialog
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Analysis Detail: {func.name}")
        dlg.resize(600, 300)
        dlg.setStyleSheet(STYLES)
        
        vbox = QVBoxLayout(dlg)
        
        tag_color = {'malicious': '#FF3B30', 'suspicious': '#FF9500', 'benign': '#8E8E93'}.get(
            func.tag.lower() if func.tag else '', '#333333')
        
        conf_color = '#34C759' if func.confidence >= 80 else '#FF9500' if func.confidence >= 50 else '#FF3B30'
        
        info = QLabel(
            f"<b>Function:</b> {func.name} ({hex(func.ea)})<br>"
            f"<b>Tag:</b> <span style='color:{tag_color}'>{func.tag.upper()}</span><br>"
            f"<b>Confidence:</b> <span style='color:{conf_color}'>{func.confidence}%</span><br>"
            f"<b>Indicators:</b> {func.indicators or 'none'}"
        )
        info.setWordWrap(True)
        vbox.addWidget(info)
        
        edit = QTextEdit()
        edit.setPlainText(func.tag_reason)
        edit.setReadOnly(True)
        vbox.addWidget(edit)
        
        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        vbox.addWidget(btn)
        
        dlg.exec_()

    def open_settings(self):
        from pseudonote.view import SettingsDialog
        d = SettingsDialog(self.pn_config, self, hide_extra_tabs=True, mode='analyzer')
        d.exec_()

    def add_log(self, msg, lv='info'):
        color = '#D4D4D4'
        if lv == 'ok': color = '#4EC9B0'
        elif lv == 'err': color = '#F44336'
        elif lv == 'warn': color = '#D19A66'
        elif lv == 'info': color = '#569CD6'
        
        ts = time.strftime("%H:%M:%S")
        self.log.append(f'<span style="color: gray;">[{ts}]</span> <span style="color: {color};">{msg}</span>')
        self.log.ensureCursorVisible()

    def update_button_states(self):
        has_content = self.model.total() > 0
        has_checked = len(self.model.get_checked()) > 0
        
        self.unload_btn.setEnabled(has_content)
        self.export_btn.setEnabled(has_content)
        
        self.analyze_btn.setEnabled(has_checked)
        self.summarize_btn.setEnabled(has_checked)
        self.forward_btn.setEnabled(has_checked)

    def load_pattern(self):
        pat = self.load_input.text().strip()
        if not pat: return
        self.load_funcs(pattern=pat, replace=False)

    def load_funcs(self, prefix=None, pattern=None, replace=True):
        funcs = []
        for ea in idautils.Functions():
            if not is_valid_seg(ea): continue
            name = idc.get_func_name(ea)
            if not name:
                continue
            
            match = False
            if prefix and name.startswith(prefix):
                match = True
            elif pattern and pattern.lower() in name.lower():
                match = True
            
            if match:
                fdata = FuncData(ea, name)
                stored = load_from_idb(ea, tag=90)
                if stored and '|' in stored:
                    parts = stored.split('|', 3)
                    if len(parts) == 4:
                        fdata.tag, fdata.confidence, fdata.indicators, fdata.tag_reason = \
                            parts[0], int(parts[1]) if parts[1].isdigit() else 0, parts[2], parts[3]
                        fdata.status = 'Cached'
                funcs.append(fdata)
                
        if funcs:
            self.model.set_data(funcs)
            self.add_log(f"Loaded {len(funcs)} functions.", 'ok')
        elif replace:
            # Full replace intent (e.g. Load sub_*): clear even if empty
            self.model.set_data([])
            self.add_log("No functions found. Table cleared.", 'warn')
        else:
            # Search intent: preserve existing list on no match
            msg = "No functions found"
            if prefix: msg += f" with prefix '{prefix}'"
            if pattern: msg += f" containing '{pattern}'"
            self.add_log(f"{msg}. Current list preserved.", 'warn')

    def load_eas(self, eas, append=False):
        if not append:
            self.model.clear()
            
        funcs = []
        for ea in eas:
            name = idc.get_func_name(ea)
            if name:
                fdata = FuncData(ea, name)
                stored = load_from_idb(ea, tag=90)
                if stored and '|' in stored:
                    parts = stored.split('|', 3)
                    if len(parts) == 4:
                        fdata.tag = parts[0]
                        fdata.confidence = int(parts[1]) if parts[1].isdigit() else 0
                        fdata.indicators = parts[2]
                        fdata.tag_reason = parts[3]
                        fdata.status = 'Cached'
                funcs.append(fdata)
                
        if funcs:
            if append:
                self.model.append_data(funcs)
                self.add_log(f"Added {len(funcs)} functions to the table.", 'ok')
            else:
                self.model.set_data(funcs)
                self.add_log(f"Loaded {len(funcs)} functions.", 'ok')

    def unload_table(self):
        self.model.clear()
        self.add_log("Table unloaded.", 'info')

    def start_analyze(self):
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return

        if not self.check_sub_ratio(items):
            return

        # Reset cancel flag before new analysis
        _ai_mod.AI_CANCEL_REQUESTED = False

        self.analyze_btn.setEnabled(False)
        self.summarize_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(items))
        self.progress.setValue(0)

        # Build config dict for worker
        from pseudonote.renamer import BulkRenamer
        temp_renamer = BulkRenamer(self.pn_config)
        cfg = temp_renamer.build_cfg(self.pn_config)
        self._last_cfg = cfg # Enhancement 5: Store last used cfg
        temp_renamer.deleteLater()

        num_workers = cfg.get('parallel_workers', 1)
        batch_size = cfg.get('batch_size', 1)
        
        for w in self.workers:
            w.stop()
        self.workers = []
        self._worker_progress = {} # Bug 2: initialize worker progress tracking
        self.completed_count = 0
        self.total_count = len(items)
        self.progress.setRange(0, self.total_count)

        if num_workers > 1 and len(items) > 1:
            chunk_size = max(1, len(items) // num_workers)
            chunks = [items[i:i+chunk_size] for i in range(0, len(items), chunk_size)]
            self.add_log(f"Starting analysis with {len(chunks)} parallel workers (batch={batch_size})...", 'info')
            for chunk in chunks:
                w = AnalyzeWorker(cfg, chunk, self.include_ctx_cb.isChecked())
                w.batch_done.connect(self.on_batch_done)
                w.progress.connect(self.on_progress)
                w.finished.connect(self.on_worker_finished)
                w.log.connect(self.add_log)
                w.update_status.connect(self.on_update_status)
                self.workers.append(w)
                w.start()
        else:
            self.add_log(f"Starting sequential analysis (batch={batch_size})...", 'info')
            self.worker = AnalyzeWorker(cfg, items, self.include_ctx_cb.isChecked())
            self.worker.batch_done.connect(self.on_batch_done)
            self.worker.progress.connect(self.on_progress) # Connect to global progress handler
            self.worker.finished.connect(self.on_worker_finished) # Connect to global finished handler
            self.worker.log.connect(self.add_log)
            self.worker.update_status.connect(self.on_update_status)
            self.workers.append(self.worker)
            self.worker.start()

    def on_update_status(self, text):
        if not text:
            self.progress.setFormat("%p% (%v/%m)")
            if hasattr(self, '_cooldown_text'):
                self._cooldown_text = ""
            return
            
        if "Cooling down" in text:
            self._cooldown_text = text
            
        display_text = text
        if hasattr(self, '_cooldown_text') and self._cooldown_text and "Analyzing" in text:
            display_text = f"{self._cooldown_text} | {text}"
            
        self.progress.setFormat(f"{display_text} | %p%")

    def on_progress(self, done, total):
        if not hasattr(self, '_worker_progress'):
            self._worker_progress = {}
        sender_id = id(self.sender())
        prev = self._worker_progress.get(sender_id, 0)
        delta = done - prev
        self._worker_progress[sender_id] = done
        if hasattr(self, 'completed_count') and hasattr(self, 'total_count'):
            self.completed_count += delta
            self.progress.setValue(min(self.completed_count, self.total_count))

    def on_worker_finished(self, count):
        # Remove finished worker from list
        sender = self.sender()
        if sender in self.workers:
            self.workers.remove(sender)
        
        # Only finish when all workers are done
        if not self.workers:
            self.finish_analyze()
            if _ai_mod.AI_CANCEL_REQUESTED:
                self.add_log("Analysis stopped by user.", 'warn')

    def on_batch_done(self, results):
        # Capture sort state before any mutations
        sort_col = self.model.sort_col
        sort_ord = self.model.sort_ord
        
        indices = []
        for idx, func, tag, confidence, indicators, reason in results:
            func.tag = tag
            func.confidence = confidence
            func.indicators = indicators
            func.tag_reason = reason
            func.status = 'OK'
            indices.append(idx)
            
            # Save to IDB
            save_to_idb(func.ea, f"{func.tag}|{func.confidence}|{func.indicators}|{func.tag_reason}", tag=90)
            
        # sort() calls beginResetModel/endResetModel which redraws all rows.
        # No need to call refresh_rows() after — it would operate on a
        # stale indices list and is redundant.
        self.model.sort(sort_col, sort_ord)

    def finish_analyze(self):
        self.progress.setVisible(False)
        self.stop_btn.setEnabled(False)
        self.add_log("Analysis complete.", 'ok')
        _ai_mod.AI_CANCEL_REQUESTED = False   # always reset after finish
        self.update_button_states()  # handles analyze/summarize/forward correctly

    def stop_all(self):
        _ai_mod.AI_CANCEL_REQUESTED = True
        self.stop_btn.setEnabled(False)  # prevent double-click
        self.progress.setFormat("Stopping... waiting for current function to finish")
        for w in self.workers:
            w.stop()
        if hasattr(self, 'worker') and self.worker:
            self.worker.stop()
        self.add_log("Stop requested. Waiting for current function to finish...", 'warn')

    def summarize_selected(self):
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return

        self.add_log("Preparing holistic summary...", 'info')
        
        full_prompt = "Perform a collective behavioral summary for these functions. What do they do together as a module?\n\n"
        char_limit_per_func = 3000 # Increased from 500 to capture more logic
        total_limit = 32000 # Increased to allow for more content in context-rich models
        omitted = 0
        
        added_count = 0
        for i, (idx, f) in enumerate(items):
            if not f.code:
                f.code = get_code_fast(f.ea, 3000)
            
            snippet = f.code or "No code found"
            if len(snippet) > char_limit_per_func:
                snippet = snippet[:char_limit_per_func] + "..."
            
            entry = f"Function {f.name} ({hex(f.ea)})"
            if f.tag:
                entry += f" [Tag: {f.tag.upper()}, Confidence: {f.confidence}%"
                if f.indicators:
                    entry += f", Indicators: {f.indicators}"
                entry += "]"
            entry += f":\n```\n{snippet}\n```\n\n"
            
            if len(full_prompt) + len(entry) > total_limit:
                omitted = len(items) - i
                full_prompt += f"\n[truncated: {omitted} functions omitted due to length]"
                break
            
            full_prompt += entry
            added_count += 1
        
        # Guard: abort if nothing was added
        if added_count == 0:
            self.add_log(
                "Error: All selected functions exceed the total prompt limit. "
                "Select fewer or shorter functions.", 'err')
            if hasattr(self, 'summary_dlg'):
                self.summary_dlg.close()
            return

        sys_prompt = """You are an expert malware analyst. Given multiple decompiled 
functions from the same binary (some with pre-computed tags and indicators), 
provide a unified behavioral analysis covering:
1. What this module/component appears to do collectively
2. The likely execution flow or call chain between these functions
3. Any indicators of malicious capability (even if individual functions 
   appear benign in isolation)
4. How the pre-tagged malicious/suspicious functions relate to the 
   overall module behavior
5. Confidence level and what additional context would improve the analysis

Be specific. Reference function names, tags, and behaviors observed. 
Do not pad with generic statements."""
        
        # Build config & model messages
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": full_prompt}
        ]
        
        self.summary_dlg = StreamingSummaryDialog(self)
        self.summary_dlg.show()
        
        try:
            ai = SimpleAI(self.pn_config)
            self.add_log("Sending holistic request to AI (streaming)...", 'info')
            
            def _on_chunk(partial):
                if hasattr(self, 'summary_dlg') and self.summary_dlg:
                    self.summary_dlg.append_chunk(partial)
            
            def _on_done(response, finish_reason):
                if hasattr(self, 'summary_dlg') and self.summary_dlg:
                    self.summary_dlg.finalize(response)
                    self.add_log("Summary complete.", 'ok')
                else:
                    self.add_log("AI finished but dialog was closed.", 'warn')

            ai.query_model_async(messages, callback=_on_done, on_chunk=_on_chunk)
            
        except Exception as e:
            self.add_log(f"Summary Error: {str(e)}", 'err')
            if hasattr(self, 'summary_dlg'):
                self.summary_dlg.close()

    def forward_to_renamer(self):
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return
        
        eas = [f.ea for idx, f in items]
        self.add_log(f"Forwarding {len(eas)} functions to Bulk Renamer...", 'info')
        
        from pseudonote.renamer import BulkRenamer
        found = None
        # Try to find an open BulkRenamer dialog
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, BulkRenamer) and widget.isVisible():
                found = widget
                break
        
        if found:
            found.load_eas(eas)
            found.raise_()
            found.activateWindow()
        else:
            # Create a new one
            dlg = BulkRenamer(self.pn_config, self.parent())
            dlg.show()
            dlg.load_eas(eas)

    def export_csv(self):
        if not self.model.funcs:
            QMessageBox.warning(self, 'Warning', 'Table is empty')
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if not path: return
        
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Use headers from model but skip the checkbox column
                writer.writerow(self.model.HEADERS[1:])
                
                # Export all functions in the current model (respecting filter if we want, 
                # but usually "export" means the current view. Let's export what's visible)
                for i in self.model.filtered:
                    func = self.model.funcs[i]
                    writer.writerow([
                        f"{func.ea:X}",
                        func.demangled or func.name,
                        func.tag,
                        func.confidence,
                        func.indicators,
                        func.tag_reason,
                        func.status
                    ])
            self.add_log(f"Exported {len(self.model.filtered)} rows to {os.path.basename(path)}", 'ok')
            QMessageBox.information(self, "Success", f"Data exported successfully to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export CSV: {str(e)}")
            self.add_log(f"Export error: {str(e)}", 'err')

    def show_summary_dialog(self, text):
        dlg = QDialog(self)
        dlg.setWindowTitle("Holistic Behavioral Summary")
        dlg.resize(800, 600)
        dlg.setStyleSheet(STYLES)
        
        vbox = QVBoxLayout(dlg)
        edit = QTextEdit()
        edit.setPlainText(text)
        edit.setReadOnly(True)
        vbox.addWidget(edit)
        
        h = QHBoxLayout()
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(text))
        h.addWidget(copy_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        h.addWidget(close_btn)
        vbox.addLayout(h)
        
        dlg.exec_()
