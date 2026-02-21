# -*- coding: utf-8 -*-
import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment
import json, os, re, time, threading, queue, configparser
from collections import deque

try:
    import requests
    HAS_REQUESTS = True
    SESSION = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=30, pool_maxsize=30, max_retries=2, pool_block=False)
    SESSION.mount('http://', adapter)
    SESSION.mount('https://', adapter)
except ImportError:
    HAS_REQUESTS = False
    SESSION = None

import urllib.request, urllib.error

# GUI Imports
from pseudonote.qt_compat import QtWidgets, QtGui, QtCore, Signal
from pseudonote.qt_compat import (
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, 
    QSpinBox, QProgressBar, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QHeaderView, QAbstractItemView, QMenu, QAction,
    QDialog, QDialogButtonBox, QGroupBox, QFileDialog,
    QApplication, QThread, QTimer, QAbstractTableModel,
    QModelIndex, QTableView, QColor, QFont, QIcon, QSize,
    QBrush, QPainter, QPalette, QKeySequence, QTextEdit,
    QWidget, QTabWidget, QStackedWidget, QSplitter, QSpacerItem
)
Qt = QtCore.Qt

# Modern Dark Theme (VS Code / Material inspired)
STYLES = """
QWidget {
    background-color: #1E1E1E;
    color: #CCCCCC;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10pt;
}

QDialog {
    background-color: #1E1E1E;
}

QGroupBox {
    border: 1px solid #3E3E42;
    border-radius: 4px;
    margin-top: 20px; /* Leave space for title */
    background-color: #252526;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 5px;
    color: #4FC3F7; /* Light Blue */
    background-color: #1E1E1E; /* Match dialog bg to cut through border */
}

QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #2D2D30;
    border: 1px solid #3E3E42;
    border-radius: 2px;
    color: #F0F0F0;
    padding: 4px;
    selection-background-color: #264F78;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #007ACC; /* VS Code Blue */
}
QLineEdit:disabled {
    color: #6D6D6D;
    background-color: #252526;
}

QPushButton {
    background-color: #3E3E42;
    color: #FFFFFF;
    border: 1px solid #3E3E42;
    padding: 6px 16px;
    border-radius: 2px;
}
QPushButton:hover {
    background-color: #4E4E52;
    border-color: #5E5E62;
}
QPushButton:pressed {
    background-color: #007ACC;
    border-color: #007ACC;
}
QPushButton:disabled {
    background-color: #2D2D30;
    color: #6D6D6D;
    border-color: #2D2D30;
}

/* Specific Button Styles */
QPushButton#primary {
    background-color: #007ACC;
    border-color: #007ACC;
}
QPushButton#primary:hover {
    background-color: #0098FF;
}

QPushButton#success {
    background-color: #388E3C;
    border-color: #388E3C;
}
QPushButton#success:hover {
    background-color: #43A047;
}

QPushButton#danger {
    background-color: #D32F2F;
    border-color: #D32F2F;
}
QPushButton#danger:hover {
    background-color: #E53935;
}

QTableView {
    background-color: #252526;
    border: 1px solid #3E3E42;
    gridline-color: #3E3E42;
    selection-background-color: #264F78;
    selection-color: #FFFFFF;
    alternate-background-color: #2D2D30;
}
QTableView::item {
    padding: 2px;
}
QHeaderView::section {
    background-color: #2D2D30;
    color: #CCCCCC;
    padding: 4px;
    border: none;
    border-right: 1px solid #3E3E42;
    border-bottom: 1px solid #3E3E42;
    font-weight: bold;
}
QHeaderView::section:horizontal {
    border-top: 1px solid #3E3E42;
}

QScrollBar:vertical {
    border: none;
    background: #1E1E1E;
    width: 14px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #424242;
    min-height: 20px;
    border-radius: 0px;
}
QScrollBar::handle:vertical:hover {
    background: #686868;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px; 
}

QProgressBar {
    background-color: #2D2D30;
    border: none;
    color: #FFFFFF;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #007ACC;
}

QSpinBox {
    background-color: #2D2D30;
    border: 1px solid #3E3E42;
    padding: 2px;
    color: #F0F0F0;
}
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #3E3E42;
    border: none;
    width: 16px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #4E4E52;
}

QLabel {
    color: #CCCCCC;
}
QLabel#h1 {
    color: #FFFFFF;
    font-size: 12pt;
    font-weight: bold;
}
QLabel#accent {
    color: #4FC3F7;
}
QLabel#dim {
    color: #808080;
    font-style: italic;
}

QComboBox {
    background-color: #3E3E42;
    border: 1px solid #3E3E42;
    border-radius: 2px;
    padding: 4px;
    color: #FFFFFF;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #252526;
    border: 1px solid #3E3E42;
    selection-background-color: #007ACC;
    color: #FFFFFF;
}
"""

SKIP_SEGS = {'.plt','.plt.got','.plt.sec','extern','.extern','.got','.got.plt','.init','.fini','.dynsym','.dynstr','LOAD','.interp','.rela.dyn','.rela.plt','.hash','.gnu.hash','.note','.note.gnu.build-id','.note.ABI-tag'}
SYS_PREFIX = ('__cxa_','__gxx_','__gnu_','__libc_','__ctype_','_GLOBAL_','_init','_fini','_start','atexit','malloc','free','memcpy','memset','strlen','printf','scanf','fprintf','sprintf','operator','std::','boost::','__stack_chk','__security','_security','__report','__except','__imp_','__x86.','__do_global')
SYS_MODULES = ('kernel32.','ntdll.','user32.','advapi32.','msvcrt.','ucrtbase.','ws2_32.','libc.so','libm.so','libpthread','foundation.','corefoundation.','uikit.')

DEFAULT_PROMPT = """You are an expert reverse engineer. Analyze the decompiled code and suggest a descriptive function name.

Rules:
- Use snake_case format
- Be specific and descriptive (e.g., parse_user_config, validate_license_key, decrypt_network_packet)
- Focus on what the function DOES, not how
- Use common prefixes: init_, parse_, validate_, process_, handle_, send_, recv_, encrypt_, decrypt_, load_, save_, get_, set_, create_, destroy_, check_, is_, has_
- Keep names 3-40 characters
- NO generic names like: func1, do_something, process_data, handle_stuff

Output ONLY the function name, nothing else."""

DEFAULT_BATCH_PROMPT = """You are an expert reverse engineer. For each function below, suggest a descriptive snake_case name.

Rules:
- snake_case format only
- Be specific: parse_config_file, validate_user_token, send_heartbeat_packet
- Focus on WHAT function does
- Common prefixes: init_, parse_, validate_, process_, handle_, send_, recv_, encrypt_, decrypt_, load_, save_, get_, set_, create_, destroy_, check_, is_, has_
- 3-40 chars per name
- NO generic names

Output format - exactly one name per line, numbered:
1. suggested_name_one
2. suggested_name_two
..."""

def is_valid_seg(ea):
    seg = idaapi.getseg(ea)
    if not seg: return False
    name = idaapi.get_segm_name(seg)
    if not name or name in SKIP_SEGS: return False
    return name.startswith('.text') or name in ('CODE','.code') or ('.' not in name and seg.perm & idaapi.SEGPERM_EXEC)

def is_sys_func(name):
    nl = name.lower()
    for p in SYS_PREFIX:
        if name.startswith(p) or nl.startswith(p.lower()): return True
    for m in SYS_MODULES:
        if m in nl: return True
    return False

def get_func_size(ea):
    f = ida_funcs.get_func(ea)
    return (f.end_ea - f.start_ea) if f else 0

def get_xref_count(ea):
    c = 0
    for _ in idautils.CodeRefsTo(ea, True):
        c += 1
        if c > 150: break
    return c

def get_code_fast(ea, max_len=1200):
    result = [None]
    def _get_code():
        try:
            cf = ida_hexrays.decompile(ea)
            if cf:
                result[0] = str(cf)[:max_len]
                return
        except: pass
        f = ida_funcs.get_func(ea)
        if not f:
            result[0] = None
            return
        lines = []
        cur = f.start_ea
        while cur < f.end_ea and len(lines) < 25:
            lines.append(idc.GetDisasm(cur))
            cur = idc.next_head(cur, f.end_ea)
        result[0] = '\n'.join(lines)[:max_len]
    idaapi.execute_sync(_get_code, idaapi.MFF_READ)
    return result[0]

def get_strings_fast(ea):
    result = [[]]
    def _get_strings():
        r = []
        try:
            for item in idautils.FuncItems(ea):
                for xref in idautils.DataRefsFrom(item):
                    s = idc.get_strlit_contents(xref)
                    if s:
                        try:
                            s = s.decode() if isinstance(s, bytes) else s
                            if 2 < len(s) < 60: r.append(s[:50])
                        except: pass
                if len(r) >= 4: break
        except: pass
        result[0] = list(set(r))[:4]
    idaapi.execute_sync(_get_strings, idaapi.MFF_READ)
    return result[0]

def get_calls_fast(ea):
    result = [[]]
    def _get_calls():
        r = []
        try:
            for item in idautils.FuncItems(ea):
                for xref in idautils.CodeRefsFrom(item, False):
                    n = idc.get_func_name(xref)
                    if n and not n.startswith('sub_'): r.append(n)
                if len(r) >= 5: break
        except: pass
        result[0] = list(set(r))[:5]
    idaapi.execute_sync(_get_calls, idaapi.MFF_READ)
    return result[0]

def ai_request(cfg, prompt, sys_prompt, logger=None):
    # cfg is expected to be a dict with needed keys from PseudoNote Config
    url = cfg.get('api_url', '')
    req_url = url # Default to provided URL
    key = cfg.get('api_key', '')
    model = cfg.get('model', '')
    provider = cfg.get('provider', 'openai')
    
    hdrs = {'Content-Type': 'application/json'}
    
    # Simple logic similar to original but using PseudoNote detected provider type (if passed) or inferring
    
    is_ollama = provider == 'ollama' or 'localhost:11434' in url
    is_anthropic = provider == 'anthropic' or 'anthropic.com' in url
    is_ollama_native = is_ollama and '/api/' in url

    if is_ollama_native:
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}],'stream':False,'options':{'temperature':0.1,'num_predict':500}}
    elif is_anthropic:
        hdrs['x-api-key'] = key
        hdrs['anthropic-version'] = '2023-06-01'
        data = {'model':model,'max_tokens':500,'messages':[{'role':'user','content':sys_prompt+'\n\n'+prompt}],'temperature':0.1}
    else:
        # Standard OpenAI compatible
        if key: hdrs['Authorization'] = f'Bearer {key}'
        
        # Ensure we target the chat/completions endpoint
        if not req_url.endswith('chat/completions') and not req_url.endswith('/generate'):
            req_url = f"{req_url.rstrip('/')}/chat/completions"
            
        data = {'model':model,'messages':[{'role':'system','content':sys_prompt},{'role':'user','content':prompt}]}
        
        # Reasoning models (o1, o3, gpt-5) don't support max_tokens or temperature
        is_reasoning = any(x in model.lower() for x in ['o1', 'o3', 'gpt-5'])
        if is_reasoning:
            data['max_completion_tokens'] = 4096 # Reasoning models need large budget for internal chain-of-thought
        else:
            data['max_tokens'] = 500
            data['temperature'] = 0.1

    # Implement specific retry logic for 429 errors as requested
    # Try once. If 429, wait 60s, try again. If 429 again, fail.
    
    for attempt in range(2):
        try:
            if HAS_REQUESTS and SESSION:
                # Use local reference for data to avoid UnboundLocalError
                r = SESSION.post(req_url, headers=hdrs, json=data, timeout=120)
                r.raise_for_status()
                res = r.json()
            else:
                # Fallback to urllib if requests missing
                req = urllib.request.Request(req_url, json.dumps(data).encode(), hdrs)
                with urllib.request.urlopen(req, timeout=120) as r:
                    res = json.loads(r.read().decode())
            
            # Return parsed response immediately on success
            if is_ollama_native: return res.get('message',{}).get('content','').strip()
            elif is_anthropic: return res['content'][0]['text'].strip()
            
            # OpenAI / OpenAI-compatible
            msg = res.get('choices', [{}])[0].get('message', {})
            content = msg.get('content') or ''
            refusal = msg.get('refusal') or ''
            
            # Log refusal if present
            if refusal:
                warn = f"Model refused request: {refusal[:200]}"
                if logger: logger(warn)
                else: print(f"[PseudoNote] {warn}")
            
            # For reasoning models, content might be empty but reasoning is in 'reasoning_content'
            if not content.strip():
                content = msg.get('reasoning_content') or msg.get('reasoning') or ''
            
            if not content.strip():
                # Dump the FULL raw response to IDA output so we can see what's happening
                raw = json.dumps(res, indent=2, default=str)
                print(f"[PseudoNote] EMPTY RESPONSE - Full API JSON:\n{raw[:2000]}\n{'-'*40}")
                if logger:
                    logger(f"Warning: Empty content from API. content={repr(msg.get('content'))}, refusal={repr(refusal)}")
                    
                # Check if there's an 'output' field (some newer API formats)
                if 'output' in res:
                    out = res['output']
                    if isinstance(out, str): content = out
                    elif isinstance(out, list):
                        for item in out:
                            if isinstance(item, dict) and item.get('content'):
                                content = item['content']
                                break
            
            return content.strip()

        except Exception as e:
            # Generic retry on any error (429, timeout, network, etc)
            if attempt == 0:
                err_msg = str(e)
                try:
                    import requests
                    if isinstance(e, requests.exceptions.RequestException) and e.response is not None:
                        err_msg += f" (Status: {e.response.status_code}) | {e.response.text[:150]}"
                except: pass

                msg = f"API Request Failed: {err_msg}. Sleeping 120s before retry..."
                if logger: logger(msg)
                else: print(f"[PseudoNote] {msg}")
                
                time.sleep(120)
                continue
            
            # Second failure (attempt 1) -> terminate request
            raise e

def clean_name(name, existing=None):
    if not name: return None
    name = re.sub(r'[`"\'\n\r\t]', '', name)
    name = name.split('(')[0].split(':')[-1].strip()
    name = re.sub(r'^[\d\.\-\*\s]+', '', name)
    m = re.search(r'\b([a-z][a-z0-9_]*[a-z0-9])\b', name.lower())
    if m:
        name = m.group(1)
    else:
        name = re.sub(r'_+', '_', re.sub(r'[^a-zA-Z0-9_]', '_', name)).strip('_').lower()
    name = re.sub(r'^[0-9_]+', '', name)[:50]
    
    if not name or len(name) < 3: return None
    if name in ('function','func','sub','unknown','unnamed','noname'): return None
    
    # Add prefix as requested
    if not name.startswith('fn_b_'):
        name = f"fn_b_{name}"

    if existing:
        orig, cnt = name, 1
        while name in existing:
            name = f"{orig}_{cnt}"
            cnt += 1
            if cnt > 99: return None
    return name

class FuncData:
    __slots__ = ['ea','name','suggested','status','checked','code','strings','calls']
    def __init__(self, ea, name):
        self.ea, self.name, self.suggested, self.status, self.checked = ea, name, '', 'Pending', True
        self.code = self.strings = self.calls = None

class ResultSignal(QThread):
    result = Signal(list)
    def __init__(self): super().__init__()

class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['', 'Address', 'Current Name', 'AI Suggestion', 'Status']
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.funcs, self.filtered, self.filter_text = [], [], ''

    def set_data(self, funcs):
        self.beginResetModel()
        self.funcs = funcs
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
            self.filtered = [i for i,f in enumerate(self.funcs) if ft in f.name.lower() or ft in f'{f.ea:x}' or (f.suggested and ft in f.suggested.lower())]

    def set_filter(self, t):
        self.beginResetModel()
        self.filter_text = t
        self._apply_filter()
        self.endResetModel()

    def rowCount(self, p=QModelIndex()): return len(self.filtered)
    def columnCount(self, p=QModelIndex()): return 5
    def headerData(self, s, o, r=Qt.DisplayRole): return self.HEADERS[s] if r==Qt.DisplayRole and o==Qt.Horizontal else None

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self.filtered): return None
        f = self.funcs[self.filtered[idx.row()]]
        c = idx.column()
        
        if role == Qt.DisplayRole:
            # Column 0 is checkbox now, handled by CheckStateRole
            if c==1: return f'{f.ea:X}'
            elif c==2: return f.name
            elif c==3: return f.suggested
            elif c==4: return f.status
            
        elif role == Qt.CheckStateRole and c==0:
            return Qt.Checked if f.checked else Qt.Unchecked
            
        elif role == Qt.TextAlignmentRole:
            if c==0: return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ForegroundRole and c==4:
            # Color code status
            if f.status == 'OK': return QColor('#4EC9B0') # Green-ish
            if f.status == 'Skip': return QColor('#808080') # Gray
            if f.status == 'Applied': return QColor('#569CD6') # Blue-ish
            if f.status == 'Pending': return QColor('#DCDCAA') # Yellow-ish
            
        return None

    def setData(self, idx, value, role=Qt.EditRole):
        if idx.isValid() and role == Qt.CheckStateRole and idx.column() == 0:
            # Handle PySide6 strict typing
            val = value.value if hasattr(value, 'value') else value
            chk = Qt.Checked.value if hasattr(Qt.Checked, 'value') else Qt.Checked
            
            f = self.funcs[self.filtered[idx.row()]]
            f.checked = (val == chk)
            self.dataChanged.emit(idx, idx, [Qt.CheckStateRole])
            return True
        return False

    def flags(self, idx):
        # Handle PySide6 strict typing
        f_enabled = Qt.ItemIsEnabled
        f_selectable = Qt.ItemIsSelectable
        f_check = Qt.ItemIsUserCheckable
        
        if hasattr(f_enabled, 'value'):
            val = f_enabled.value | f_selectable.value
            if idx.column() == 0:
                val |= f_check.value
            try:
                return Qt.ItemFlag(val)
            except:
                return val
        else:
            base = f_enabled | f_selectable
            if idx.column() == 0:
                base |= f_check
            return base

    def get_func(self, row): return self.funcs[self.filtered[row]] if 0<=row<len(self.filtered) else None
    
    def refresh_rows(self, indices):
        if not indices: return
        rows = [self.filtered.index(i) for i in indices if i in self.filtered]
        if rows:
            self.dataChanged.emit(self.index(min(rows),0), self.index(max(rows),4))

    def toggle_all(self, chk):
        for i in self.filtered:
            self.funcs[i].checked = chk
        if self.filtered:
            self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))

    def get_checked(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked]
    def get_with_suggestions(self): return [(i,f) for i,f in enumerate(self.funcs) if f.checked and f.suggested]
    def total(self): return len(self.funcs)

class AnalyzeWorker(QThread):
    batch_done = Signal(list)
    progress = Signal(int, int)
    finished = Signal(int)
    log = Signal(str, str)

    def __init__(self, cfg, items, existing, sys_prompt, batch_size):
        super().__init__()
        self.cfg = cfg
        self.items = items
        self.existing = set(existing)
        self.sys_prompt = sys_prompt
        self.batch_size = batch_size
        self.batch_size = batch_size
        self.running = True
        self.needs_cooldown = False

    def stop(self):
        self.running = False

    def run(self):
        done = 0
        total = len(self.items)
        batches = [self.items[i:i+self.batch_size] for i in range(0, total, self.batch_size)]

        for batch in batches:
            if not self.running: break
            results = self.process_batch(batch)
            for idx, func, name in results:
                if name:
                    self.existing.add(name)
            self.batch_done.emit(results)
            done += len(batch)
            self.progress.emit(done, total)
            
            if self.needs_cooldown:
                time.sleep(22)
                self.needs_cooldown = False

        self.finished.emit(done)

    def process_batch(self, batch):
        results = []
        valid = []

        for idx, func in batch:
            if not func.code:
                # self.log.emit(f"Getting code for {hex(func.ea)}...", 'info')
                func.code = get_code_fast(func.ea, 800)
                func.strings = get_strings_fast(func.ea)
                func.calls = get_calls_fast(func.ea)
            
            if func.code:
                valid.append((idx, func))
            else:
                self.log.emit(f"Skipping {hex(func.ea)}: No code found", 'warn')
                results.append((idx, func, None))

        if not valid:
            self.log.emit("Batch empty (no valid functions with code)", 'warn')
            return results

        try:
            self.needs_cooldown = True
            logger = lambda m: self.log.emit(m, 'info')
            
            if len(valid) == 1:
                idx, f = valid[0]
                self.log.emit(f"Processing single function: {f.name} ({hex(f.ea)})", 'info')
                prompt = f"Code:\n```\n{f.code}\n```"
                if f.strings: prompt += f"\nStrings found: {f.strings}"
                if f.calls: prompt += f"\nCalled functions: {f.calls}"
                resp = ai_request(self.cfg, prompt, self.sys_prompt, logger=logger)
                name = clean_name(resp, self.existing)
                results.append((idx, f, name))
            else:
                self.log.emit(f"Processing batch of {len(valid)} functions...", 'info')
                prompt = "Functions to name:\n\n"
                for i, (idx, f) in enumerate(valid):
                    prompt += f"[{i+1}]\n```\n{f.code[:600]}\n```\n"
                    if f.strings: prompt += f"Strings: {f.strings[:3]}\n"
                    if f.calls: prompt += f"Calls: {f.calls[:3]}\n"
                    prompt += "\n"

                resp = ai_request(self.cfg, prompt, self.sys_prompt, logger=logger)
                names, actual_count = self.parse_batch_response(resp, len(valid))
                self.log.emit(f"API returned {actual_count} names for batch of {len(valid)}", 'info')

                for i, (idx, f) in enumerate(valid):
                    suggestion = names[i] if i < len(names) else None
                    name = clean_name(suggestion, self.existing) if suggestion else None
                    
                    if name:
                        self.existing.add(name)
                    elif suggestion:
                        self.log.emit(f"Suggestion '{suggestion}' for {hex(f.ea)} rejected by clean_name", 'warn')
                    else:
                        self.log.emit(f"No suggestion found for {hex(f.ea)} (index {i+1} in batch)", 'warn')
                        
                    results.append((idx, f, name))

        except Exception as e:
            self.log.emit(f'Batch Error: {str(e)[:100]}', 'err')
            import traceback
            print(f"[PseudoNote] Batch error traceback:")
            traceback.print_exc()
            for idx, f in valid:
                results.append((idx, f, None))

        return results

    def parse_batch_response(self, resp, expected):
        if not resp or not resp.strip():
            self.log.emit("Warning: AI returned empty response!", 'warn')
            return [None] * expected, 0

        names = []
        
        # Log first 200 chars of response
        snippet = resp.strip()[:200].replace('\n', ' | ')
        self.log.emit(f"Parsing response: {snippet}", 'info')

        # Strategy 1: Split by lines and try to extract one name per line
        for line in resp.split('\n'):
            line = line.strip()
            if not line or '```' in line: continue
            
            # Strip common list prefixes: "1. ", "- ", "* ", "[1] ", "**1.**", etc.
            clean = re.sub(r'^[\s\d\.\)\-\*\#\[\]\:\|]+', '', line).strip()
            # Also strip leading "Function", "Fn", etc. (case-insensitive)
            clean = re.sub(r'^(function|func|fn|sub)\s*[\d\.\)\:\-]*\s*', '', clean, flags=re.IGNORECASE).strip()
            
            if not clean or len(clean) < 3: continue
            
            # Extract the first token that looks like an identifier
            parts = re.split(r'[\s,\:\(\)\|]+', clean)
            if not parts: continue
            nm = parts[0].strip(' "\'`*')
            nm = re.sub(r'[^a-zA-Z0-9_]', '', nm)
            
            if nm and len(nm) >= 3 and nm.lower() not in ('function','func','sub','unknown','unnamed','noname','the','this','and','for','with'):
                names.append(nm)

        # Fallback: regex scan for identifiers in the whole response
        if len(names) < expected:
            # Regex for common function naming patterns (snake_case, camelCase)
            found = re.findall(r'\b([a-zA-Z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)*)\b', resp)
            for n in found:
                if len(n) >= 3 and n.lower() not in ('void', 'int', 'char', 'return', 'include', 'func', 'function', 'const', 'unsigned', 'static'):
                    # In fallback mode, we still allow duplicates if needed, but usually we try to fill gaps
                    if len(names) < expected:
                        names.append(n)
                    else:
                        break

        if len(names) < expected:
            self.log.emit(f"Parser found {len(names)}/{expected} names. Check IDA Output for raw text.", 'warn')
            print(f"[PseudoNote] Raw API Response:\n{resp}\n{'-'*40}")

        actual_count = min(len(names), expected)
        while len(names) < expected:
            names.append(None)
            
        return names[:expected], actual_count

class RenamerSettingsDialog(QDialog):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Settings")
        self.resize(500, 350)
        self.setStyleSheet(STYLES)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # API Provider settings
        layout.addWidget(QLabel("API Provider:"))
        self.provider_cb = QComboBox()
        self.provider_cb.addItems(["OpenAI", "Anthropic", "Ollama", "LMStudio", "OpenAICompatible", "DeepSeek", "Gemini"])
        layout.addWidget(self.provider_cb)

        layout.addWidget(QLabel("API URL:"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://api.openai.com/v1")
        layout.addWidget(self.url_edit)

        layout.addWidget(QLabel("Model Code/Name:"))
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("gpt-4")
        layout.addWidget(self.model_edit)

        # API Key
        layout.addWidget(QLabel("API Key:"))
        self.key_edit = QLineEdit()
        layout.addWidget(self.key_edit)
        
        # Performance Section
        layout.addSpacing(10)
        layout.addWidget(QLabel("<b>Bulk Renamer Settings</b>"))
        perf_grp = QGroupBox("Optimization")
        perf_layout = QGridLayout()
        
        perf_layout.addWidget(QLabel("Batch Size:"), 0, 0)
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(1, 50)
        self.batch_spin.setValue(getattr(self.config, 'batch_size', 10))
        perf_layout.addWidget(self.batch_spin, 0, 1)

        perf_layout.addWidget(QLabel("Parallel Workers:"), 0, 2)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 10)
        self.workers_spin.setValue(getattr(self.config, 'parallel_workers', 1))
        perf_layout.addWidget(self.workers_spin, 0, 3)
        
        perf_grp.setLayout(perf_layout)
        layout.addWidget(perf_grp)
        layout.addStretch()

        # Select current provider
        curr = self.config.active_provider
        idx = self.provider_cb.findText(curr, Qt.MatchFixedString) if curr else -1
        if idx >= 0: self.provider_cb.setCurrentIndex(idx)
        else: self.provider_cb.setCurrentText(curr if curr else "OpenAI")

        # Connect
        self.provider_cb.currentTextChanged.connect(self.load_for_provider)
        self.load_for_provider(self.provider_cb.currentText())

        # Save Button
        try:
            btns = QDialogButtonBox.StandardButton(QDialogButtonBox.Save.value | QDialogButtonBox.Cancel.value)
        except AttributeError:
            btns = QDialogButtonBox.Save | QDialogButtonBox.Cancel

        btn_box = QDialogButtonBox(btns)
        btn_box.accepted.connect(self.save)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def load_for_provider(self, p):
        p = p.lower()
        if p == 'openai':
            self.url_edit.setText(self.config.openai_url)
            self.model_edit.setText(self.config.openai_model)
            self.key_edit.setText(self.config.openai_key)
        elif p == 'deepseek':
            self.url_edit.setText(self.config.deepseek_url)
            self.model_edit.setText(self.config.deepseek_model)
            self.key_edit.setText(self.config.deepseek_key)
        elif p == 'anthropic':
            self.url_edit.setText(self.config.anthropic_url)
            self.model_edit.setText(self.config.anthropic_model)
            self.key_edit.setText(self.config.anthropic_key)
        elif p == 'ollama':
            self.url_edit.setText(self.config.ollama_host)
            self.model_edit.setText(self.config.ollama_model)
            self.key_edit.setText("ollama") 
        elif p == 'lmstudio':
            self.url_edit.setText(self.config.lmstudio_url)
            self.model_edit.setText(self.config.lmstudio_model)
            self.key_edit.setText(self.config.lmstudio_key)
        elif p == 'openaicompatible':
            self.url_edit.setText(self.config.custom_url)
            self.model_edit.setText(self.config.custom_model)
            self.key_edit.setText(self.config.custom_key)
        elif p == 'gemini':
            self.url_edit.setText('google_generative_ai')
            self.model_edit.setText(self.config.gemini_model)
            self.key_edit.setText(self.config.gemini_key)

    def save(self):
        p = self.provider_cb.currentText()
        self.config.active_provider = p 
        
        pl = p.lower()
        url = self.url_edit.text().strip()
        model = self.model_edit.text().strip()
        key = self.key_edit.text().strip()
        
        if pl == 'openai':
            self.config.openai_url = url
            self.config.openai_model = model
            self.config.openai_key = key
        elif pl == 'deepseek':
            self.config.deepseek_url = url
            self.config.deepseek_model = model
            self.config.deepseek_key = key
        elif pl == 'anthropic':
            self.config.anthropic_url = url
            self.config.anthropic_model = model
            self.config.anthropic_key = key
        elif pl == 'ollama':
            self.config.ollama_host = url
            self.config.ollama_model = model
        elif pl == 'lmstudio':
            self.config.lmstudio_url = url
            self.config.lmstudio_model = model
            self.config.lmstudio_key = key
            self.config.custom_url = url
            self.config.custom_model = model
            self.config.custom_key = key
        elif pl == 'gemini':
             self.config.gemini_key = key
             self.config.gemini_model = model

        try:
            # Save Performance
            self.config.batch_size = self.batch_spin.value()
            self.config.parallel_workers = self.workers_spin.value()
            self.config.save()
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")

class BulkRenamer(QDialog):
    def __init__(self, pn_config, parent=None):
        super().__init__(parent)
        self.pn_config = pn_config
        self.cfg = self.build_cfg(pn_config)
        self.model = None
        self.is_loading = False
        self.load_timer = None
        self.func_iter = None
        self.temp_funcs = []
        self.scanned = 0
        self.workers = []
        self.existing_names = set()
        self.setup_ui()

    def open_settings(self):
        d = RenamerSettingsDialog(self.pn_config, self)
        if d.exec_():
            # Refresh local config from updated pn_config
            self.cfg = self.build_cfg(self.pn_config)
            # Maybe show status message?
            self.add_log(f"Settings updated. Provider: {self.cfg['provider']}, Model: {self.cfg['model']}")

    def build_cfg(self, c):
        # Convert PseudoNote config to local format expected by workers
        cfg = {
            'provider': c.active_provider,
            'batch_size': getattr(c, 'batch_size', 10),
            'parallel_workers': getattr(c, 'parallel_workers', 1),
            'use_custom_prompt': False,
            'custom_prompt': ''
        }
        
        # Extract credentials based on active provider
        p = c.active_provider.lower()
        if p == 'openai':
            cfg['api_url'] = c.openai_url
            cfg['api_key'] = c.openai_key
            cfg['model'] = c.openai_model
        elif p == 'deepseek':
            cfg['api_url'] = c.deepseek_url
            cfg['api_key'] = c.deepseek_key
            cfg['model'] = c.deepseek_model
        elif p == 'anthropic':
            cfg['api_url'] = c.anthropic_url
            cfg['api_key'] = c.anthropic_key
            cfg['model'] = c.anthropic_model
        elif p == 'ollama':
            cfg['api_url'] = c.ollama_host
            cfg['api_key'] = 'ollama'
            cfg['model'] = c.ollama_model
        elif p == 'lmstudio':
            cfg['api_url'] = c.lmstudio_url
            cfg['api_key'] = c.lmstudio_key
            cfg['model'] = c.lmstudio_model
        elif p == 'openaicompatible' or p == 'custom':
            cfg['api_url'] = c.custom_url
            cfg['api_key'] = c.custom_key
            cfg['model'] = c.custom_model
        else:
            # Fallback
            cfg['api_url'] = c.openai_url
            cfg['api_key'] = c.openai_key
            cfg['model'] = c.openai_model
            
        return cfg

    def setup_ui(self):
        self.setWindowTitle('PseudoNote: Bulk Function Renamer')
        self.resize(1200, 850)
        self.setStyleSheet(STYLES)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # Toolbar
        tb_widget = QWidget()
        tb = QHBoxLayout(tb_widget)
        tb.setContentsMargins(0, 5, 0, 5)
        
        self.load_btn = QPushButton('Load All sub_*')
        self.load_btn.setObjectName("primary")
        self.load_btn.clicked.connect(lambda: self.load_funcs())
        tb.addWidget(self.load_btn)

        btn_lib = QPushButton('Load unknown_libname_*')
        btn_lib.setObjectName("primary")
        btn_lib.clicked.connect(lambda: self.load_funcs(prefix='unknown_libname_', append=True))
        tb.addWidget(btn_lib)

        btn_fnb = QPushButton('Load fn_b_* (renamed functions)')
        btn_fnb.setObjectName("primary")
        btn_fnb.clicked.connect(lambda: self.load_funcs(prefix='fn_b_', append=True))
        tb.addWidget(btn_fnb)
        
        lb = QPushButton('Load Current')
        lb.clicked.connect(self.load_current)
        tb.addWidget(lb)
        
        rlb = QPushButton('Load Range')
        rlb.clicked.connect(self.load_range)
        tb.addWidget(rlb)
        
        tb.addSpacing(10)
        tb.addWidget(QLabel('|'))
        tb.addSpacing(10)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Filter functions (name or address)...')
        self.filter_edit.setFixedWidth(250)
        self.filter_edit.textChanged.connect(lambda t: self.model.set_filter(t) or self.update_count())
        tb.addWidget(self.filter_edit)
        
        tb.addStretch()

        self.count_lbl = QLabel('0 functions loaded')
        self.count_lbl.setObjectName("accent")
        tb.addWidget(self.count_lbl)
        
        layout.addWidget(tb_widget)

        # Main Data Table
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.doubleClicked.connect(self.jump_to)
        # self.table.clicked.connect(self.on_click) # No longer needed, real checkboxes used
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
    
        # Context Menu for Settings
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context_menu)
    
        # Column sizing
        self.table.setColumnWidth(0, 30)  # Checkbox
        self.table.setColumnWidth(1, 100) # Address
        self.table.setColumnWidth(4, 80) # Status
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.Stretch) # Current
        h.setSectionResizeMode(3, QHeaderView.Stretch) # Suggested
        
        layout.addWidget(self.table)

        # Bottom Area: Log and Actions
        bottom = QVBoxLayout()
        bottom.setSpacing(10)

        # Log Panel (Collapsible feel via small height)
        log_header = QHBoxLayout()
        log_header.addWidget(QLabel("Activity Log"))
        log_header.addStretch()
        
        # Unload button
        ub = QPushButton('Unload Table')
        ub.setToolTip("Clear the current list of functions")
        ub.clicked.connect(lambda: [self.model.clear(), self.update_count()])
        log_header.addWidget(ub)

        cb = QPushButton('Clear Log')
        cb.setFixedWidth(120) # Increased width to avoid text cut-off
        cb.clicked.connect(lambda: self.log.clear())
        log_header.addWidget(cb)
        bottom.addLayout(log_header)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(100)
        self.log.setStyleSheet("font-family: Consolas; font-size: 9pt;")
        bottom.addWidget(self.log)
        
        # Progress Bar overlay logic could be added, but simple one for now
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(12)
        bottom.addWidget(self.progress)
        self.status_lbl = QLabel("")
        bottom.addWidget(self.status_lbl)

        # Action Buttons bar
        actions = QHBoxLayout()
        
        self.analyze_btn = QPushButton('Analyze Selected Functions')
        self.analyze_btn.setObjectName("primary")
        self.analyze_btn.setMinimumHeight(32)
        self.analyze_btn.setMinimumWidth(180)
        self.analyze_btn.clicked.connect(self.start_analyze)
        actions.addWidget(self.analyze_btn)
        
        self.stop_btn = QPushButton('Stop Analysis')
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setMinimumHeight(32)
        self.stop_btn.clicked.connect(self.stop_all)
        self.stop_btn.setEnabled(False)
        actions.addWidget(self.stop_btn)
        
        actions.addStretch()
        
        # Selection Utils
        ab = QPushButton('Select All')
        ab.setFixedWidth(100)
        ab.clicked.connect(lambda: self.model.toggle_all(True))
        actions.addWidget(ab)
        
        nb = QPushButton('Select None')
        nb.setFixedWidth(100)
        nb.clicked.connect(lambda: self.model.toggle_all(False))
        actions.addWidget(nb)
        
        actions.addSpacing(20)
        
        self.apply_btn = QPushButton('Apply Renames')
        self.apply_btn.setObjectName("success")
        self.apply_btn.setMinimumHeight(32)
        self.apply_btn.setMinimumWidth(150)
        self.apply_btn.clicked.connect(self.apply_renames)
        actions.addWidget(self.apply_btn)
        
        bottom.addLayout(actions)
        layout.addLayout(bottom)

    def on_table_context_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet(STYLES)
        act = menu.addAction("⚙️ Configure API Settings...")
        act.triggered.connect(self.open_settings)
        
        menu.addSeparator()
        
        # Add basic selection actions to context menu too
        sel_all = menu.addAction("Select All")
        sel_all.triggered.connect(lambda: self.model.toggle_all(True))
        
        sel_none = menu.addAction("Select None")
        sel_none.triggered.connect(lambda: self.model.toggle_all(False))
        
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def add_log(self, msg, lv='info'):
        colors = {'info':'#CCCCCC','ok':'#4EC9B0','err':'#F44336','warn':'#DCDCAA'}
        self.log.append(f'<span style="color:{colors.get(lv,"#CCCCCC")}">[{time.strftime("%H:%M:%S")}] {msg}</span>')
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def update_count(self):
        v, t = self.model.rowCount(), self.model.total()
        sug = sum(1 for f in self.model.funcs if f.suggested)
        txt = f'{v:,}/{t:,} functions'
        if sug: txt += f' <span style="color:#4EC9B0">({sug} suggestions)</span>'
        self.count_lbl.setText(txt)

    def load_funcs(self, prefix='sub_', append=False):
        self.load_prefix = prefix
        if not append:
            self.model.clear()
            self.temp_funcs = []
            self.seen_eas = set()
        else:
            self.temp_funcs = self.model.funcs[:]
            self.seen_eas = {f.ea for f in self.temp_funcs}

        self.scanned = 0
        self.is_loading = True
        self.progress.setVisible(True)
        self.progress.setRange(0,0)
        self.status_lbl.setText(f'Scanning for {prefix}*...')
        self.load_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.func_iter = iter(idautils.Functions())
        self.load_timer = QTimer(self)
        self.load_timer.timeout.connect(self.load_batch)
        self.load_timer.start(1)

    def load_batch(self):
        if not self.is_loading:
            self.finish_load()
            return

        for _ in range(2000):
            try:
                ea = next(self.func_iter)
                if ea in self.seen_eas: continue
                
                self.scanned += 1
                name = idc.get_func_name(ea)
                if not name or not name.startswith(self.load_prefix): continue
                if not is_valid_seg(ea): continue
                
                self.temp_funcs.append(FuncData(ea, name))
                self.seen_eas.add(ea)
            except StopIteration:
                self.finish_load()
                return

        if self.scanned % 10000 < 2000:
            self.status_lbl.setText(f'Scanning... {self.scanned:,} checked | Found {len(self.temp_funcs):,}')

    def finish_load(self):
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None
        self.model.set_data(self.temp_funcs)
        self.temp_funcs = []
        self.progress.setVisible(False)
        self.update_count()
        self.add_log(f'Loaded {self.model.total():,} functions', 'ok')
        self.status_lbl.setText('')
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def load_current(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            name = idc.get_func_name(f.start_ea)
            fd = FuncData(f.start_ea, name)
            fd.code = get_code_fast(f.start_ea)
            fd.strings = get_strings_fast(f.start_ea)
            fd.calls = get_calls_fast(f.start_ea)
            self.model.set_data([fd])
            self.update_count()
            self.add_log(f'Loaded current: {name}', 'ok')

    def load_range(self):
        start, ok1 = QInputDialog.getText(self, 'Range', 'Start address (hex):')
        if not ok1: return
        end, ok2 = QInputDialog.getText(self, 'Range', 'End address (hex):')
        if not ok2: return
        try:
            start_ea = int(start, 16)
            end_ea = int(end, 16)
        except:
            QMessageBox.warning(self, 'Error', 'Invalid hex address')
            return

        funcs = []
        for ea in idautils.Functions(start_ea, end_ea):
            name = idc.get_func_name(ea)
            if name and name.startswith('sub_'):
                funcs.append(FuncData(ea, name))

        self.model.set_data(funcs)
        self.update_count()
        self.add_log(f'Loaded {len(funcs)} functions in range', 'ok')

    def get_existing(self):
        ex = set()
        for ea in idautils.Functions():
            n = idc.get_func_name(ea)
            if n and not n.startswith('sub_'): ex.add(n)
        for f in self.model.funcs:
            if f.suggested: ex.add(f.suggested)
        return ex

    def get_system_prompt(self, is_batch=False):
        return DEFAULT_BATCH_PROMPT if is_batch else DEFAULT_PROMPT

    def start_analyze(self):
        if not self.model.total():
            QMessageBox.warning(self, 'Warning', 'Load functions first')
            return

        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected')
            return

        count = len(items)
        if count > 500:
            choices = []
            for n in [100, 500, 1000, 2000, 5000, 10000, 50000, count]:
                if n <= count:
                    choices.append(str(n) if n < 10000 else f'{n//1000}K')
            choice, ok = QInputDialog.getItem(self, 'Select Count', f'{count:,} functions selected. Analyze how many?', choices, 0, False)
            if not ok: return
            sel = int(choice.replace('K','000'))
            items = items[:sel]

        for w in self.workers:
            w.stop()
        self.workers = []

        self.existing_names = self.get_existing()
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(items))
        self.progress.setValue(0)

        batch_size = getattr(self.pn_config, 'batch_size', 10)
        num_workers = getattr(self.pn_config, 'parallel_workers', 1)
        sys_prompt = self.get_system_prompt(batch_size > 1)

        chunk_size = max(1, len(items) // num_workers)
        chunks = [items[i:i+chunk_size] for i in range(0, len(items), chunk_size)]

        self.add_log(f'Starting analysis: {len(items):,} functions, {len(chunks)} workers, batch={batch_size}', 'info')
        self.completed = 0
        self.total_items = len(items)

        for chunk in chunks:
            worker = AnalyzeWorker(self.cfg, chunk, self.existing_names, sys_prompt, batch_size)
            worker.batch_done.connect(self.on_batch_done)
            worker.progress.connect(self.on_progress)
            worker.finished.connect(self.on_worker_finished)
            worker.log.connect(self.add_log)
            self.workers.append(worker)
            worker.start()

    def on_batch_done(self, results):
        indices = []
        for idx, func, name in results:
            if name:
                func.suggested = name
                func.status = 'OK'
                self.existing_names.add(name)
            else:
                func.status = 'Skip'
            indices.append(idx)
        self.model.refresh_rows(indices)
        self.update_count()

    def on_progress(self, done, total):
        self.completed += done - getattr(self, '_last_done', 0)
        self._last_done = done
        self.progress.setValue(min(self.completed, self.total_items))
        self.status_lbl.setText(f'Analyzing: {self.completed:,}/{self.total_items:,}')

    def on_worker_finished(self, count):
        sender = self.sender()
        if sender in self.workers:
            self.workers.remove(sender)
        
        if not self.workers:
            self.finish_analyze()

    def finish_analyze(self):
        self.progress.setVisible(False)
        suggestions = sum(1 for f in self.model.funcs if f.suggested)
        self.status_lbl.setText(f'Done: {suggestions:,} suggestions')
        self.add_log(f'Analysis complete: {suggestions:,} suggestions', 'ok')
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.workers = []
        self._last_done = 0

    def stop_all(self):
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None

        for w in self.workers:
            w.stop()

        if self.temp_funcs:
            self.model.set_data(self.temp_funcs)
            self.temp_funcs = []

        self.add_log('Stopped', 'warn')
        self.progress.setVisible(False)
        self.update_count()
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def jump_to(self, idx):
        f = self.model.get_func(idx.row())
        if f: idaapi.jumpto(f.ea)

    def apply_renames(self):
        items = self.model.get_with_suggestions()
        if not items:
            self.add_log('No functions with suggestions to apply', 'warn')
            return

        applied = 0
        indices = []
        for i, f in items:
            if ida_name.set_name(f.ea, f.suggested, ida_name.SN_NOWARN|ida_name.SN_FORCE):
                applied += 1
                f.name = f.suggested
                f.suggested = ''
                f.status = 'Applied'
                f.checked = False
                indices.append(i)

        self.model.refresh_rows(indices)
        self.update_count()
        self.add_log(f'Applied {applied:,} renames', 'ok')
        self.status_lbl.setText(f'Applied {applied:,} renames')
