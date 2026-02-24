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
    QWidget, QTabWidget, QStackedWidget, QSplitter, QSpacerItem
)
Qt = QtCore.Qt

# Modern Light Theme (Premium Clean)
STYLES = """
QWidget {
    background-color: #FDFDFD;
    color: #333333;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10pt;
    outline: none; /* Remove focus dots globally */
}

QDialog {
    background-color: #F5F5F7;
}

QGroupBox {
    border: 1px solid #D1D1D6;
    border-radius: 8px;
    margin-top: 20px;
    background-color: #FFFFFF;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 15px;
    padding: 0 5px;
    color: #007AFF;
    background-color: #FFFFFF;
}

QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #FFFFFF;
    border: 1px solid #D1D1D6;
    border-radius: 4px;
    color: #1C1C1E;
    padding: 6px;
    selection-background-color: #007AFF;
    selection-color: #FFFFFF;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #007AFF;
}
QLineEdit:disabled {
    color: #8E8E93;
    background-color: #F2F2F7;
}

QPushButton {
    background-color: #FFFFFF;
    color: #1C1C1E;
    border: 1px solid #D1D1D6;
    padding: 8px 18px;
    border-radius: 6px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #F2F2F7;
}
QPushButton:pressed {
    background-color: #E5E5EA;
}
QPushButton:focus {
    outline: none; /* Ensure no focus dots on buttons */
}
QPushButton:disabled {
    background-color: #F2F2F7;
    color: #8E8E93;
}

QPushButton#primary {
    background-color: #007AFF;
    color: #FFFFFF;
    border: 1px solid #007AFF;
}
QPushButton#primary:hover {
    background-color: #0062CC;
}
QPushButton#primary:disabled {
    background-color: #E5E5EA;
    color: #8E8E93;
    border: 1px solid #D1D1D6;
}

QPushButton#success {
    background-color: #34C759;
    color: #FFFFFF;
    border: 1px solid #34C759;
}
QPushButton#success:hover {
    background-color: #28a745;
}
QPushButton#success:disabled {
    background-color: #E5E5EA;
    color: #8E8E93;
    border: 1px solid #D1D1D6;
}

QPushButton#danger {
    background-color: #FF3B30;
    color: #FFFFFF;
    border: 1px solid #FF3B30;
}
QPushButton#danger:hover {
    background-color: #c82333;
}
QPushButton#danger:disabled {
    background-color: #E5E5EA;
    color: #8E8E93;
    border: 1px solid #D1D1D6;
}

QPushButton#secondary {
    background-color: #5856D6;
    color: #FFFFFF;
    border: 1px solid #5856D6;
}
QPushButton#secondary:hover {
    background-color: #4845B2;
}
QPushButton#secondary:disabled {
    background-color: #E5E5EA;
    color: #8E8E93;
    border: 1px solid #D1D1D6;
}

QTableView {
    background-color: #FFFFFF;
    border: 1px solid #D1D1D6;
    gridline-color: #F2F2F7;
    selection-background-color: #007AFF;
    selection-color: #FFFFFF;
    alternate-background-color: #F9F9FB;
    border-radius: 4px;
    outline: none;
}
QTableView::item {
    padding: 4px;
}
QHeaderView::section {
    background-color: #F2F2F7;
    color: #3A3A3C;
    padding: 8px;
    border: none;
    border-right: 1px solid #D1D1D6;
    border-bottom: 1px solid #D1D1D6;
    font-weight: bold;
    background: transparent;
}
QHeaderView::section:horizontal {
    border-top: 1px solid #D1D1D6;
}

QProgressBar {
    background-color: #E5E5EA;
    border: none;
    border-radius: 6px;
    color: #000000;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #007AFF;
    border-radius: 6px;
}

QLabel {
    color: #3A3A3C;
    background: transparent;
}
QLabel#h1 {
    color: #1C1C1E;
    font-size: 13pt;
    font-weight: bold;
}
QLabel#accent {
    color: #007AFF;
}
QLabel#status_msg {
    color: #636366;
    font-style: italic;
    font-size: 9pt;
    background: transparent;
}

QCheckBox {
    background: transparent;
}

QComboBox {
    background-color: #FFFFFF;
    border: 1px solid #D1D1D6;
    border-radius: 4px;
    padding: 6px;
    color: #1C1C1E;
}
QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    border: 1px solid #D1D1D6;
    selection-background-color: #007AFF;
    color: #1C1C1E;
}
QScrollBar:vertical {
    border: none;
    background: #FDFDFD;
    width: 12px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #D1D1D6;
    min-height: 30px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover {
    background: #C7C7CC;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

SKIP_SEGS = {'.plt','.plt.got','.plt.sec','extern','.extern','.got','.got.plt','.init','.fini','.dynsym','.dynstr','.interp','.rela.dyn','.rela.plt','.hash','.gnu.hash','.note','.note.gnu.build-id','.note.ABI-tag'}
SYS_PREFIX = ('__cxa_','__gxx_','__gnu_','__libc_','__ctype_','_GLOBAL_','_init','_fini','_start','atexit','malloc','free','memcpy','memset','strlen','printf','scanf','fprintf','sprintf','operator','std::','boost::','__stack_chk','__security','_security','__report','__except','__imp_','__x86.','__do_global')
SYS_MODULES = ('kernel32.','ntdll.','user32.','advapi32.','msvcrt.','ucrtbase.','ws2_32.','libc.so','libm.so','libpthread','foundation.','corefoundation.','uikit.')

DEFAULT_PROMPT = """Expert reverse engineer. Name this function in snake_case.

THUNK RULE (overrides all): Single return/jmp to unnamed/opaque target →
name it thunk_<offset> or wrap_<offset>, confidence ≤20%. No semantic names.

SUB RULE: sub_XXXXX calls are unnamed black boxes — zero semantic information.
Do NOT infer purpose from sub_* patterns, argument count, or call order alone.
If body contains ONLY sub_* calls with no strings/known APIs/constants → confidence ≤30%,
use a conservative name (e.g. wrap_<offset>).

Otherwise: name reflects WHAT code does, based on evidence only.
Evidence = named API calls, strings, constants, recognizable patterns.
Prefixes only if evidence supports: init_ parse_ validate_ process_ handle_ get_ set_ create_ destroy_ check_
Length: 3-40 chars. No generic filler (func1, do_something).
Confidence: no evidence=≤30%, weak=31-60%, strong=61-95%.

Output: suggested_name [score]
Example: decrypt_payload [95]"""

DEFAULT_BATCH_PROMPT = """Expert reverse engineer. Name each function in snake_case.

THUNK RULE (overrides all): Single return/jmp to unnamed/opaque target →
thunk_<offset> or wrap_<offset>, confidence ≤20%. No semantic names.

SUB RULE: sub_XXXXX calls are unnamed black boxes — zero semantic information.
Do NOT infer purpose from sub_* patterns, argument count, or call order alone.
Body contains ONLY sub_* calls with no strings/known APIs/constants → confidence ≤30%,
use conservative name (e.g. wrap_<offset>).

Otherwise: name what code clearly does, evidence only.
Evidence = named API calls, strings, constants, recognizable patterns.
Prefixes only if evidence supports: init_ parse_ validate_ process_ handle_ get_ set_ create_ destroy_ check_
Length: 3-40 chars. No generic filler.
Confidence: no evidence=≤30%, weak=31-60%, strong=61-95%.

Output one per line:
1. name [score]
2. name [score]"""

def is_valid_seg(ea):
    seg = idaapi.getseg(ea)
    if not seg: return False
    name = idaapi.get_segm_name(seg)
    if not name: return True # If it's a function but the segment has no name, allow it
    
    # Only skip segments that are clearly NOT user code (Imports/Stubs)
    nl = name.lower()
    if any(x in nl for x in ('.plt', 'extern', '.got', '.note', '.init', '.fini', '.interp', '.hash')):
        return False

    return True

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

def get_code_fast(ea, max_len=5000, asm_max=25):
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
        while cur < f.end_ea and len(lines) < asm_max:
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

def clean_name(name, existing=None, ea=None):
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
    if getattr(CONFIG, 'use_bulk_prefix', True):
        prefix = getattr(CONFIG, 'rename_prefix', 'bulkren_')
        if not name.startswith(prefix):
            name = f"{prefix}{name}"

    if ea is not None and getattr(CONFIG, 'bulk_append_address', False):
        use_0x = getattr(CONFIG, 'bulk_use_0x', False)
        addr_str = f"{ea:X}"
        if use_0x:
            name = f"{name}_0x{addr_str}"
        else:
            name = f"{name}_{addr_str}"

    if existing:
        orig, cnt = name, 1
        while name in existing:
            name = f"{orig}_{cnt}"
            cnt += 1
            if cnt > 99: return None
    return name

class FuncData:
    __slots__ = ['ea','name','demangled','suggested','score','status','checked','code','strings','calls']
    def __init__(self, ea, name):
        self.ea, self.name, self.suggested, self.score, self.status, self.checked = ea, name, '', '', 'Pending', True
        self.demangled = None
        if name.startswith('??') or name.startswith('_Z'):
            self.demangled = ida_name.demangle_name(name, 0)
        self.code = self.strings = self.calls = None

class ResultSignal(QThread):
    result = Signal(list)
    def __init__(self): super().__init__()

class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['', 'Address', 'Current Name', 'AI Suggestion', 'Score', 'Status']
    
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
            res = []
            for i, f in enumerate(self.funcs):
                if ft in f.name.lower() or ft in f'{f.ea:x}':
                    res.append(i)
                elif f.demangled and ft in f.demangled.lower():
                    res.append(i)
                elif f.suggested and ft in f.suggested.lower():
                    res.append(i)
            self.filtered = res

    def set_filter(self, t):
        self.beginResetModel()
        self.filter_text = t
        self._apply_filter()
        self.endResetModel()

    def rowCount(self, p=QModelIndex()): return len(self.filtered)
    def columnCount(self, p=QModelIndex()): return 6
    def headerData(self, s, o, r=Qt.DisplayRole): return self.HEADERS[s] if r==Qt.DisplayRole and o==Qt.Horizontal else None

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self.filtered): return None
        f = self.funcs[self.filtered[idx.row()]]
        c = idx.column()
        
        if role == Qt.DisplayRole:
            # Column 0 is checkbox now, handled by CheckStateRole
            if c==1: return f'{f.ea:X}'
            elif c==2:
                return self.funcs[self.filtered[idx.row()]].demangled or f.name
            elif c==3: return f.suggested
            elif c==4: return f.score
            elif c==5: return f.status
            
        elif role == Qt.CheckStateRole and c==0:
            return Qt.Checked if f.checked else Qt.Unchecked
            
        elif role == Qt.TextAlignmentRole:
            if c==0: return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ForegroundRole:
            if c == 4 and f.score: # Confidence score colors
                try:
                    s = int(f.score.replace('%', ''))
                    if s >= 80: return QColor('#34C759') # High (Green)
                    if s >= 50: return QColor('#FF9500') # Medium (Orange)
                    return QColor('#FF3B30') # Low (Red)
                except: pass
            
            if c == 5: # Status colors
                if f.status == 'OK': return QColor('#34C759')
                if f.status == 'Skip': return QColor('#8E8E93')
                if f.status == 'Applied': return QColor('#007AFF')
                if f.status == 'Pending': return QColor('#FF9500')
            
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

    def select_good_scores(self, threshold=80):
        count = 0
        for i in self.filtered:
            f = self.funcs[i]
            score_val = 0
            if f.score:
                try:
                    score_val = int(f.score.replace('%', ''))
                except: pass
            f.checked = (score_val >= threshold)
            if f.checked: count += 1
        if self.filtered:
            self.dataChanged.emit(self.index(0,0), self.index(len(self.filtered)-1,0))
        return count

    def total(self): return len(self.funcs)

class AnalyzeWorker(QThread):
    batch_done = Signal(list)
    progress = Signal(int, int)
    finished = Signal(int)
    log = Signal(str, str)
    update_status = Signal(str)

    def __init__(self, cfg, items, existing, sys_prompt, batch_size):
        super().__init__()
        self.cfg = cfg
        self.items = items
        self.existing = set(existing)
        self.sys_prompt = sys_prompt
        self.batch_size = batch_size
        self.cooldown_seconds = cfg.get('cooldown_seconds', 22)
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
            for idx, func, name, score in results:
                if name:
                    self.existing.add(name)
            self.batch_done.emit(results)
            done += len(batch)
            self.progress.emit(done, total)
            
            if self.needs_cooldown:
                self.log.emit('Rate limit reached. Cooling down...', 'info')
                for s in range(self.cooldown_seconds, 0, -1):
                    if not self.running: break
                    self.update_status.emit(f'Cooling down ({s}s)')
                    time.sleep(1)
                self.needs_cooldown = False
                self.update_status.emit('')

        self.finished.emit(done)

    def process_batch(self, batch):
        results = []
        valid = []

        for idx, func in batch:
            if not func.code:
                # self.log.emit(f"Getting code for {hex(func.ea)}...", 'info')
                asm_max = self.cfg.get('asm_max_lines', 25)
                # Gather more code (up to 5000) so we can handle long functions properly in single mode
                func.code = get_code_fast(func.ea, 5000, asm_max=asm_max)
                func.strings = get_strings_fast(func.ea)
                func.calls = get_calls_fast(func.ea)
            
            if func.code:
                line_count = func.code.count('\n')
                # Dynamic limit: we aim for a total batch volume of ~800 lines to ensure AI accuracy and avoid truncation.
                # Smaller batches allow for longer individual functions.
                dynamic_line_limit = max(100, 800 // len(batch))
                dynamic_char_limit = max(4000, 15000 // len(batch))
                
                force = self.cfg.get('force_bulk_rename', False)
                if not force and len(batch) > 1 and (len(func.code) > dynamic_char_limit or line_count > dynamic_line_limit):
                    self.log.emit(f"Skipping {hex(func.ea)} ({line_count} lines): Volume too high for a batch of {len(batch)}. "
                                  "Suggested: Decrease 'Batch Size' to 1 in Settings for large functions.", 'warn')
                    results.append((idx, func, None, ''))
                    continue
                valid.append((idx, func))
            else:
                self.log.emit(f"Skipping {hex(func.ea)}: No code found", 'warn')
                results.append((idx, func, None, ''))

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
                
                name_part, score_part = '', ''
                if resp:
                    # Parse single response for [score]
                    name_part = resp
                    s_match = re.search(r'\[(\d+)%?\]', resp)
                    if s_match:
                        score_part = f"{s_match.group(1)}%"
                        name_part = resp.replace(s_match.group(0), "").strip()
                
                name = clean_name(name_part, self.existing, ea=f.ea) if name_part else None
                results.append((idx, f, name, score_part))
            else:
                self.log.emit(f"Processing batch of {len(valid)} functions...", 'info')
                prompt = "Functions to name:\n\n"
                for i, (idx, f) in enumerate(valid):
                    # In a batch (>1), truncate to 800 to avoid token limits, add marker
                    snippet = f.code
                    if len(snippet) > 800:
                        snippet = snippet[:800] + "\n// ... (truncated) ..."
                    
                    prompt += f"[{i+1}]\n```\n{snippet}\n```\n"
                    if f.strings: prompt += f"Strings: {f.strings[:3]}\n"
                    if f.calls: prompt += f"Calls: {f.calls[:3]}\n"
                    prompt += "\n"

                resp = ai_request(self.cfg, prompt, self.sys_prompt, logger=logger)
                names, scores, actual_count = self.parse_batch_response(resp, len(valid))
                self.log.emit(f"API returned {actual_count} names for batch of {len(valid)}", 'info')

                for i, (idx, f) in enumerate(valid):
                    suggestion = names[i] if i < len(names) else None
                    score = scores[i] if i < len(scores) else ''
                    name = clean_name(suggestion, self.existing, ea=f.ea) if suggestion else None
                    
                    if name:
                        self.existing.add(name)
                    elif suggestion:
                        self.log.emit(f"Suggestion '{suggestion}' for {hex(f.ea)} rejected by clean_name", 'warn')
                    else:
                        self.log.emit(f"No suggestion found for {hex(f.ea)} (index {i+1} in batch)", 'warn')
                        
                    results.append((idx, f, name, score))

        except Exception as e:
            self.log.emit(f'Batch Error: {str(e)[:100]}', 'err')
            import traceback
            print(f"[PseudoNote] Batch error traceback:")
            traceback.print_exc()
            for idx, f in valid:
                results.append((idx, f, None, ''))

        return results

    def parse_batch_response(self, resp, expected):
        if not resp or not resp.strip():
            self.log.emit("Warning: AI returned empty response!", 'warn')
            return [None] * expected, [''] * expected, 0

        names, scores = [], []
        
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
            
            # Split line to find [score]
            score_match = re.search(r'\[(\d+)%?\]', line)
            score_val = f"{score_match.group(1)}%" if score_match else ""
            
            # Extract the first token that looks like an identifier
            parts = re.split(r'[\s,\:\(\)\|\[\]]+', clean)
            if not parts: continue
            nm = parts[0].strip(' "\'`*')
            nm = re.sub(r'[^a-zA-Z0-9_]', '', nm)
            
            if nm and len(nm) >= 3 and nm.lower() not in ('function','func','sub','unknown','unnamed','noname','the','this','and','for','with'):
                names.append(nm)
                scores.append(score_val)

        # Fallback: regex scan for identifiers in the whole response
        if len(names) < expected:
            # Regex for common function naming patterns (snake_case, camelCase)
            found = re.findall(r'\b([a-zA-Z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)*)\b', resp)
            for n in found:
                if len(n) >= 3 and n.lower() not in ('void', 'int', 'char', 'return', 'include', 'func', 'function', 'const', 'unsigned', 'static'):
                    if n not in names:
                        if len(names) < expected:
                            names.append(n)
                            scores.append('')
                        else:
                            break

        if len(names) < expected:
            self.log.emit(f"Parser found {len(names)}/{expected} names. Check IDA Output for raw text.", 'warn')
            print(f"[PseudoNote] Raw API Response:\n{resp}\n{'-'*40}")

        actual_count = min(len(names), expected)
        
        # Ensure we return exactly 'expected' items
        final_names = (names + [None] * expected)[:expected]
        final_scores = (scores + [''] * expected)[:expected]
            
        return final_names, final_scores, actual_count


class BulkRenamer(QDialog):
    def __init__(self, pn_config, parent=None):
        super().__init__(parent)
        self.pn_config = CONFIG
        self.workers = []
        self.is_loading = False
        self.load_mode = 'prefix' # prefix or search
        self.load_timer = None
        self.func_iter = None
        self.temp_funcs = []
        self.scanned = 0
        self.workers = []
        self.existing_names = set()
        self.setup_ui()
        self.loader = None
        self.worker = None

        # Animated status indicator
        self.busy_dots = 0
        self.busy_timer = QTimer(self)
        self.busy_timer.timeout.connect(self.on_busy_tick)

    def open_settings(self):
        from pseudonote.view import SettingsDialog
        # Hide extra tabs (Appearance, Rename, Logs) in Bulk Renamer settings
        d = SettingsDialog(self.pn_config, self, hide_extra_tabs=True)
        if d.exec_():
            # Refresh local config from updated pn_config
            self.cfg = self.build_cfg(self.pn_config)
            

            
            self.add_log(f"Settings updated. Provider: {self.cfg['provider']}, Model: {self.cfg['model']}")

    def build_cfg(self, c):
        # Convert PseudoNote config to local format expected by workers
        cfg = {
            'provider': c.active_provider,
            'batch_size': getattr(c, 'batch_size', 10),
            'parallel_workers': getattr(c, 'parallel_workers', 1),
            'rename_prefix': getattr(c, 'rename_prefix', 'bulkren_'),
            'cooldown_seconds': getattr(c, 'cooldown_seconds', 22),
            'asm_max_lines': getattr(c, 'asm_max_lines', 25),
            'force_bulk_rename': getattr(c, 'force_bulk_rename', False),
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

        # Toolbar Container
        tb_container = QVBoxLayout()
        tb_container.setSpacing(8)
        
        # Row 1: Preset Loaders & Settings
        tb_row1_widget = QWidget()
        tb_row1_widget.setObjectName("tb_row1_container")
        tb_row1_widget.setStyleSheet("QWidget#tb_row1_container { background: transparent; }")
        tb_row1 = QHBoxLayout(tb_row1_widget)
        tb_row1.setContentsMargins(0, 0, 0, 0)
        tb_row1.setSpacing(8)
        
        self.load_btn = QPushButton('Load sub_*')
        self.load_btn.setObjectName("primary")
        self.load_btn.clicked.connect(lambda: self.load_funcs(prefix='sub_'))
        tb_row1.addWidget(self.load_btn)

        btn_lib = QPushButton('Load unknown_libname_*')
        btn_lib.setObjectName("primary")
        btn_lib.clicked.connect(lambda: self.load_funcs(prefix='unknown_libname_', append=True))
        tb_row1.addWidget(btn_lib)

        btn_all = QPushButton('Load all functions')
        btn_all.setObjectName("primary")
        btn_all.clicked.connect(lambda: self.load_funcs(prefix=None, append=True, mode='all'))
        tb_row1.addWidget(btn_all)

        btn_renamed = QPushButton('Load renamed functions')
        btn_renamed.setToolTip("Load every function previously renamed by PseudoNote")
        btn_renamed.setObjectName("primary")
        btn_renamed.clicked.connect(lambda: self.load_funcs(prefix=None, append=True, mode='metadata'))
        tb_row1.addWidget(btn_renamed)
        
        tb_row1.addStretch()

        settings_btn = QPushButton("Settings")
        settings_btn.setToolTip("Open PseudoNote Settings")
        settings_btn.setObjectName("secondary")
        settings_btn.setFixedWidth(110)
        settings_btn.clicked.connect(self.open_settings)
        tb_row1.addWidget(settings_btn)

        tb_container.addWidget(tb_row1_widget)

        # Row 2: Search & Filter Tools
        tb_row2_widget = QWidget()
        tb_row2_widget.setObjectName("tb_row2_container")
        tb_row2_widget.setStyleSheet("QWidget#tb_row2_container { background: transparent; }")
        tb_row2 = QHBoxLayout(tb_row2_widget)
        tb_row2.setContentsMargins(0, 5, 0, 5)
        tb_row2.setSpacing(10)
        
        # Search Binary Section
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search Functions:"))
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("Function name or address...")
        self.find_edit.setFixedWidth(350)
        self.find_edit.returnPressed.connect(self.on_find_edit_return)
        search_layout.addWidget(self.find_edit)
        
        self.find_btn = QPushButton("Load")
        self.find_btn.setAutoDefault(False)
        self.find_btn.setObjectName("primary")
        self.find_btn.setFixedWidth(100)
        self.find_btn.clicked.connect(lambda: self.load_funcs(prefix=self.find_edit.text(), append=True, mode='search'))
        search_layout.addWidget(self.find_btn)
        tb_row2.addLayout(search_layout)

        # Visual Separator
        sep = QLabel("|")
        sep.setStyleSheet("color: #D1D1D6; margin: 0 10px; font-weight: bold;")
        tb_row2.addWidget(sep)

        # Filter Section
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter Table:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Search in current list...')
        self.filter_edit.setFixedWidth(400)
        self.filter_edit.textChanged.connect(lambda t: self.model.set_filter(t) or self.update_count())
        filter_layout.addWidget(self.filter_edit)
        tb_row2.addLayout(filter_layout)

        tb_row2.addStretch()
        
        tb_container.addWidget(tb_row2_widget)
        
        layout.addLayout(tb_container)

        # Main Data Table
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        # self.table.doubleClicked.connect(self.jump_to) # Disabled as requested
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
        self.table.setColumnWidth(4, 70)  # Score
        self.table.setColumnWidth(5, 80)  # Status
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.Stretch) # Current
        h.setSectionResizeMode(3, QHeaderView.Stretch) # Suggested
        
        layout.addWidget(self.table)

        # Bottom Area: Log and Actions
        bottom = QVBoxLayout()
        bottom.setSpacing(10)

        # Log Panel (Collapsible feel via small height)
        log_header = QHBoxLayout()
        log_lbl = QLabel("Activity Log")
        log_lbl.setStyleSheet("background: transparent; color: #666666; font-weight: 600; font-size: 10pt;")
        log_header.addWidget(log_lbl)
        log_header.addStretch()
        
        # Selection Utils moved to header
        self.sel_good_btn = QPushButton('Select Good Score')
        self.sel_good_btn.setToolTip("Select all functions with a confidence score of 80% or higher")
        self.sel_good_btn.setFixedWidth(150)
        self.sel_good_btn.setEnabled(False)
        self.sel_good_btn.clicked.connect(self.on_select_good)
        log_header.addWidget(self.sel_good_btn)

        ab = QPushButton('Select All')
        ab.setFixedWidth(150)
        ab.clicked.connect(lambda: self.model.toggle_all(True))
        log_header.addWidget(ab)
        
        nb = QPushButton('Select None')
        nb.setFixedWidth(130)
        nb.clicked.connect(lambda: self.model.toggle_all(False))
        log_header.addWidget(nb)

        # Unload button
        ub = QPushButton('Unload Table')
        ub.setToolTip("Clear the current list of functions")
        ub.clicked.connect(lambda: [self.model.clear(), setattr(self, 'load_mode', 'prefix'), self.update_count()])
        log_header.addWidget(ub)

        cb = QPushButton('Clear Log')
        cb.setFixedWidth(120) 
        cb.clicked.connect(lambda: self.log.clear())
        log_header.addWidget(cb)
        bottom.addLayout(log_header)

        # Merged Log and Progress area
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(130) # Slightly taller since it now holds status
        self.log.setStyleSheet("""
            QTextEdit {
                font-family: 'Segoe UI', Consolas; 
                font-size: 9pt; 
                background-color: transparent; 
                border: 1px solid #E0E0E0; 
                border-radius: 6px;
                color: #333333;
            }
        """)
        bottom.addWidget(self.log)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(16) # Slightly taller for text
        self.progress.setTextVisible(True)
        self.progress.setAlignment(Qt.AlignCenter)
        bottom.addWidget(self.progress)

        # Action Buttons bar
        actions = QHBoxLayout()
        
        self.analyze_btn = QPushButton('Analyze Selected Function')
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
        
        self.apply_btn = QPushButton('Apply Renames')
        self.apply_btn.setAutoDefault(False)
        self.apply_btn.setObjectName("success")
        self.apply_btn.setMinimumHeight(32)
        self.apply_btn.setMinimumWidth(150)
        self.apply_btn.setEnabled(False) # Grey out until suggestions exist
        self.apply_btn.clicked.connect(self.apply_renames)
        actions.addWidget(self.apply_btn)

        self.undo_btn = QPushButton('Undo Renames')
        self.undo_btn.setToolTip("Revert selected functions to their names before PseudoNote renaming")
        self.undo_btn.setObjectName("danger")
        self.undo_btn.setMinimumHeight(32)
        self.undo_btn.setMinimumWidth(150)
        self.undo_btn.setEnabled(False) # Grey out until metadata mode
        self.undo_btn.clicked.connect(self.undo_renames)
        actions.addWidget(self.undo_btn)
        bottom.addLayout(actions)
        layout.addLayout(bottom)

        # Initial hint
        self.add_log("*Adjust Batch/Workers in Settings for speed.", "err")

    def on_table_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        menu = QMenu(self)
        menu.setStyleSheet(STYLES)
        
        if idx.isValid():
            jump_act = menu.addAction("🔍 Open function in view")
            jump_act.triggered.connect(lambda: self.jump_to(idx))
            menu.addSeparator()

        act = menu.addAction("⚙️ Configure Settings...")
        act.triggered.connect(self.open_settings)
        
        menu.addSeparator()
        
        # Add basic selection actions to context menu too
        sel_all = menu.addAction("Select All")
        sel_all.triggered.connect(lambda: self.model.toggle_all(True))
        
        sel_none = menu.addAction("Select None")
        sel_none.triggered.connect(lambda: self.model.toggle_all(False))
        
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def add_log(self, msg, lv='info'):
        colors = {'info':'#3A3A3C','ok':'#34C759','err':'#FF3B30','warn':'#FF9500'}
        self.log.append(f'<span style="color:{colors.get(lv,"#3A3A3C")}">[{time.strftime("%H:%M:%S")}] {msg}</span>')
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_busy_tick(self):
        self.busy_dots = (self.busy_dots + 1) % 4
        if self.progress.isVisible():
            fmt = self.progress.format().rstrip('.')
            self.progress.setFormat(fmt + ('.' * self.busy_dots))

    def update_status(self, text):
        if not text:
            self.busy_timer.stop()
            return
            
        # If it's a progress update, show it on the progress bar if visible
        if self.progress.isVisible() and any(x in text for x in ["Scanning", "Analyzing", "Cooling down"]):
            self.progress.setFormat(f"{text}  %p%")
        else:
            # Log significant status changes to the activity log, but skip per-second updates
            if not any(text.startswith(x) for x in ["Scanning", "Analyzing", "Cooling down"]):
                self.add_log(text, 'info')
        
        if "Analyzing" in text or "Cooling down" in text:
            if not self.busy_timer.isActive():
                self.busy_dots = 0
                self.busy_timer.start(500)
        else:
            self.busy_timer.stop()

    def update_count(self):
        v, t = self.model.rowCount(), self.model.total()
        sug = sum(1 for f in self.model.funcs if f.suggested)
        
        # Update Apply button: only enable if we have suggestions AND not busy
        if not self.workers and not self.is_loading:
            self.apply_btn.setEnabled(sug > 0)
            
        # Update Undo button: only enabled in metadata mode with data
        self.undo_btn.setEnabled(getattr(self, 'load_mode', '') == 'metadata' and t > 0 and not self.is_loading)

    def load_funcs(self, prefix='sub_', append=False, mode='prefix'):
        self.load_prefix = prefix
        self.load_mode = mode
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
        
        status_msg = f'Scanning for {prefix}*...'
        if mode == 'metadata':
            status_msg = 'Scanning for all renamed functions...'
        elif mode == 'search':
            status_msg = f'Searching for "{prefix}"...'
        elif mode == 'all':
            status_msg = 'Scanning for all functions...'
            
        self.update_status(status_msg)
        
        # UI State: Loading is considered a busy/analysing state for these buttons
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
                if not name: continue
                
                # Matching Logic
                is_match = False
                if self.load_mode == 'metadata':
                    from pseudonote.idb_storage import load_from_idb
                    marker = load_from_idb(ea, tag=83)
                    # Only match if marked AND currently doesn't start with sub_
                    is_match = (marker == "renamed_by_pseudonote" and not name.startswith("sub_"))
                elif self.load_mode == 'all':
                    is_match = True
                else:
                    if self.load_prefix:
                        lp = self.load_prefix.lower()
                        if self.load_mode == 'search':
                            # Match by name substring
                            is_match = lp in name.lower()
                            # Match by demangled name if available
                            if not is_match:
                                demangled = ida_name.demangle_name(name, 0)
                                if demangled and lp in demangled.lower():
                                    is_match = True
                            # Match by address (hex)
                            if not is_match:
                                eas_str = f'{ea:x}'
                                if lp.startswith('0x'):
                                    is_match = lp[2:] == eas_str
                                else:
                                    is_match = lp == eas_str
                        else:
                            is_match = name.startswith(self.load_prefix)
                
                if not is_match: continue
                if not is_valid_seg(ea): continue
                
                self.temp_funcs.append(FuncData(ea, name))
                self.seen_eas.add(ea)
            except StopIteration:
                self.finish_load()
                return

        if self.scanned % 10000 < 2000:
            self.update_status(f'Scanning... {self.scanned:,} checked | Found {len(self.temp_funcs):,}')

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
        self.update_status('')
        
        # UI State: Not busy anymore
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)




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

        # Ensure we use up-to-date settings from CONFIG
        self.cfg = self.build_cfg(CONFIG)
        
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
        
        # UI State: Analysing
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.sel_good_btn.setEnabled(False)
        self.apply_btn.setEnabled(False) # Also grey out apply while analysing
        
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
            worker.update_status.connect(self.update_status)
            self.workers.append(worker)
            worker.start()

    def on_batch_done(self, results):
        indices = []
        for res in results:
            if not res or len(res) < 4: continue
            idx, func, name, score = res
            if name:
                func.suggested = name
                func.score = score
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
        self.update_status(f'Analyzing: {self.completed:,}/{self.total_items:,}')

    def on_worker_finished(self, count):
        sender = self.sender()
        if sender in self.workers:
            self.workers.remove(sender)
        
        if not self.workers:
            self.finish_analyze()

    def finish_analyze(self):
        self.progress.setVisible(False)
        suggestions = sum(1 for f in self.model.funcs if f.suggested)
        self.update_status(f'Done: {suggestions:,} suggestions')
        self.add_log(f'Analysis complete: {suggestions:,} suggestions', 'ok')
        
        # UI State: Finished analysing
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.apply_btn.setEnabled(suggestions > 0)
        
        self.workers = []
        self._last_done = 0
        self.sel_good_btn.setEnabled(suggestions > 0)

    def on_select_good(self):
        count = self.model.select_good_scores(80)
        self.add_log(f"Selected {count:,} high-confidence suggestions (>= 80%)", 'info')
        self.update_count()

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
        
        # UI State: Stopped/Not busy
        self.load_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        suggestions = sum(1 for f in self.model.funcs if f.suggested)
        self.apply_btn.setEnabled(suggestions > 0)
        self.sel_good_btn.setEnabled(suggestions > 0)

    def jump_to(self, idx):
        f = self.model.get_func(idx.row())
        if f: idaapi.jumpto(f.ea)

    def on_find_edit_return(self):
        # Prevent focus loss or propagation that might cause IDA to jump
        # By explicitly handling this and keeping focus, we avoid triggering global shortcuts
        txt = self.find_edit.text().strip()
        if txt:
            self.load_funcs(prefix=txt, append=True, mode='search')
        # Consume the focus so Enter doesn't hit a default button
        self.find_edit.setFocus()

    def apply_renames(self):
        items = self.model.get_with_suggestions()
        if not items:
            self.add_log('No functions with suggestions to apply', 'warn')
            return

        applied = 0
        indices = []
        from pseudonote.idb_storage import save_to_idb, load_from_idb
        for i, f in items:
            # Store original name if not already stored (to allow Undo back to very first state)
            orig = load_from_idb(f.ea, tag=82)
            if not orig:
                cur_name = idc.get_func_name(f.ea)
                if cur_name and not cur_name.startswith('sub_'):
                    save_to_idb(f.ea, cur_name, tag=82)

            if ida_name.set_name(f.ea, f.suggested, ida_name.SN_NOWARN|ida_name.SN_FORCE):
                applied += 1
                f.name = f.suggested
                f.suggested = ''
                f.status = 'Applied'
                f.checked = False
                
                # Save metadata marker (tag 81) to track this function as "renamed by us"
                save_to_idb(f.ea, "renamed_by_pseudonote", tag=83)
                
                indices.append(i)

        self.model.refresh_rows(indices)
        self.update_count()
        self.add_log(f'Applied {applied:,} renames', 'ok')
        self.update_status(f'Applied {applied:,} renames')

    def undo_renames(self):
        items = self.model.get_checked()
        if not items:
            self.add_log('No functions selected to undo', 'warn')
            return
            
        res = QMessageBox.question(self, "Undo Renames", 
                                f"Are you sure you want to revert {len(items):,} functions to their original names?",
                                QMessageBox.Yes | QMessageBox.No)
        
        # Handle both int and Enum result (PySide6 compatibility)
        val = res.value if hasattr(res, 'value') else res
        yes_val = QMessageBox.Yes.value if hasattr(QMessageBox.Yes, 'value') else QMessageBox.Yes
        if val != yes_val: return

        reverted = 0
        indices = []
        from pseudonote.idb_storage import load_from_idb, save_to_idb
        for i, f in items:
            # Try to get stored original name (tag 82)
            orig_name = load_from_idb(f.ea, tag=82)
            
            # If no original name, setting to "" reverts to IDA default sub_XXXX
            target = orig_name if orig_name else ""
            
            # Flags: SN_NOWARN (0x01) | SN_FORCE (0x0800)
            # When target is "", some flags might cause failure.
            success = False
            if target == "":
                # Reverting to default sub_XXXX
                success = ida_name.set_name(f.ea, "", ida_name.SN_NOWARN)
            else:
                # Reverting to a specific original name
                success = ida_name.set_name(f.ea, target, ida_name.SN_NOWARN | ida_name.SN_FORCE)

            if success:
                reverted += 1
                f.name = idc.get_func_name(f.ea)
                f.suggested = ''
                f.status = 'Undone'
                f.checked = False
                
                # Clear markers so they don't appear in "Load renamed" and are forgotten
                save_to_idb(f.ea, "", tag=83)
                save_to_idb(f.ea, "", tag=82)
                
                indices.append(i)
            else:
                # Check if it's already the default name or already the target name
                cur = idc.get_func_name(f.ea)
                if (target == "" and cur.startswith("sub_")) or (target != "" and cur == target):
                    reverted += 1
                    f.status = 'Undone'
                    save_to_idb(f.ea, "", tag=83)
                    save_to_idb(f.ea, "", tag=82)
                    indices.append(i)
                else:
                    self.add_log(f"Failed to revert {f.ea:X} to '{target}' (Currently: '{cur}')", "warn")

        self.model.refresh_rows(indices)
        self.update_count()
        self.add_log(f'Reverted {reverted:,} functions', 'ok')
        self.update_status(f'Reverted {reverted:,} functions')
