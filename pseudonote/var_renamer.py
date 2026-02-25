# -*- coding: utf-8 -*-
import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment
import json, os, re, time, csv
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

from pseudonote.renamer import (
    STYLES, is_valid_seg, is_sys_func, get_code_fast,
    get_calls_fast, ai_request
)
import pseudonote.ai_client as _ai_mod
from pseudonote.idb_storage import save_to_idb, load_from_idb

Qt = QtCore.Qt

# IDB storage tag for var_renamer (tag=90 reserved for analyzer)
_IDB_TAG = 91


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def count_sub_calls(code, own_name=None):
    """Count the number of sub_XXXXXX references in the given pseudocode."""
    if not code:
        return 0
    matches = re.findall(r'\bsub_[0-9A-Fa-f]+\b', code)
    if own_name and own_name.startswith('sub_'):
        matches = [m for m in matches if m != own_name]
    return len(matches)


def apply_var_renames(ea, suggestions, log_fn=None):
    """Apply variable renames using ida_hexrays. Returns (applied, failed) counts.

    IMPORTANT: rename_lvar must NOT be called inside execute_sync(MFF_WRITE).
    MFF_WRITE acquires an IDB write lock that conflicts with HexRays internal
    locking, causing rename_lvar to consistently return False. handlers.py
    calls rename_lvar directly from a background thread (no execute_sync) and
    it works — we match that pattern exactly.
    """
    if not suggestions:
        return 0, 0

    applied = 0
    failed = 0

    # Get canonical function start_ea (same as handlers.py)
    func_obj = idaapi.get_func(ea)
    if not func_obj:
        if log_fn:
            log_fn(f"  [{hex(ea)}] get_func() returned None — skipping", 'err')
        return 0, len(suggestions)
    func_ea = func_obj.start_ea

    # Decompile first to populate the HexRays cfunc cache.
    # rename_lvar needs a cached cfunc — decompile() ensures it exists.
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as ex:
        if log_fn:
            log_fn(f"  [{hex(ea)}] decompile() raised: {ex}", 'err')
        return 0, len(suggestions)

    if log_fn:
        if cfunc:
            lvar_names = sorted(l.name for l in cfunc.get_lvars())[:30]
            log_fn(f"  [{hex(ea)}] lvar names present: {lvar_names}", 'info')
        log_fn(f"  [{hex(ea)}] AI suggestions keys: {sorted(suggestions.keys())[:30]}", 'info')

    # C reserved words IDA will reject as variable names
    C_KEYWORDS = {
        'auto','break','case','char','const','continue','default','do',
        'double','else','enum','extern','float','for','goto','if','inline',
        'int','long','register','restrict','return','short','signed',
        'sizeof','static','struct','switch','typedef','union','unsigned',
        'void','volatile','while','_Bool','_Complex','_Imaginary',
    }

    for old_name, new_name in suggestions.items():
        # Sanitize to a valid C identifier
        new_name = re.sub(r'[^A-Za-z0-9_]', '_', new_name)
        if not new_name or new_name[0].isdigit():
            new_name = '_' + new_name
        new_name = new_name[:60]

        if new_name in C_KEYWORDS:
            if log_fn:
                log_fn(f"  [{hex(ea)}] '{new_name}' is a C keyword — skipping '{old_name}'", 'warn')
            failed += 1
            continue

        ok = False

        # --- Primary: rename_lvar called DIRECTLY (no execute_sync) ---
        # Matches handlers.py exactly. execute_sync(MFF_WRITE) conflicts with
        # HexRays locking and causes rename_lvar to return False consistently.
        try:
            ok = bool(ida_hexrays.rename_lvar(func_ea, old_name, new_name))
            if ok and log_fn:
                log_fn(f"  [{hex(ea)}] OK (lvar): '{old_name}' -> '{new_name}'", 'info')
        except Exception as ex:
            if log_fn:
                log_fn(f"  rename_lvar('{old_name}') raised: {ex}", 'warn')

        # --- Fallback: global symbol (dword_XXXX, qword_XXXX, byte_XXXX ...) ---
        # idc.set_name modifies the IDB directly, so it does need execute_sync.
        if not ok:
            try:
                _gr = [False]

                def _rename_global(_gr=_gr, old_name=old_name, new_name=new_name):
                    gea = idc.get_name_ea_simple(old_name)
                    if gea != idaapi.BADADDR:
                        _gr[0] = bool(idc.set_name(gea, new_name, idc.SN_AUTO))

                idaapi.execute_sync(_rename_global, idaapi.MFF_WRITE)
                ok = _gr[0]
                if ok and log_fn:
                    log_fn(f"  [{hex(ea)}] OK (global): '{old_name}' -> '{new_name}'", 'info')
                elif log_fn:
                    log_fn(f"  [{hex(ea)}] not a local or global: '{old_name}'", 'warn')
            except Exception as ex:
                if log_fn:
                    log_fn(f"  set_name('{old_name}') raised: {ex}", 'warn')

        if ok:
            applied += 1
        else:
            failed += 1

    return applied, failed



def parse_var_response(resp, log_fn=None):
    """
    Parse AI response lines of the form:
        old_name -> new_name
    Returns dict {old_name: new_name}. Returns {} if NO_RENAMES or empty.
    """
    if not resp or resp.strip().upper() == 'NO_RENAMES':
        return {}

    result = {}
    pattern = re.compile(r'^\s*(\w+)\s*->\s*(\w+)\s*$')
    for line in resp.splitlines():
        m = pattern.match(line)
        if m:
            old, new = m.group(1), m.group(2)
            if old != new:
                result[old] = new

    if not result and resp.strip().upper() != 'NO_RENAMES':
        if log_fn:
            log_fn(f"Warning: AI response yielded 0 renames. Raw (first 120 chars): {resp[:120]!r}", 'warn')

    return result


# ---------------------------------------------------------------------------
# FuncData
# ---------------------------------------------------------------------------

class FuncData:
    __slots__ = [
        'ea', 'name', 'demangled', 'status', 'checked',
        'code', 'var_suggestions', 'applied_renames', 'sub_count', 'queue'
    ]

    def __init__(self, ea, name):
        self.ea = ea
        self.name = name
        self.demangled = None
        if name.startswith('??') or name.startswith('_Z'):
            self.demangled = ida_name.demangle_name(name, 0)
        self.status = 'Pending'
        self.checked = True
        self.code = None
        self.var_suggestions = {}
        self.applied_renames = {}  # retains renames after var_suggestions is cleared
        self.sub_count = 0
        self.queue = 'clear'


# ---------------------------------------------------------------------------
# VirtualFuncModel
# ---------------------------------------------------------------------------

class VirtualFuncModel(QAbstractTableModel):
    HEADERS = ['', 'Address', 'Function Name', 'Queue', 'sub_* Count', 'Variables Renamed', 'Status']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.funcs, self.filtered, self.filter_text = [], [], ''
        self.sort_col = 3   # default: Queue
        self.sort_ord = Qt.AscendingOrder

    # ---- data management --------------------------------------------------

    def set_data(self, funcs):
        self.beginResetModel()
        self.funcs = funcs
        self._apply_filter()
        self.endResetModel()

    def append_data(self, funcs):
        existing_eas = {f.ea for f in self.funcs}
        new_funcs = [f for f in funcs if f.ea not in existing_eas]
        if not new_funcs:
            return
        self.beginResetModel()
        self.funcs.extend(new_funcs)
        self._apply_filter()
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.funcs, self.filtered = [], []
        self.endResetModel()

    # ---- filtering --------------------------------------------------------

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
                elif ft in f.queue.lower():
                    res.append(i)
                elif ft in f.status.lower():
                    res.append(i)
                # also search var_suggestions keys/values
                elif f.var_suggestions and any(
                    ft in k.lower() or ft in v.lower()
                    for k, v in f.var_suggestions.items()
                ):
                    res.append(i)
            self.filtered = res

        self.sort(self.sort_col, self.sort_ord)

    def set_filter(self, t):
        self.beginResetModel()
        self.filter_text = t
        self._apply_filter()
        self.endResetModel()

    # ---- QAbstractTableModel overrides ------------------------------------

    def rowCount(self, p=QModelIndex()):
        return len(self.filtered)

    def columnCount(self, p=QModelIndex()):
        return 7

    def headerData(self, s, o, r=Qt.DisplayRole):
        return self.HEADERS[s] if r == Qt.DisplayRole and o == Qt.Horizontal else None

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self.filtered):
            return None
        f = self.funcs[self.filtered[idx.row()]]
        c = idx.column()

        if role == Qt.DisplayRole:
            if c == 1: return f'{f.ea:X}'
            elif c == 2: return f.demangled or f.name
            elif c == 3: return f.queue.upper()
            elif c == 4: return str(f.sub_count)
            elif c == 5: return str(len(f.var_suggestions)) if f.var_suggestions else ''
            elif c == 6: return f.status

        elif role == Qt.CheckStateRole and c == 0:
            return Qt.Checked if f.checked else Qt.Unchecked

        elif role == Qt.TextAlignmentRole:
            if c == 0: return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ForegroundRole:
            if c == 3:  # Queue colors
                q = f.queue
                if q == 'clear':    return QColor('#34C759')
                if q == 'blocked':  return QColor('#FF9500')
                if q == 'done':     return QColor('#007AFF')
                if q == 'skipped':  return QColor('#8E8E93')
            if c == 6:  # Status colors
                s = f.status
                if 'Applied' in s or 'Renamed' in s:  return QColor('#34C759')
                if s == 'Pending':  return QColor('#FF9500')
                if 'Skipped' in s:  return QColor('#8E8E93')
                if 'Error' in s:    return QColor('#FF3B30')
                if 'Blocked' in s:  return QColor('#FF9500')
                if s.startswith('OK:') or s.startswith('Done:'): return QColor('#34C759')

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

    def get_func(self, row):
        return self.funcs[self.filtered[row]] if 0 <= row < len(self.filtered) else None

    def refresh_rows(self, indices):
        if not indices:
            return
        rows = [self.filtered.index(i) for i in indices if i in self.filtered]
        if rows:
            self.dataChanged.emit(
                self.index(min(rows), 0),
                self.index(max(rows), 6)
            )

    def toggle_all(self, chk):
        for i in self.filtered:
            self.funcs[i].checked = chk
        if self.filtered:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self.filtered) - 1, 0)
            )

    def select_by_queue(self, queue_name):
        queue_name = queue_name.lower()
        if queue_name == 'ready': queue_name = 'clear'
        if queue_name == 'deferred': queue_name = 'blocked'
        for i in self.filtered:
            f = self.funcs[i]
            f.checked = (f.queue.lower() == queue_name)
        if self.filtered:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.filtered) - 1, 0))

    def get_checked(self):
        return [(i, f) for i, f in enumerate(self.funcs) if f.checked]

    def total(self):
        return len(self.funcs)

    # ---- sorting ----------------------------------------------------------

    def _queue_sort_key(self, idx_val):
        q = self.funcs[idx_val].queue
        return {'clear': 0, 'blocked': 1, 'done': 2, 'skipped': 3}.get(q, 4)

    def sort(self, col, ord=Qt.AscendingOrder):
        self.beginResetModel()
        self.sort_col = col
        self.sort_ord = ord
        reverse = (ord == Qt.DescendingOrder)

        if col == 0:    # Checkbox
            self.filtered.sort(key=lambda i: self.funcs[i].checked, reverse=reverse)
        elif col == 1:    # Address
            self.filtered.sort(key=lambda i: self.funcs[i].ea, reverse=reverse)
        elif col == 2:  # Name
            self.filtered.sort(
                key=lambda i: (self.funcs[i].demangled or self.funcs[i].name).lower(),
                reverse=reverse
            )
        elif col == 3:  # Queue
            self.filtered.sort(key=self._queue_sort_key, reverse=reverse)
        elif col == 4:  # sub_* Count
            self.filtered.sort(key=lambda i: self.funcs[i].sub_count, reverse=reverse)
        elif col == 6:  # Status
            self.filtered.sort(key=lambda i: self.funcs[i].status.lower(), reverse=reverse)

        self.layoutChanged.emit()
        self.endResetModel()


# ---------------------------------------------------------------------------
# VarRenameWorker
# ---------------------------------------------------------------------------

VAR_SYS_PROMPT = """You are an expert reverse engineer analyzing decompiled C code.
Your task is to suggest meaningful variable names to replace the generic 
compiler-generated names (v1, v2, a1, a2, result, etc.).

RULES:
- Only rename variables where you have STRONG evidence of their purpose
- Evidence = how the variable is used, what APIs it is passed to, 
  what values are assigned to it, what conditions it appears in
- Use snake_case for all variable names
- Keep names short but descriptive: 3-30 characters
- Do NOT rename variables if their purpose is unclear
- Do NOT rename loop counters like i, j, k unless context is very clear
- Do NOT suggest names that are already descriptive
- Parameter names (a1, a2, etc.) should be renamed based on how they 
  are used in the function body

OUTPUT FORMAT (strictly follow, one variable per line):
old_name -> new_name
old_name -> new_name

If no variables can be confidently renamed, output exactly:
NO_RENAMES"""


VAR_BATCH_SYS_PROMPT = """You are an expert reverse engineer analyzing decompiled C code.
Your task is to suggest meaningful variable names to replace generic compiler-generated names for MULTIPLE functions.

RULES:
- Only rename variables where you have STRONG evidence (usage, API calls, assignments).
- Use snake_case for all variable names (3-30 characters).
- Parameter names (a1, a2, etc.) should be renamed based on body context.

OUTPUT FORMAT (strictly follow):
For EACH function, start with a marker [Function: func_name] and list its renames below.
If a function has no renames, output NO_RENAMES under its marker.

Example:
[Function: sub_12345]
v1 -> bytes_read
a1 -> out_buffer

[Function: sub_67890]
NO_RENAMES
"""


def parse_var_batch_response(resp, expected_funcs, log_fn=None):
    if not resp:
        return [{} for _ in expected_funcs]

    # Initialize results map for expected functions
    results_map = {f.name: {} for f in expected_funcs}
    current_func = None
    
    line_pattern = re.compile(r'^\s*(\w+)\s*->\s*(\w+)\s*$')
    marker_pattern = re.compile(r'\[Function:\s*([^\]]+)\]')

    for line in resp.splitlines():
        line = line.strip()
        if not line: continue

        m_func = marker_pattern.search(line)
        if m_func:
            current_func = m_func.group(1).strip()
            continue

        if current_func and current_func in results_map:
            if line.upper() == 'NO_RENAMES' or line.upper() == '(NO_RENAMES)':
                continue
            m = line_pattern.match(line)
            if m:
                old, new = m.group(1), m.group(2)
                if old != new:
                    results_map[current_func][old] = new

    return [results_map[f.name] for f in expected_funcs]


class VarRenameWorker(QThread):
    batch_done = Signal(list)   # list of (idx, func, suggestions_dict)
    progress = Signal(int, int)
    finished = Signal(int)
    log = Signal(str, str)
    update_status = Signal(str)

    def __init__(self, cfg, items, is_retry=False):
        super().__init__()
        self.cfg = cfg
        self.items = items          # list of (idx, FuncData)
        self.is_retry = is_retry
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        done = 0
        total = len(self.items)
        batch_size = max(1, self.cfg.get('batch_size', 1))
        
        # Group items into batches
        batches = [self.items[i : i + batch_size] for i in range(0, total, batch_size)]

        for b_idx, batch in enumerate(batches):
            if not self.running or _ai_mod.AI_CANCEL_REQUESTED:
                break

            # Cooldown between batches (skip before first)
            if b_idx > 0:
                cd = self.cfg.get('cooldown_seconds', 0)
                if cd > 0:
                    for s in range(cd * 10, 0, -2):
                        if not self.running: break
                        self.update_status.emit(f"Cooling down ({s / 10.0:.1f}s)")
                        time.sleep(0.2)
                    if not self.running: break

            # Prepare batch data
            batch_valid = []
            for idx, func in batch:
                if not func.code:
                    func.code = get_code_fast(func.ea, 50000, asm_max=1000)

                # Live Queue Reclassification
                if func.code:
                    func.sub_count = count_sub_calls(func.code, own_name=func.name)
                    func.queue = 'clear' if func.sub_count == 0 else 'blocked'

                if func.queue == 'blocked' and not self.is_retry:
                    func.status = 'Blocked'
                    # Signal to on_batch_done to defer this item (using None as sentinel)
                    self.batch_done.emit([(idx, func, None)])
                    done += 1
                    self.progress.emit(done, total)
                    continue

                if self.is_retry and func.queue == 'blocked':
                    func.status = 'Skipped: unresolved callees'
                    # func.queue already 'blocked'
                    self.batch_done.emit([(idx, func, {})]) # Empty dict = no suggestions
                    done += 1
                    self.progress.emit(done, total)
                    continue

                if not func.code:
                    self.log.emit(f"Skipping {hex(func.ea)}: No code", 'warn')
                    func.status = 'Error: No code'
                    self.batch_done.emit([(idx, func, {})])
                    done += 1
                    self.progress.emit(done, total)
                    continue
                
                batch_valid.append((idx, func))

            if not batch_valid:
                self.progress.emit(done, total)
                continue

            # Construct Prompt
            if len(batch_valid) == 1:
                idx, func = batch_valid[0]
                user_prompt = f"Function: {func.name} at {hex(func.ea)}\n\nCode:\n```\n{func.code}\n```"
                sys_prompt = VAR_SYS_PROMPT
            else:
                user_prompt = "Functions to analyze:\n\n"
                for idx, func in batch_valid:
                    user_prompt += f"--- [Function: {func.name}] ---\n```\n{func.code}\n```\n\n"
                sys_prompt = VAR_BATCH_SYS_PROMPT

            self.update_status.emit(f"Analyzing batch ({len(batch_valid)} funcs)")
            
            try:
                self._resp_len = 0
                def _chunk(t):
                    self._resp_len += len(t)
                    self.update_status.emit(f"Analyzing batch… {self._resp_len} chars")

                resp = ai_request(
                    self.cfg, user_prompt, sys_prompt,
                    logger=lambda m: self.log.emit(m, 'info'),
                    on_chunk=_chunk
                )

                if len(batch_valid) == 1:
                    idx, func = batch_valid[0]
                    suggestions = parse_var_response(resp, log_fn=lambda m, lv='warn': self.log.emit(m, lv))
                    self.batch_done.emit([(idx, func, suggestions)])
                    done += 1
                else:
                    batch_funcs = [it[1] for it in batch_valid]
                    sug_list = parse_var_batch_response(resp, batch_funcs, log_fn=lambda m: self.log.emit(m, 'warn'))
                    results_to_emit = []
                    for k, sug in enumerate(sug_list):
                        idx, func = batch_valid[k]
                        results_to_emit.append((idx, func, sug))
                        done += 1
                    self.batch_done.emit(results_to_emit)

            except Exception as e:
                self.log.emit(f"Batch analysis error: {str(e)}", 'err')
                # Fallback: mark items in batch as error
                err_results = []
                for idx, func in batch_valid:
                    func.status = f'Error: {str(e)[:60]}'
                    err_results.append((idx, func, {}))
                    done += 1
                self.batch_done.emit(err_results)

            self.progress.emit(done, total)

        self.finished.emit(done)


# ---------------------------------------------------------------------------
# BulkVariableRenamer Dialog
# ---------------------------------------------------------------------------

class BulkVariableRenamer(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.pn_config = CONFIG
        self.workers = []
        self._last_cfg = None
        self._worker_progress = {}
        self.completed_count = 0
        self.total_count = 0
        self._deferred_items = []
        self._is_retry_phase = False

        # Load state for batched scanning
        self.is_loading = False
        self.load_timer = None
        self.func_iter = None
        self.temp_funcs = []
        self.scanned = 0
        self._scan_idx = 0     # index into temp_funcs for pseudocode scan pass

        self.setup_ui()
        QTimer.singleShot(100, self.check_workflow_tip)

    def check_workflow_tip(self):
        if not getattr(CONFIG, 'show_pro_tip', True):
            return
        
        msg = (
            "<b>Pro Tip:</b> For the best results, use the tools in this sequence:<br><br>"
            "1. <b>Function Renamer</b> → 2. <b>Variable Renamer</b> → 3. <b>Function Analyzer</b><br><br>"
            "Following this order ensures the AI has the most accurate function names "
            "and variable context available at each step."
        )
        
        box = QMessageBox(self)
        box.setWindowTitle("PseudoNote Workflow Tip")
        box.setText(msg)
        box.setIcon(QMessageBox.Information)
        
        cb = QCheckBox("Don't show this tip again")
        box.setCheckBox(cb)
        box.exec_()
        
        if cb.isChecked():
            CONFIG.show_pro_tip = False
            CONFIG.save()

    # -----------------------------------------------------------------------
    # build_cfg — mirrors BulkRenamer.build_cfg
    # -----------------------------------------------------------------------
    def build_cfg(self, c):
        cfg = {
            'provider': c.active_provider,
            'parallel_workers': getattr(c, 'parallel_workers', 1),
            'cooldown_seconds': getattr(c, 'cooldown_seconds', 0),
            'asm_max_lines': getattr(c, 'asm_max_lines', 25),
        }
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
        elif p in ('openaicompatible', 'custom'):
            cfg['api_url'] = c.custom_url
            cfg['api_key'] = c.custom_key
            cfg['model'] = c.custom_model
        else:
            cfg['api_url'] = c.openai_url
            cfg['api_key'] = c.openai_key
            cfg['model'] = c.openai_model
        return cfg

    # -----------------------------------------------------------------------
    # setup_ui
    # -----------------------------------------------------------------------
    def setup_ui(self):
        self.setWindowTitle('PseudoNote: Bulk Variable Renamer')
        self.resize(1300, 900)
        self.setStyleSheet(STYLES)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- Toolbar row 1 ---
        tb = QHBoxLayout()
        tb.setSpacing(8)

        self.load_sub_btn = QPushButton('Load sub_*')
        self.load_sub_btn.setObjectName("primary")
        self.load_sub_btn.clicked.connect(lambda: self.load_funcs(prefix='sub_'))
        tb.addWidget(self.load_sub_btn)

        self.load_all_btn = QPushButton('Load All Functions')
        self.load_all_btn.setObjectName("primary")
        self.load_all_btn.clicked.connect(lambda: self.load_funcs(prefix=None, mode='all'))
        tb.addWidget(self.load_all_btn)

        self.load_btn = QPushButton('Load')
        self.load_btn.setObjectName("primary")
        self.load_btn.clicked.connect(self._do_load_pattern)
        tb.addWidget(self.load_btn)

        self.load_input = QLineEdit()
        self.load_input.setPlaceholderText("Search substring...")
        self.load_input.setFixedWidth(280)
        self.load_input.returnPressed.connect(self._do_load_pattern)
        tb.addWidget(self.load_input)

        tb.addStretch()

        settings_btn = QPushButton("Settings")
        settings_btn.setObjectName("secondary")
        settings_btn.clicked.connect(self.open_settings)
        tb.addWidget(settings_btn)

        layout.addLayout(tb)
        
        # --- Row 1b: Quick Load buttons ---
        smart_row = QHBoxLayout()
        smart_row.setSpacing(8)

        entry_btn = QPushButton("Entry Points")
        entry_btn.setToolTip(
            "Load entry-point functions: main, WinMain, DllMain, wWinMain, wmain, "
            "TLS callbacks, and the binary's OEP. These are common starting points for malicious logic."
        )
        entry_btn.clicked.connect(self.load_entry_points)
        smart_row.addWidget(entry_btn)

        exports_btn = QPushButton("Exports")
        exports_btn.setToolTip("Load all exported functions from the binary.")
        exports_btn.clicked.connect(self.load_exports)
        smart_row.addWidget(exports_btn)

        high_xref_btn = QPushButton("High Xref")
        high_xref_btn.setToolTip("Load functions called by 5 or more distinct callers (hub/dispatcher functions).")
        high_xref_btn.clicked.connect(self.load_high_xref)
        smart_row.addWidget(high_xref_btn)

        wrapper_btn = QPushButton("Wrapper (Tiny functions)")
        wrapper_btn.setToolTip("Load very small functions that call exactly one named import.")
        wrapper_btn.clicked.connect(self.load_import_wrappers)
        smart_row.addWidget(wrapper_btn)

        smart_row.addStretch()
        layout.addLayout(smart_row)

        # --- Info / stats bar ---
        info_row = QHBoxLayout()
        self.stats_label = QLabel("Ready: 0 | Deferred: 0 | Total: 0")
        self.stats_label.setObjectName("status_msg")
        info_row.addWidget(self.stats_label)
        info_row.addStretch()
        layout.addLayout(info_row)

        # --- Filter row ---
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter Table:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Search in current list...')
        self.filter_edit.textChanged.connect(lambda t: (
            self.model.set_filter(t),
            self.update_stats_label()
        ))
        filter_layout.addWidget(self.filter_edit)
        layout.addLayout(filter_layout)

        # --- Table ---
        self.model = VirtualFuncModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)

        h = self.table.horizontalHeader()
        self.table.setColumnWidth(0, 30)   # checkbox
        self.table.setColumnWidth(1, 100)  # address
        self.table.setColumnWidth(2, 220)  # function name
        self.table.setColumnWidth(3, 80)   # queue
        self.table.setColumnWidth(4, 90)   # sub_* count
        self.table.setColumnWidth(5, 130)  # variables renamed
        h.setSectionsClickable(True)
        h.setSortIndicatorShown(True)
        h.setSectionResizeMode(QHeaderView.Interactive)
        h.setSectionResizeMode(6, QHeaderView.Stretch)  # status stretches
        h.setStretchLastSection(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(self.on_table_double_click)

        layout.addWidget(self.table)

        self.model.dataChanged.connect(self.update_button_states)
        self.model.modelReset.connect(self.update_button_states)
        self.model.modelReset.connect(self.update_stats_label)

        # --- Selection row ---
        sel_row = QHBoxLayout()

        sel_all_btn = QPushButton('Select All')
        sel_all_btn.clicked.connect(lambda: self.model.toggle_all(True))
        sel_row.addWidget(sel_all_btn)

        sel_none_btn = QPushButton('Select None')
        sel_none_btn.clicked.connect(lambda: self.model.toggle_all(False))
        sel_row.addWidget(sel_none_btn)

        sep = QLabel("|")
        sep.setStyleSheet("color: gray; margin: 0 5px;")
        sel_row.addWidget(sep)

        sel_clear_btn = QPushButton('Select Clear')
        sel_clear_btn.clicked.connect(lambda: self.model.select_by_queue('clear'))
        sel_row.addWidget(sel_clear_btn)

        sel_blocked_btn = QPushButton('Select Blocked')
        sel_blocked_btn.clicked.connect(lambda: self.model.select_by_queue('blocked'))
        sel_row.addWidget(sel_blocked_btn)

        sel_row.addStretch()
        layout.addLayout(sel_row)

        # --- Log ---
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(130)
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
        layout.addWidget(self.log)

        # --- Progress ---
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(16)
        self.progress.setTextVisible(True)
        self.progress.setAlignment(Qt.AlignCenter)
        self.progress.setFormat("%p% (%v/%m)")
        layout.addWidget(self.progress)

        # --- Actions row ---
        actions = QHBoxLayout()

        self.start_btn = QPushButton('Start Variable Rename')
        self.start_btn.setObjectName("primary")
        self.start_btn.setMinimumHeight(32)
        self.start_btn.clicked.connect(self.start_rename)
        actions.addWidget(self.start_btn)

        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setMinimumHeight(32)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_all)
        actions.addWidget(self.stop_btn)

        actions.addStretch()

        self.apply_btn = QPushButton('Apply Suggestions')
        self.apply_btn.setObjectName("success")
        self.apply_btn.setMinimumHeight(32)
        self.apply_btn.setMinimumWidth(140)
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self.apply_suggestions)
        actions.addWidget(self.apply_btn)

        self.unload_btn = QPushButton('Unload')
        self.unload_btn.setObjectName("danger")
        self.unload_btn.setMinimumHeight(32)
        self.unload_btn.clicked.connect(self._unload_table)
        actions.addWidget(self.unload_btn)

        self.export_btn = QPushButton('Export CSV')
        self.export_btn.setObjectName("secondary")
        self.export_btn.setMinimumHeight(32)
        self.export_btn.clicked.connect(self.export_csv)
        actions.addWidget(self.export_btn)

        layout.addLayout(actions)
        self.update_button_states()

    # -----------------------------------------------------------------------
    # Stats / status
    # -----------------------------------------------------------------------
    def update_stats_label(self):
        clear = sum(1 for f in self.model.funcs if f.queue == 'clear')
        blocked = sum(1 for f in self.model.funcs if f.queue == 'blocked')
        total = self.model.total()
        self.stats_label.setText(f"Clear: {clear} | Blocked: {blocked} | Total: {total}")

    def add_log(self, msg, lv='info'):
        colors = {'info': '#3A3A3C', 'ok': '#34C759', 'err': '#FF3B30', 'warn': '#FF9500'}
        color = colors.get(lv, '#3A3A3C')
        ts = time.strftime("%H:%M:%S")
        self.log.append(
            f'<span style="color: gray;">[{ts}]</span> '
            f'<span style="color: {color};">{msg}</span>'
        )
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def update_button_states(self):
        has_content = self.model.total() > 0
        has_checked = len(self.model.get_checked()) > 0
        has_suggestions = any(f.var_suggestions for f in self.model.funcs)
        is_busy = bool(self.workers) or self.is_loading

        self.start_btn.setEnabled(has_checked and not is_busy)
        self.stop_btn.setEnabled(is_busy)
        self.apply_btn.setEnabled(has_suggestions and not is_busy)
        self.unload_btn.setEnabled(has_content)
        self.export_btn.setEnabled(has_content)

    def open_settings(self):
        from pseudonote.view import SettingsDialog
        d = SettingsDialog(self.pn_config, self, hide_extra_tabs=True, mode='var_renamer')
        d.exec_()

    def _make_fdata(self, ea, name):
        """Create a FuncData with persistent rename state check."""
        fd = FuncData(ea, name)
        # Check if already renamed by AI (persistent state)
        marker = load_from_idb(ea, _IDB_TAG)
        if marker == "variables_renamed":
            fd.queue = 'done'
            fd.status = 'Already Renamed'
            fd.checked = False
        else:
            fd.queue = 'clear'
            fd.status = 'Pending'
        return fd

    def _finish_smart_load(self, funcs, kind):
        """Common finalization for all smart load buttons."""
        if funcs:
            self.model.append_data(funcs)
            self.update_stats_label()
            self.update_button_states()
            self.add_log(f"Loaded {len(funcs)} {kind} function(s).", 'ok')
        else:
            self.add_log(f"No {kind} functions found.", 'info')

    def load_entry_points(self):
        """Load main-like entry-point functions + OEP."""
        ENTRY_KEYWORDS = [
            'main', 'wmain', 'winmain', 'wwinmain', 'dllmain',
            'dllentrypoint', 'wstartup', 'rtlentrypoint',
            'tlscallback', 'tls_callback', 'crtstart', 'crtmain',
            'wincrt', 'startup',
        ]
        funcs = []
        seen = set()

        def _name_matches(name):
            raw_lc = name.lower()
            if 'main' in raw_lc: return True
            n = raw_lc.lstrip('_')
            for sep in ('@', '('):
                if sep in n: n = n[:n.index(sep)]
            return any(kw == n or kw in n for kw in ENTRY_KEYWORDS)

        def _collect():
            for _, ordinal, ea, name in idautils.Entries():
                if ea == idaapi.BADADDR or ea in seen: continue
                if not is_valid_seg(ea): continue
                if not name:
                    name = idc.get_func_name(ea) or idc.get_name(ea) or ''
                if _name_matches(name):
                    funcs.append(self._make_fdata(ea, name))
                    seen.add(ea)

            for ea in idautils.Functions():
                if ea in seen or not is_valid_seg(ea): continue
                name = idc.get_func_name(ea)
                if name and _name_matches(name):
                    funcs.append(self._make_fdata(ea, name))
                    seen.add(ea)

        idaapi.execute_sync(_collect, idaapi.MFF_READ)
        self._finish_smart_load(funcs, "entry point")

    def load_exports(self):
        """Load all exported functions."""
        funcs = []
        seen = set()
        def _collect():
            for _, ordinal, ea, name in idautils.Entries():
                if ea == idaapi.BADADDR or ea in seen: continue
                if not is_valid_seg(ea): continue
                if not name:
                    name = idc.get_func_name(ea) or idc.get_name(ea) or f'export_{hex(ea)}'
                funcs.append(self._make_fdata(ea, name))
                seen.add(ea)
        idaapi.execute_sync(_collect, idaapi.MFF_READ)
        self._finish_smart_load(funcs, "export")

    def load_high_xref(self):
        """Load functions with high incoming cross-references."""
        MIN_XREF = 5
        funcs = []
        def _collect():
            for ea in idautils.Functions():
                if not is_valid_seg(ea): continue
                name = idc.get_func_name(ea)
                if not name: continue
                callers = {xref.frm for xref in idautils.XrefsTo(ea, idaapi.XREF_FAR) if xref.type in (idaapi.fl_CN, idaapi.fl_CF)}
                if len(callers) >= MIN_XREF:
                    funcs.append(self._make_fdata(ea, name))
        idaapi.execute_sync(_collect, idaapi.MFF_READ)
        self._finish_smart_load(funcs, f"high-xref (≥{MIN_XREF} callers)")

    def load_import_wrappers(self):
        """Load small functions that call exactly one named (non-sub_*) external."""
        funcs = []
        def _collect():
            for ea in idautils.Functions():
                if not is_valid_seg(ea): continue
                name = idc.get_func_name(ea)
                if not name: continue
                named_callees = set()
                for item in idautils.FuncItems(ea):
                    for xref in idautils.CodeRefsFrom(item, False):
                        callee_name = idc.get_func_name(xref)
                        if callee_name and not callee_name.startswith('sub_') and callee_name != name:
                            named_callees.add(callee_name)
                f = ida_funcs.get_func(ea)
                func_size = (f.size() if f else 0)
                if len(named_callees) == 1 and func_size < 80:
                    funcs.append(self._make_fdata(ea, name))
        idaapi.execute_sync(_collect, idaapi.MFF_READ)
        self._finish_smart_load(funcs, "import wrapper")

    # -----------------------------------------------------------------------
    # Load functions (batched via QTimer to keep UI responsive)
    # -----------------------------------------------------------------------
    def _do_load_pattern(self):
        pat = self.load_input.text().strip()
        if not pat:
            return
        self.load_funcs(prefix=pat, mode='search', replace=False)

    def load_funcs(self, prefix=None, mode='prefix', replace=True):
        """
        Step 1: Enumerate all functions matching the prefix/mode.
        Step 2: Fetch pseudocode for each in a batched QTimer loop.
        Step 3: Classify into ready/deferred.
        """
        if replace:
            self.model.clear()
            self.temp_funcs = []

        self.load_prefix = prefix
        self.load_mode = mode
        self.scanned = 0
        self.is_loading = True

        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.progress.setFormat("Scanning functions...")

        self.load_sub_btn.setEnabled(False)
        self.load_all_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.add_log(f"Scanning functions (mode={mode}, prefix={prefix!r})...", 'info')

        # Build a simple FuncData list first (fast — just name matching)
        raw_funcs = []
        seen_eas = set()
        if not replace:
            seen_eas = {f.ea for f in self.temp_funcs}

        def _collect():
            for ea in idautils.Functions():
                if ea in seen_eas:
                    continue
                name = idc.get_func_name(ea)
                if not name:
                    continue
                is_match = False
                if mode == 'all':
                    is_match = True
                elif mode == 'search' and prefix:
                    lp = prefix.lower()
                    is_match = lp in name.lower()
                    if not is_match:
                        dem = ida_name.demangle_name(name, 0)
                        if dem and lp in dem.lower():
                            is_match = True
                    if not is_match:
                        is_match = lp in f'{ea:x}'
                elif prefix:
                    is_match = name.startswith(prefix)
                if not is_match:
                    continue
                if not is_valid_seg(ea):
                    continue

                # NEW: Check if already renamed by AI (persistent state)
                marker = load_from_idb(ea, _IDB_TAG)
                fd = FuncData(ea, name)
                if marker == "variables_renamed":
                    fd.queue = 'done'
                    fd.status = 'Already Renamed'
                    fd.checked = False

                raw_funcs.append(fd)
                seen_eas.add(ea)

        idaapi.execute_sync(_collect, idaapi.MFF_READ)

        self.temp_funcs = list(self.model.funcs) + raw_funcs if not replace else raw_funcs
        self.add_log(f"Scan: found {len(raw_funcs)} matching functions. Populating table...", 'info')

        # Now start the pseudocode-fetch pass
        self._scan_idx = len(self.model.funcs) if not replace else 0
        self._scan_total = len(self.temp_funcs)

        self.progress.setRange(0, self._scan_total)
        self.progress.setValue(self._scan_idx)
        self.progress.setFormat(f"Populating table... %v/%m")

        self.load_timer = QTimer(self)
        self.load_timer.timeout.connect(self._scan_batch)
        self.load_timer.start(1)

    def _scan_batch(self):
        """Standard loading pass: no decompilation to keep UI instant."""
        if not self.is_loading:
            self._finish_load()
            return

        batch_size = 500
        end = min(self._scan_idx + batch_size, len(self.temp_funcs))

        for i in range(self._scan_idx, end):
            f = self.temp_funcs[i]
            f.sub_count = 0
            f.queue = 'clear'
            f.code = None

        self._scan_idx = end
        self.progress.setValue(self._scan_idx)

        if self._scan_idx >= len(self.temp_funcs):
            self._finish_load()

    def _finish_load(self):
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None
        self.is_loading = False
        self.model.set_data(self.temp_funcs)
        self.model.modelReset.connect(self.update_stats_label)
        self.update_stats_label()
        self.progress.setVisible(False)
        self.add_log(f"Loaded {len(self.temp_funcs)} functions. Live classification enabled.", 'ok')
        self.load_sub_btn.setEnabled(True)
        self.load_all_btn.setEnabled(True)
        self.update_button_states()

    # -----------------------------------------------------------------------
    # Start rename
    # -----------------------------------------------------------------------
    def start_rename(self):
        items = self.model.get_checked()
        if not items:
            QMessageBox.warning(self, 'Warning', 'No functions selected.')
            return

        # Reset cancel flag
        _ai_mod.AI_CANCEL_REQUESTED = False

        self._deferred_items = []
        self._runtime_deferred = []
        self._is_retry_phase = False

        # Build cfg
        from pseudonote.renamer import BulkRenamer
        tmp = BulkRenamer(self.pn_config)
        self._last_cfg = tmp.build_cfg(self.pn_config)
        tmp.deleteLater()

        self._start_worker(items, is_retry=False)

    def _start_worker(self, items, is_retry=False):
        for w in self.workers:
            w.stop()
        self.workers = []
        self._worker_progress = {}
        self.completed_count = 0
        self.total_count = len(items)

        self.progress.setVisible(True)
        self.progress.setRange(0, self.total_count)
        self.progress.setValue(0)
        self.progress.setFormat("%p% (%v/%m)")

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.apply_btn.setEnabled(False)

        # Split items across parallel_workers threads
        n_workers = max(1, self._last_cfg.get('parallel_workers', 1))
        # Clamp to item count so we don't make empty workers
        n_workers = min(n_workers, len(items))

        # Round-robin distribution to keep load balanced
        slices = [[] for _ in range(n_workers)]
        for i, item in enumerate(items):
            slices[i % n_workers].append(item)

        phase = "retry pass" if is_retry else "first pass"
        self.add_log(
            f"Starting variable rename ({phase}): {len(items)} function(s) across {n_workers} worker(s)...",
            'info'
        )

        for sl in slices:
            if not sl:
                continue
            w = VarRenameWorker(self._last_cfg, sl, is_retry=is_retry)
            w.batch_done.connect(self.on_batch_done)
            w.progress.connect(self.on_progress)
            w.finished.connect(self.on_worker_finished)
            w.log.connect(self.add_log)
            w.update_status.connect(self.on_update_status)
            self.workers.append(w)
            w.start()

    # -----------------------------------------------------------------------
    # Retry deferred
    # -----------------------------------------------------------------------
    def retry_deferred(self):
        if not self._deferred_items:
            self.finish_rename()
            return

        self._is_retry_phase = True
        self.add_log(
            f"Retry pass: re-scanning {len(self._deferred_items)} BLOCKED functions...",
            'info'
        )
        
        promoted = []
        still_blocked = []

        for idx, func in self._deferred_items:
            # Re-fetch pseudocode (callees may have been renamed externally)
            new_code = get_code_fast(func.ea, 50000, asm_max=1000)
            if new_code is not None:
                func.code = new_code
            func.sub_count = count_sub_calls(func.code, own_name=func.name)
            if func.sub_count == 0:
                func.queue = 'clear'
                func.status = 'Pending'
                promoted.append((idx, func))
            else:
                func.queue = 'blocked'
                still_blocked.append((idx, func))

        self._deferred_items = still_blocked
        self.add_log(
            f"Retry: {len(promoted)} promoted to CLEAR, {len(still_blocked)} still BLOCKED.",
            'info' if promoted else 'warn'
        )
        self.model.sort(self.model.sort_col, self.model.sort_ord)

        self._deferred_items = []
        if promoted:
            self._start_worker(promoted, is_retry=True)
        elif still_blocked:
            for idx, func in still_blocked:
                func.status = 'Analyzed (with sub_*)'
            self.add_log(f"Proceeding to analyze {len(still_blocked)} functions despite unresolved callees.", 'warn')
            self._start_worker(still_blocked, is_retry=True)
        else:
            self.finish_rename()

    # -----------------------------------------------------------------------
    # Worker slots
    # -----------------------------------------------------------------------
    def on_batch_done(self, results):
        sort_col = self.model.sort_col
        sort_ord = self.model.sort_ord
        auto_apply = getattr(self.pn_config, 'var_auto_apply', False)

        for idx, func, suggestions in results:
            if suggestions is None: # DEFERRED
                func.queue = 'blocked'
                func.status = 'Blocked'
                self._runtime_deferred.append((idx, func))
                continue

            func.var_suggestions = suggestions
            if suggestions:
                if auto_apply:
                    # Apply immediately — don't store suggestions for later
                    applied, failed = apply_var_renames(func.ea, suggestions, log_fn=self.add_log)
                    if applied > 0 or failed == 0:
                        func.status = f"Applied: {applied} renamed"
                        if failed > 0:
                            func.status += f", {failed} failed"
                        if applied > 0:
                            save_to_idb(func.ea, _IDB_TAG, "variables_renamed")
                    else:
                        func.status = f"Apply failed ({failed} variables)"
                    func.var_suggestions = {}  # clear — already applied
                    func.applied_renames = dict(suggestions)  # keep for detail view
                    func.queue = 'done'
                else:
                    func.status = f"Done: {len(suggestions)} suggestions"
                    func.queue = 'done'
            elif func.status.startswith('Error'):
                pass  # keep error status
            elif 'Skipped' in func.status:
                pass  # keep skipped status
            else:
                func.status = 'No renames suggested'
                func.queue = 'done'

        self.model.sort(sort_col, sort_ord)
        self.update_stats_label()

        # Enable Apply button only if there are pending (non-auto-applied) suggestions
        has_suggestions = any(f.var_suggestions for f in self.model.funcs)
        if has_suggestions and not self.workers:
            self.apply_btn.setEnabled(True)

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

    def on_worker_finished(self, count):
        sender = self.sender()
        if sender in self.workers:
            self.workers.remove(sender)

        if not self.workers:
            self._deferred_items.extend(self._runtime_deferred)
            self._runtime_deferred = []
            
            if self._deferred_items:
                self.retry_deferred()
            else:
                self.finish_rename()

    def finish_rename(self):
        self.progress.setVisible(False)
        _ai_mod.AI_CANCEL_REQUESTED = False
        done_count = sum(1 for f in self.model.funcs if f.queue == 'done')
        has_suggestions = any(f.var_suggestions for f in self.model.funcs)
        self.add_log(
            f"Variable rename complete. {done_count} function(s) processed.",
            'ok'
        )
        self.update_button_states()
        self.update_stats_label()
        if has_suggestions:
            self.apply_btn.setEnabled(True)

    def stop_all(self):
        _ai_mod.AI_CANCEL_REQUESTED = True
        self.stop_btn.setEnabled(False)
        self.progress.setFormat("Stopping... waiting for current function to finish")
        for w in self.workers:
            w.stop()
        self.is_loading = False
        if self.load_timer:
            self.load_timer.stop()
            self.load_timer = None
        self.add_log("Stop requested. Waiting for current function to finish...", 'warn')

    # -----------------------------------------------------------------------
    # Apply suggestions
    # -----------------------------------------------------------------------
    def apply_suggestions(self):
        checked_funcs = [f for _, f in self.model.get_checked() if f.var_suggestions]
        if not checked_funcs:
            # Fallback: apply to all funcs with suggestions
            checked_funcs = [f for f in self.model.funcs if f.var_suggestions]
        if not checked_funcs:
            self.add_log('No functions with pending suggestions to apply.', 'warn')
            return

        total_applied = 0
        total_failed = 0
        indices = []

        for i, f in enumerate(self.model.funcs):
            if not f.var_suggestions:
                continue
            if f not in checked_funcs:
                continue
            applied, failed = apply_var_renames(f.ea, f.var_suggestions, log_fn=self.add_log)
            total_applied += applied
            total_failed += failed
            if applied > 0 or failed == 0:
                f.status = f"Applied: {applied} renamed"
                if failed > 0:
                    f.status += f", {failed} failed"
                if applied > 0:
                    save_to_idb(f.ea, _IDB_TAG, "variables_renamed")
            else:
                f.status = f"Apply failed ({failed} variables)"
            f.applied_renames = dict(f.var_suggestions)  # keep for detail view
            f.var_suggestions = {}  # clear after apply
            indices.append(i)

        self.model.refresh_rows(indices)
        self.update_stats_label()
        self.add_log(
            f"Apply complete: {total_applied} variable(s) renamed, "
            f"{total_failed} failed.",
            'ok' if total_applied > 0 else 'warn'
        )
        self.update_button_states()

    # -----------------------------------------------------------------------
    # Unload
    # -----------------------------------------------------------------------
    def _unload_table(self):
        self.model.clear()
        self.temp_funcs = []
        self.update_stats_label()
        self.add_log("Table unloaded.", 'info')
        self.update_button_states()

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def show_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        func = self.model.get_func(idx.row())
        if not func:
            return

        menu = QMenu(self)
        menu.setStyleSheet(STYLES)

        view_action = menu.addAction("View Pseudocode")
        view_action.triggered.connect(lambda: idaapi.open_pseudocode(func.ea, 0))

        menu.addSeparator()

        rescan_action = menu.addAction("Re-scan this function")

        def _rescan():
            new_code = get_code_fast(func.ea, 50000, asm_max=1000)
            if new_code is not None:
                func.code = new_code
            func.sub_count = count_sub_calls(func.code)
            func.queue = 'clear' if func.sub_count == 0 else 'blocked'
            func.status = 'Pending'
            func_index = self.model.filtered[idx.row()]
            self.model.refresh_rows([func_index])
            self.update_stats_label()
            self.add_log(
                f"Re-scanned {func.name}: sub_count={func.sub_count}, queue={func.queue}",
                'info'
            )

        rescan_action.triggered.connect(_rescan)

        reanalyze_action = menu.addAction("Re-analyze this function")

        def _reanalyze():
            if not self._last_cfg:
                QMessageBox.warning(
                    self, 'Warning',
                    'No previous config found. Run Start Variable Rename first.'
                )
                return
            _ai_mod.AI_CANCEL_REQUESTED = False
            func_index = self.model.filtered[self.table.indexAt(pos).row()]
            single_item = [(func_index, func)]
            self._start_worker(single_item, is_retry=False)

        reanalyze_action.triggered.connect(_reanalyze)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    # -----------------------------------------------------------------------
    # Double-click → detail dialog
    # -----------------------------------------------------------------------
    def on_table_double_click(self, idx):
        if not idx.isValid():
            return
        func = self.model.get_func(idx.row())
        if not func:
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Variable Suggestions: {func.name}")
        dlg.resize(550, 400)
        dlg.setStyleSheet(STYLES)

        vbox = QVBoxLayout(dlg)

        queue_colors = {
            'clear': '#34C759', 'blocked': '#FF9500',
            'done': '#007AFF', 'skipped': '#8E8E93'
        }
        qcolor = queue_colors.get(func.queue, '#333333')

        info = QLabel(
            f"<b>Function:</b> {func.demangled or func.name} ({hex(func.ea)})<br>"
            f"<b>Queue:</b> <span style='color:{qcolor}'>{func.queue.upper()}</span><br>"
            f"<b>sub_* Count:</b> {func.sub_count}"
        )
        info.setWordWrap(True)
        vbox.addWidget(info)

        if func.var_suggestions:
            suggestions_text = "\n".join(
                f"{old} \u2192 {new}"
                for old, new in func.var_suggestions.items()
            )
        elif getattr(func, 'applied_renames', None):
            suggestions_text = "\n".join(
                f"{old} \u2192 {new}  (already applied)"
                for old, new in func.applied_renames.items()
            )
        else:
            suggestions_text = "(No suggestions)"

        edit = QTextEdit()
        edit.setPlainText(suggestions_text)
        edit.setReadOnly(True)
        vbox.addWidget(edit)

        btn_row = QHBoxLayout()

        if func.var_suggestions:
            apply_this_btn = QPushButton("Apply These Renames")
            apply_this_btn.setObjectName("success")

            def _apply_this():
                applied, failed = apply_var_renames(func.ea, func.var_suggestions)
                func.status = f"Applied: {applied} renamed"
                if failed > 0:
                    func.status += f", {failed} failed"
                if applied > 0:
                    save_to_idb(func.ea, _IDB_TAG, "variables_renamed")
                func.var_suggestions = {}
                self.model.refresh_rows([self.model.funcs.index(func)])
                self.update_button_states()
                self.add_log(
                    f"Applied {applied} rename(s) for {func.name}, {failed} failed.",
                    'ok'
                )
                dlg.accept()

            apply_this_btn.clicked.connect(_apply_this)
            btn_row.addWidget(apply_this_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        vbox.addLayout(btn_row)

        dlg.exec_()

    # -----------------------------------------------------------------------
    # Export CSV
    # -----------------------------------------------------------------------
    def export_csv(self):
        if not self.model.funcs:
            QMessageBox.warning(self, 'Warning', 'Table is empty.')
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if not path:
            return

        try:
            with open(path, 'w', newline='', encoding='utf-8') as fp:
                writer = csv.writer(fp)
                writer.writerow(['Address', 'Function Name', 'Queue', 'sub_* Count', 'Suggestions', 'Status'])
                for i in self.model.filtered:
                    f = self.model.funcs[i]
                    suggestions_str = '; '.join(
                        f'{k}->{v}' for k, v in f.var_suggestions.items()
                    ) if f.var_suggestions else ''
                    writer.writerow([
                        f'{f.ea:X}',
                        f.demangled or f.name,
                        f.queue,
                        f.sub_count,
                        suggestions_str,
                        f.status
                    ])
            self.add_log(
                f"Exported {len(self.model.filtered)} rows to {os.path.basename(path)}",
                'ok'
            )
            QMessageBox.information(self, "Success", f"Data exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export CSV: {str(e)}")
            self.add_log(f"Export error: {str(e)}", 'err')
