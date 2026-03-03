"""
Deep Analyzer for PseudoNote - Complete bottom-up recursive analysis.
"""
__version__ = "1.0.0"
__author__ = "PseudoNote Deep Analyzer"

import idaapi, idautils, idc, ida_hexrays, ida_funcs, ida_name, ida_segment, ida_nalt
import subprocess
import sys
import shutil
import stat
import concurrent.futures
import math
import html
import datetime
import json
import os
import re
import time
import collections
from typing import Dict, List, Optional, Callable, Set, Any, Tuple
from pseudonote.qt_compat import (
    QtWidgets, QtCore, QtGui, QThread, Signal, Slot, QDialog,
    QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QGroupBox, QLineEdit, QPushButton, 
    QCheckBox, QSpinBox, QProgressBar, QSplitter, QTreeWidget, QTreeWidgetItem, 
    QHeaderView, QTabWidget, QTextEdit, QTextBrowser, QFont, QMessageBox, 
    QTimer, QMenu, QApplication, QFrame, QWidget, QSettings, QComboBox
)
import pseudonote.ai_client as _ai_mod

from pseudonote.config import CONFIG, LOGGER
from pseudonote.idb_storage import save_to_idb, load_from_idb
from pseudonote.renamer import (
    is_valid_seg, is_sys_func, get_code_fast, get_strings_fast,
    ai_request, count_sub_calls_fast, STYLES
)
from pseudonote.view import SettingsDialog
import pseudonote.api_taxonomy as api_tax
from pseudonote.report_generator import (
    generate_html_report, 
    save_decompiled_to_disk,
    save_readable_to_disk,
    get_function_artifact_path,
    cleanup_decompiled_code,
    load_readable_from_disk, 
    load_decompiled_from_disk,
    write_markdown_header,
    append_function_to_markdown,
    finalize_markdown,
    assemble_malware_source,
    build_analysis_digest,
    build_function_markdown_piece,
    get_graph_ascii,
    generate_call_flow_mermaid,
    generate_technical_overview,
    generate_malware_analysis_assessment,
    generate_key_capabilities,
    generate_suspicious_functions,
    generate_malicious_functions,
    generate_behavioral_indicators,
    generate_risk_assessment,
    generate_execution_flow_overview,
    generate_c2_analysis,
    generate_anti_analysis_logic,
    generate_crypto_artifacts,
    generate_persistence_mechanisms,
    generate_file_registry_interaction,
    generate_api_resolving_logic,
    generate_recon_infostealer_analysis
)

# Consolidated reporting logic aliases
from pseudonote.report_generator import _validated_ai_request


# Code truncation helper (line-based)
def truncate_code_lines(code, max_lines=750):
    """
    Truncate decompiled code by line count to prevent context overflow.
    
    Default 750 lines ~ 30-40k chars, safe for most LLM context windows.
    Adjustable via CONFIG if needed.
    """
    # Allow override from config
    max_lines = getattr(CONFIG, 'deep_max_code_lines', max_lines)
    
    if not code: return ""
    if isinstance(code, list):
        lines = code
    else:
        lines = str(code).splitlines()
    
    if len(lines) <= max_lines: 
        return code if isinstance(code, str) else "\n".join(lines)
    
    # Truncate with clear marker
    return "\n".join(lines[:max_lines]) + "\n... [TRUNCATED: %d lines omitted]" % (len(lines) - max_lines)

# Styles matching renamer's aesthetic
STYLES_ANALYZER = STYLES + """
    QGroupBox {
        border: 1px solid #D1D1D6;
        border-radius: 8px;
        margin-top: 20px;
        background-color: transparent;
        font-weight: bold;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        padding: 0 5px;
        color: #007AFF;
        background-color: transparent;
    }
    QTabWidget::pane {
        border: 1px solid #D1D1D6;
        border-radius: 8px;
        background: #FFFFFF;
    }
    QTabBar::tab {
        background: #F2F2F7;
        border: 1px solid #D1D1D6;
        border-bottom: none;
        padding: 8px 16px;
        border-radius: 6px 6px 0 0;
        font-weight: bold;
        color: #636366;
    }
    QTabBar::tab:selected {
        background: #FFFFFF;
        color: #1C1C1E;
        border-top: 2px solid #007AFF;
    }
    QTreeWidget {
        background-color: #FFFFFF;
        border: 1px solid #D1D1D6;
        border-radius: 4px;
        outline: none;
    }
    QTreeWidget::item {
        padding: 6px;
    }
    QHeaderView::section {
        background-color: #F2F2F7;
        color: #3A3A3C;
        padding: 8px;
        border: none;
        border-right: 1px solid #D1D1D6;
        border-bottom: 1px solid #D1D1D6;
        font-weight: bold;
    }
    QProgressBar {
        background-color: #E5E5EA;
        border: none;
        border-radius: 6px;
        color: #000000;
        text-align: center;
        height: 22px;
    }
    QProgressBar::chunk {
        background-color: #007AFF;
        border-radius: 6px;
    }
    QPushButton#secondary { 
        background-color: #5856D6; 
        color: #FFFFFF; 
        border: 1px solid #5856D6; 
    }
    QPushButton#secondary:hover { background-color: #4845B2; }
    QLabel#status_msg { color: #636366; font-style: italic; font-size: 9pt; }
"""
# --- MALWARE API TAXONOMY (Imported) -----------------------------------------
from pseudonote.api_taxonomy import (
    derive_risk_from_api_tags as _derive_risk_from_api_tags,
    get_api_tags_for_function, evaluate_combination_rules,
    RISK_ORDER as _RISK_ORDER, SEVERITY_ORDER as _SEVERITY_ORDER,
    API_MAP as _API_MAP,
    is_taxonomy_healthy, reload_taxonomy, normalize_risk_tag
)

_CATEGORY_TO_SEVERITY = {}
for api_name, entry in _API_MAP.items():
    cat = entry.get("category")
    if cat and cat not in _CATEGORY_TO_SEVERITY:
        _CATEGORY_TO_SEVERITY[cat] = entry.get("severity", "LOW")

def _pick_higher_risk(a, b):
    if not a:
        return b
    if not b:
        return a
    return a if _RISK_ORDER.get(a, -1) >= _RISK_ORDER.get(b, -1) else b

def count_cfg_complexity(ea):
    """Count branches and loops in a function's control flow graph."""
    f = ida_funcs.get_func(ea)
    if not f: return {"branches": 0, "loops": 0}
    
    # Simple branch count (nodes with >1 exit)
    branches = 0
    loops = 0
    fc = idaapi.qflow_chart_t("", f, f.start_ea, f.end_ea, idaapi.FC_PREDS)
    for i in range(fc.size()):
        node = fc[i]
        succs = list(fc.succs(i))
        if len(succs) > 1:
            branches += 1
            # Heuristic loop detection: check if any successor has a lower index/EA
            for s in succs:
                if fc[s].start_ea <= node.start_ea:
                    loops += 1
                    break
    return {"branches": branches, "loops": loops}

def calculate_data_entropy(ea):
    """Detect high-entropy data blobs referenced by the function."""
    # This is a lightweight check for crypto/packing indicators
    f = ida_funcs.get_func(ea)
    if not f: return 0.0
    
    max_entropy = 0.0
    # Check data references (up to a limit)
    for head in idautils.Heads(f.start_ea, f.end_ea):
        for drefer in idautils.DataRefsFrom(head):
            # Check if it's in a data segment
            seg = ida_segment.getseg(drefer)
            if seg and (seg.type == ida_segment.SEG_DATA or seg.type == ida_segment.SEG_BSS):
                # Sample 256 bytes (or less) to check entropy
                size = 256
                buf = ida_nalt.get_bytes(drefer, size)
                if buf:
                    ent = _calc_buf_entropy(buf)
                    if ent > max_entropy: max_entropy = ent
    return float(f"{max_entropy:.2f}")

def _calc_buf_entropy(data):
    if not data: return 0.0
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def calculate_interest_score(node):
    """Calculate a heuristic 'interest' score to guide AI depth."""
    score = 0
    # Structural indicators
    if node.complexity.get('loops', 0) > 0: score += 15
    if node.complexity.get('branches', 0) > 10: score += 20
    # Data indicators
    if node.entropy > 6.0: score += 40
    # Local Risk indicators (Taxonomy powered)
    tags = api_tax.get_api_tags_for_function(node.ea, getattr(node, 'callees', []))
    if tags:
        for cat in tags.keys():
            sev = api_tax.get_category_severity(cat)
            if sev == "CRITICAL": score += 80
            elif sev == "HIGH": score += 50
            elif sev == "MEDIUM": score += 20
    
    # Priority for leaf wrappers: small functions calling high-risk APIs
    if node.is_leaf and score > 40:
        score += 30 # Focus on "Leaf-Only" wrappers of sensitive APIs
        
    if node.analysis_wave_confidence < 40: score += 10 # Low-confidence renames need more scrutiny
    return score
# ───────────────────────────────────────────────────────────────────────────

# ---------------------------------------------------------------------------
# FuncNode
# ---------------------------------------------------------------------------

def is_library_like(ea, name):
    """Unified library/thunk/import detection used across all graph operations."""
    # 1. Name-based heuristics (Fast, thread-safe)
    if not name: return False
    if is_sys_func(name): return True
    name_l = name.lower()
    if name_l.startswith(("__imp_", "imp_", "j__", "j_")) or name_l.endswith(("@plt", ".plt")):
        return True

    # 2. IDA API checks (Requires execute_sync if in worker thread)
    res = {"is_lib": False}
    def _check_ida():
        # Segment-based check (Handles thunks/imports)
        if not is_valid_seg(ea):
            res["is_lib"] = True
            return
            
        # Function flags check
        f = ida_funcs.get_func(ea)
        if f and (f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK)):
            res["is_lib"] = True
            return

        # Segment name double-check
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg) or ""
            if seg_name.lower() in ('.idata', '.plt', 'extern', '__imp', '.got', '.got.plt'):
                res["is_lib"] = True
                return

    # Use execute_sync for thread safety
    idaapi.execute_sync(_check_ida, idaapi.MFF_READ)
    return res["is_lib"]


class FuncNode:
    def __init__(self, ea, name, depth=0):
        """Initialize a function node for the call graph."""
        self.ea = ea
        self.name = name
        self.depth = depth
        self.callers = []
        self.callees = []
        self.is_library = is_library_like(ea, name)
        self.is_callback = False
        self.is_indirect = False   # Via vtable or indirect reg call
        self.is_recursive = False  # Part of a mutual recursion cycle
        self.has_dynamic_resolving = False # Calls GetProcAddress/LdrGetProcedureAddress
        self.is_leaf = False
        self.status = "Library" if self.is_library else "pending"
        self.risk_tag = "benign" if self.is_library else "pending"
        self.confidence = 100 if self.is_library else 0
        self.line_count = 0
        self.is_unnamed = name.startswith('sub_') or name.startswith('unknown_')
        
        # STATUS TRACKING FOR UI
        self.stage4_status = "PENDING"
        self.stage5_status = "PENDING"
        
        # NEW FIELDS FOR MALICIOUS CODE ANALYSIS PIPELINE
        self.preliminary_analysis = None  # Store Initial Assessment results
        self.context_markers = []         # Malicious code analysis markers from Contextual Refinement
        self.pattern_matches = []         # Attack patterns from Contextual Refinement
        self.semantic_tags = []           # [FILE_IO], [CRYPTO], [INJECTION]
        self.complexity = {"branches": 0, "loops": 0}
        self.entropy = 0.0
        self.analysis_wave_confidence = 0 # Confidence from Stage 3 renaming

    def to_dict(self):
        return {
            "ea": self.ea,
            "name": self.name,
            "depth": self.depth,
            "callers": self.callers,
            "callees": self.callees,
            "is_library": self.is_library,
            "is_callback": self.is_callback,
            "is_indirect": self.is_indirect,
            "is_recursive": self.is_recursive,
            "has_dynamic_resolving": self.has_dynamic_resolving,
            "is_leaf": self.is_leaf,
            "status": self.status,
            "confidence": self.confidence,
            "markers": self.context_markers,
            "patterns": self.pattern_matches,
            "semantic_tags": self.semantic_tags,
            "complexity": self.complexity,
            "entropy": self.entropy,
            "wave_conf": self.analysis_wave_confidence,
            "stage4_status": self.stage4_status,
            "stage5_status": self.stage5_status
        }
# ---------------------------------------------------------------------------
# Graph Functions
# ---------------------------------------------------------------------------

def build_call_graph(entry_ea: int, stop_checker: Optional[Callable[[], bool]] = None, log_fn: Optional[Callable[[str, str], None]] = None) -> Dict[int, FuncNode]:
    """Build a call graph dictionary mapping EA to FuncNode starting from entry_ea."""
    graph = {}
    boundary_eas = []
    
    if log_fn: log_fn(f"Validating entry point at 0x{entry_ea:X}...", "info")

    # Normalize entry point
    res_entry = {"f_entry": None, "is_valid": False, "name": ""}
    def _sync_entry():
        res_entry["f_entry"] = ida_funcs.get_func(entry_ea)
        res_entry["is_valid"] = is_valid_seg(entry_ea)
        res_entry["name"] = idc.get_func_name(entry_ea) or ""
    idaapi.execute_sync(_sync_entry, idaapi.MFF_READ)

    f_entry = res_entry["f_entry"]
    if not res_entry["is_valid"]:
        if log_fn: log_fn(f"Error: Address 0x{entry_ea:X} is not in a valid code segment.", "err")
        return {}

    entry_name = res_entry["name"]
    if is_sys_func(entry_name):
        if log_fn: log_fn(f"Warning: 0x{entry_ea:X} ({entry_name}) appears to be a library/system function. Skipping.", "warn")
        return {}
        
    if f_entry:
        entry_ea = f_entry.start_ea
        if log_fn: log_fn(f"Found target function: {entry_name}", "ok")
    
    if entry_ea == idaapi.BADADDR or entry_ea == 0:
        if log_fn: log_fn(f"Error: Invalid entry point address.", "err")
        return graph

    # Bug #4: Dynamic limits from CONFIG
    MAX_NODES  = getattr(CONFIG, 'max_graph_nodes', 500)
    MAX_QUEUE  = getattr(CONFIG, 'max_queue_size', 5000)
    MAX_DEPTH  = getattr(CONFIG, 'max_graph_depth', 15)
    MAX_CALLEES = getattr(CONFIG, 'max_callees_per_node', 64)

    # Priority queue-like approach: Always process shallower nodes first
    queue = collections.deque([(entry_ea, 0)])
    visited = {entry_ea}
    processed = 0

    if log_fn: log_fn("Starting recursive discovery of custom logic...", "info")

    while queue:
        if stop_checker and stop_checker():
            if log_fn:
                log_fn('Call graph building cancelled by user.', 'warn')
            return {}

        curr_ea, depth = queue.popleft()
        processed += 1
        
        # Bug #4: Early depth termination
        if depth >= MAX_DEPTH:
            continue

        # Progress logging every 50 nodes processed
        if log_fn and processed % 50 == 0:
            log_fn(f"Discovery progress: {len(graph)} nodes identified, {len(queue)} pending in queue...", "info")

        # Ensure current node exists in graph
        if curr_ea not in graph:
            res_name = {"name": f"sub_{curr_ea:x}"}
            def _sync_name():
                res_name["name"] = idc.get_func_name(curr_ea) or idc.get_name(curr_ea) or f"sub_{curr_ea:x}"
            idaapi.execute_sync(_sync_name, idaapi.MFF_READ)
            name = res_name["name"]

            # Still create node for library functions, but we won't recurse into them
            graph[curr_ea] = FuncNode(curr_ea, name, depth)
            if graph[curr_ea].is_library:
                continue
        
        curr_node = graph[curr_ea]
        # Single-pass Dijkstra check: if we found a shorter path, update (unlikely in pure BFS but safe)
        if depth < curr_node.depth:
            curr_node.depth = depth

        res_f = {"func_items": [], "f": None}
        def _sync_f():
            res_f["f"] = ida_funcs.get_func(curr_ea)
            if res_f["f"]:
                res_f["func_items"] = list(idautils.FuncItems(res_f["f"].start_ea))
        idaapi.execute_sync(_sync_f, idaapi.MFF_READ)
        
        f = res_f["f"]
        if not f:
            continue

        # Traverse instructions to find callees
        func_items = res_f["func_items"]
        for item_ea in func_items:
            if stop_checker and stop_checker():
                break
            
            # Direct Code References
            res_crefs = {"refs": []}
            def _sync_crefs():
                res_crefs["refs"] = list(idautils.CodeRefsFrom(item_ea, False))
            idaapi.execute_sync(_sync_crefs, idaapi.MFF_READ)
            
            # Bug #4: Callee fan-out limit
            callee_count = 0
            for ref_ea in res_crefs["refs"]:
                if callee_count >= MAX_CALLEES:
                    if log_fn and callee_count == MAX_CALLEES:
                        log_fn(f"Fan-out limit ({MAX_CALLEES}) reached for 0x{item_ea:X}. Skipping further callees.", "warn")
                    break
                res_callee = {"f": None, "ea": 0, "name": ""}
                def _sync_callee():
                    cf = ida_funcs.get_func(ref_ea)
                    if cf:
                        res_callee["f"] = cf
                        res_callee["ea"] = cf.start_ea
                        res_callee["name"] = idc.get_func_name(cf.start_ea) or idc.get_name(cf.start_ea) or f"sub_{cf.start_ea:x}"
                idaapi.execute_sync(_sync_callee, idaapi.MFF_READ)
                
                callee_f = res_callee["f"]
                if not callee_f: continue
                
                callee_ea = res_callee["ea"]
                if callee_ea == curr_ea: continue

                callee_name = res_callee["name"]
                
                if callee_ea not in graph:
                    if len(graph) < MAX_NODES:
                        graph[callee_ea] = FuncNode(callee_ea, callee_name, depth + 1)
                    else:
                        if callee_ea not in boundary_eas: boundary_eas.append(callee_ea)
                        continue
                
                callee_node = graph[callee_ea]
                if curr_ea not in callee_node.callers: callee_node.callers.append(curr_ea)
                if callee_ea not in curr_node.callees: curr_node.callees.append(callee_ea)
                
                if callee_node.is_library:
                    continue
                callee_count += 1

                if callee_ea not in visited:
                    visited.add(callee_ea)
                    if len(queue) < MAX_QUEUE:
                        queue.append((callee_ea, depth + 1))

            # Indirect Call / Vtable / Data Reference Detection
            res_drefs = {"refs": []}
            def _sync_drefs():
                res_drefs["refs"] = list(idautils.DataRefsFrom(item_ea))
            idaapi.execute_sync(_sync_drefs, idaapi.MFF_READ)
            
            for ref_ea in res_drefs["refs"]:
                res_indirect = {"f": None, "ea": 0, "name": "", "is_valid": False, "is_code": False}
                def _sync_indirect():
                    res_indirect["is_valid"] = is_valid_seg(ref_ea)
                    if not res_indirect["is_valid"]: return
                    
                    seg = ida_segment.getseg(ref_ea)
                    if not seg or seg.type != ida_segment.SEG_CODE: return
                    res_indirect["is_code"] = True
                    
                    cf = ida_funcs.get_func(ref_ea)
                    if cf:
                        res_indirect["f"] = cf
                        res_indirect["ea"] = cf.start_ea
                        res_indirect["name"] = idc.get_func_name(cf.start_ea) or idc.get_name(cf.start_ea) or f"sub_{cf.start_ea:x}"
                idaapi.execute_sync(_sync_indirect, idaapi.MFF_READ)
                
                # Bug #4: Callee fan-out limit (Indirect)
                if callee_count >= MAX_CALLEES:
                    break
                if not res_indirect["is_valid"] or not res_indirect["is_code"]: continue
                callee_f = res_indirect["f"]
                if not callee_f: continue

                callee_ea = res_indirect["ea"]
                if callee_ea == curr_ea: continue

                callee_name = res_indirect["name"]
                
                if callee_ea not in graph:
                    if len(graph) < MAX_NODES:
                        graph[callee_ea] = FuncNode(callee_ea, callee_name, depth + 1)
                        graph[callee_ea].is_callback = True
                        graph[callee_ea].is_indirect = True
                    else:
                        if callee_ea not in boundary_eas: boundary_eas.append(callee_ea)
                        continue
                
                callee_node = graph[callee_ea]
                if curr_ea not in callee_node.callers: callee_node.callers.append(curr_ea)
                if callee_ea not in curr_node.callees: curr_node.callees.append(callee_ea)

                if callee_node.is_library:
                    continue
                callee_count += 1

                if callee_ea not in visited:
                    visited.add(callee_ea)
                    if len(queue) < MAX_QUEUE:
                        queue.append((callee_ea, depth + 1))

    # Detect Mutual Recursion (Cycles)
    def _find_cycles():
        stack = set()
        visited_recursive = set()
        def _dfs(ea):
            if ea in stack:
                # Cycle found, tag parents as recursive
                for s_ea in stack:
                    if s_ea in graph: graph[s_ea].is_recursive = True
                return
            if ea in visited_recursive: return
            visited_recursive.add(ea)
            stack.add(ea)
            if ea in graph:
                for callee in graph[ea].callees:
                    _dfs(callee)
            stack.remove(ea)

        _dfs(entry_ea)

    _find_cycles()

    # Compute Final is_leaf and store boundary info


    for ea, node in graph.items():
        if isinstance(node, FuncNode):
            non_lib_callees = [c_ea for c_ea in node.callees if c_ea in graph and not getattr(graph[c_ea], 'is_library', True)]
            node.is_leaf = (len(non_lib_callees) == 0)

    if log_fn:
        log_fn(f"Graph discovery complete. Analyzed {len(graph)-1} unique functions across {processed} references.", "ok")
        if boundary_eas:
            log_fn(f"Note: Reach exceeded hard cap. {len(boundary_eas)} functions were omitted.", "warn")

    return graph


class DeepAnalyzerConfig:
    MAX_CODE_LINES = getattr(CONFIG, 'deep_max_lines', 200)
    MAX_GRAPH_NODES = getattr(CONFIG, 'max_graph_nodes', 500)
    MAX_QUEUE_SIZE = getattr(CONFIG, 'max_queue_size', 5000)
    MAX_PROMPT_CHARS = 32000 # Hard limit for most LLMs
    MIN_CONFIDENCE_THRESHOLD = getattr(CONFIG, 'high_confidence_threshold', 75)
    MAX_QUALITY_FUNCTIONS = 50 
    MAX_SKIPPED_DISPLAY = 30

_SESSION_OUTPUT_DIR = None

def create_metadata_file(os_path, entry_ea):
    """Create a metadata.json file with binary info and analysis context."""
    import json
    
    metadata = {
        "binary_info": {},
        "analysis_context": {}
    }
    
    # Binary Info
    def _gather_bin_info():
        import ida_ida
        info = idaapi.cvar.inf if hasattr(idaapi, 'cvar') and hasattr(idaapi.cvar, 'inf') else None
        procname = ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else (getattr(info, 'procname', 'unknown') if info else 'unknown')
        is_64bit = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else (info.is_64bit() if hasattr(info, 'is_64bit') else False)
        
        md5_func = getattr(ida_nalt, 'retrieve_input_file_md5', getattr(ida_nalt, 'eval_file_md5', lambda: b''))
        sha_func = getattr(ida_nalt, 'retrieve_input_file_sha256', getattr(ida_nalt, 'eval_file_sha256', lambda: b''))
        
        metadata["binary_info"] = {
            "input_path": idaapi.get_input_file_path(),
            "md5": md5_func(),
            "sha256": sha_func(),
            "arch": procname,
            "is_64bit": is_64bit
        }
        
        # Hash retrieval is messy across IDA versions; simplified fallback if failing
        if not metadata["binary_info"]["md5"] or not isinstance(metadata["binary_info"]["md5"], str):
             metadata["binary_info"]["md5"] = "unknown"
        if not metadata["binary_info"]["sha256"] or not isinstance(metadata["binary_info"]["sha256"], str):
             metadata["binary_info"]["sha256"] = "unknown"
             
        # Get func name
        metadata["analysis_context"]["entry_name"] = idc.get_func_name(entry_ea) if entry_ea else "unknown"
        
    idaapi.execute_sync(_gather_bin_info, idaapi.MFF_READ)
    
    # Context
    metadata["analysis_context"].update({
        "timestamp": datetime.datetime.now().isoformat(),
        "entry_ea": "0x%X" % entry_ea if entry_ea else "unknown",
        "ai_provider": getattr(CONFIG, 'active_provider', 'unknown'),
        "ai_model": getattr(CONFIG, 'model', 'unknown'),
        "pseudonote_version": __version__ if '__version__' in globals() else "1.0.0"
    })
    
    try:
        with open(os.path.join(os_path, "metadata.json"), 'w') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        print(f"[PseudoNote] Warning: Could not create metadata.json: {e}")

def get_output_dir(entry_ea=None, create=True, force_new=False):
    """Get or create the output directory for summary artifacts."""
    global _SESSION_OUTPUT_DIR
    
    if _SESSION_OUTPUT_DIR and not force_new:
        if create and not os.path.exists(_SESSION_OUTPUT_DIR):
             try: os.makedirs(_SESSION_OUTPUT_DIR)
             except: pass
        return _SESSION_OUTPUT_DIR

    res = {"path": None, "root": None, "func_name": "unknown", "target_ea": None}
    def _sync():
        res["path"] = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        res["root"] = idaapi.get_root_filename()
        target_ea = entry_ea if entry_ea is not None else idc.get_screen_ea()
        res["target_ea"] = target_ea
        res["func_name"] = idc.get_func_name(target_ea) or 'unknown'

    idaapi.execute_sync(_sync, idaapi.MFF_READ)
    idb_path = res["path"]
    target_ea = res["target_ea"]
    func_name = res["func_name"]
    
    # Determine filename for the folder name
    raw_name = "unknown"
    if idb_path:
        raw_name = os.path.splitext(os.path.basename(idb_path))[0]
    elif res.get("root"):
        raw_name = os.path.splitext(str(res["root"]))[0]
    
    # Sanitize name
    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', str(raw_name))
    
    # Target-Locked Function Name
    safe_func_name = re.sub(r'[^A-Za-z0-9_]', '_', func_name)
    
    # Session Versioning (Timestamp)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"DeepAnalyzer_{safe_func_name}_{safe_name}_{timestamp}"
    
    if not idb_path:
        base_dir = os.path.join(os.path.expanduser("~"), folder_name)
    else:
        base_dir = os.path.join(os.path.dirname(idb_path), folder_name)
    
    if create:
        for sub in ["", "decomp", "analysis"]:
            d = os.path.join(base_dir, sub)
            if not os.path.exists(d):
                try:
                    os.makedirs(d)
                except Exception as e:
                    print(f"[PseudoNote] ERROR: Could not create directory {d}: {e}")
        
        # Create metadata info.json
        create_metadata_file(base_dir, target_ea)
        # Store as session dir
        _SESSION_OUTPUT_DIR = base_dir

    return base_dir

def save_graph_to_disk(graph, output_dir, entry_ea=0):
    """Serialize the call graph and metadata to a JSON file."""
    if not isinstance(graph, dict):
        print("[PseudoNote] Error: save_graph_to_disk received non-dict object: %s" % type(graph))
        return

    nodes_list = []
    for ea, node in graph.items():
        if hasattr(node, "to_dict"):
            nodes_list.append(node.to_dict())
        else:
            nodes_list.append(node)
    
    data = {
        "entry_ea": entry_ea,
        "nodes": nodes_list
    }
    
    try:
        path = os.path.join(output_dir, "graph.json")
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("[PseudoNote] Error saving graph: %s" % e)

def load_graph_from_disk(output_dir):
    """Load the call graph from disk if it exists and reconstruct FuncNode objects."""
    path = os.path.join(output_dir, "graph.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            raw = json.load(f)
        
        reconstructed = {}
        entry_ea = raw.get("entry_ea")
        nodes_list = raw.get("nodes", [])
        
        for d in nodes_list:
            try:
                ea = d.get("ea")
                if not ea:
                    continue
                node = FuncNode(ea, d.get("name", f"sub_{ea:X}"))
                node.depth = d.get("depth", 0)
                node.callers = d.get("callers", [])
                node.callees = d.get("callees", [])
                node.is_library = d.get("is_library", False)
                node.is_unnamed = d.get("is_unnamed", False)
                node.is_leaf = d.get("is_leaf", False)
                node.status = d.get("status", "pending")
                node.confidence = d.get("confidence", 0)
                node.line_count = d.get("line_count", 0)
                node.is_callback = d.get("is_callback", False)
                node.preliminary_analysis = d.get("preliminary_analysis")
                node.context_markers = d.get("context_markers", [])
                node.pattern_matches = d.get("pattern_matches", [])
                node.semantic_tags = d.get("semantic_tags", [])
                node.complexity = d.get("complexity", {"branches": 0, "loops": 0})
                node.entropy = d.get("entropy", 0.0)
                node.analysis_wave_confidence = d.get("wave_conf", 0)
                node.stage4_status = d.get("stage4_status", "PENDING")
                node.stage5_status = d.get("stage5_status", "PENDING")
                
                # Rescue logic for loaded graphs
                if node.status == "analyzed":
                    node.stage4_status = "OK"
                    node.stage5_status = "OK"
                elif node.status == "preliminary":
                    node.stage4_status = "OK"
                
                reconstructed[ea] = node
            except:
                continue
        return reconstructed
    except:
        return None

# ---------------------------------------------------------------------------
# Wave Functions
# ---------------------------------------------------------------------------

def get_rename_waves(graph):
    """Compute waves of functions to rename, from leaves up to the entry point."""
    waves = []
    
    # Target only unnamed non-library nodes or those with generic names
    generic_prefixes = ("sub_", "unknown_", "wrap_", "tiny_func_", "nullsub_")
    unnamed_eas = {
        ea for ea, node in graph.items() 
        if isinstance(node, FuncNode) and 
        (node.is_unnamed or any(node.name.lower().startswith(p) for p in generic_prefixes)) and 
        not node.is_library
    }
    resolved = set()
    
    # Bottom-up round system: Iteratively find leaf-like functions
    while True:
        current_wave = []
        for ea in unnamed_eas:
            if ea in resolved:
                continue
            
            node = graph[ea]
            # A node is a leaf if all its non-library callees are already renamed or outside our focus
            all_resolved = True
            for callee_ea in node.callees:
                callee_node = graph.get(callee_ea)
                if not callee_node or getattr(callee_node, 'is_library', True):
                    continue
                # If callee is still unnamed and not in our resolved list, this node isn't a leaf yet
                if (getattr(callee_node, 'is_unnamed', False) or "sub_" in callee_node.name.lower()) and callee_ea not in resolved:
                    all_resolved = False
                    break
            
            if all_resolved:
                current_wave.append(ea)
        
        if not current_wave:
            break
            
        waves.append(current_wave)
        resolved.update(current_wave)
        
        # Progress check to handle cycles
        if len(resolved) == len(unnamed_eas):
            break

    # Final "leftover" wave for any nodes that couldn't be resolved (cycles)
    remaining = unnamed_eas - resolved
    if remaining:
        waves.append(list(remaining))
        
    return waves

def get_analysis_waves(graph, candidates_eas):
    """Compute waves of functions to analyze, from leaves up to the entry point."""
    waves = []
    target_eas = set(candidates_eas)
    resolved = set()
    
    # Bottom-up round system: Iteratively find leaf-like functions
    while True:
        current_wave = []
        for ea in target_eas:
            if ea in resolved: continue
            
            node = graph[ea]
            # A node is a leaf if all its non-library callees are already analyzed or outside our focus
            all_resolved = True
            for callee_ea in node.callees:
                callee_node = graph.get(callee_ea)
                if not callee_node or callee_node.is_library:
                    continue
                # If callee is in our target set and not yet resolved, this node isn't a leaf yet
                if callee_ea in target_eas and callee_ea not in resolved:
                    all_resolved = False
                    break
            
            if all_resolved:
                current_wave.append(ea)
        
        if not current_wave:
            break
            
        waves.append(current_wave)
        resolved.update(current_wave)
        
        if len(resolved) == len(target_eas):
            break

    # Final "leftover" wave for any nodes that couldn't be resolved (cycles)
    remaining = target_eas - resolved
    if remaining:
        waves.append(list(remaining))
        
    return waves

# ---------------------------------------------------------------------------
# Config Helper
# ---------------------------------------------------------------------------

def build_ai_cfg_from_config():
    """Build the configuration dictionary required for ai_request."""
    provider = CONFIG.active_provider.lower() if CONFIG.active_provider else "openai"
    
    cfg = {
        "provider": provider,
        "api_url": "",
        "api_key": "",
        "model": "",
        "parallel_workers": getattr(CONFIG, 'deep_parallel_workers', 5)
    }

    if provider == "openai":
        cfg["api_url"] = CONFIG.openai_url
        cfg["api_key"] = CONFIG.openai_key
        cfg["model"] = CONFIG.openai_model
    elif provider == "anthropic":
        cfg["api_url"] = CONFIG.anthropic_url
        cfg["api_key"] = CONFIG.anthropic_key
        cfg["model"] = CONFIG.anthropic_model
    elif provider == "deepseek":
        cfg["api_url"] = CONFIG.deepseek_url
        cfg["api_key"] = CONFIG.deepseek_key
        cfg["model"] = CONFIG.deepseek_model
    elif provider == "ollama":
        cfg["api_url"] = CONFIG.ollama_host
        cfg["api_key"] = "ollama"
        cfg["model"] = CONFIG.ollama_model
    elif provider == "lmstudio":
        cfg["api_url"] = CONFIG.lmstudio_url
        cfg["api_key"] = CONFIG.lmstudio_key
        cfg["model"] = CONFIG.lmstudio_model
    elif provider in ("custom", "openaicompatible"):
        cfg["api_url"] = CONFIG.custom_url
        cfg["api_key"] = CONFIG.custom_key
        cfg["model"] = CONFIG.custom_model
    else:
        # Fallback to OpenAI
        cfg["provider"] = "openai"
        cfg["api_url"] = CONFIG.openai_url
        cfg["api_key"] = CONFIG.openai_key
        cfg["model"] = CONFIG.openai_model
        
    return cfg

# === SECTION 2: RENAME PASS LOGIC & WORKER THREAD ===

# --- FILE ARTIFACT HELPERS MOVED TO report_generator.py ---

def rename_single_function(ea: int, node: FuncNode, graph: Dict[int, FuncNode], output_dir: str, ai_cfg: dict, log_fn: Callable, 
                           char_count_cb: Optional[Callable] = None, cooldown_cb: Optional[Callable] = None, 
                           update_cb: Optional[Callable] = None, code: Optional[str] = None, 
                           strings: Optional[List[str]] = None, state_cb: Optional[Callable] = None, 
                           do_var_rename: bool = True) -> Tuple[str, int]:
    """Analyze a single function and apply a descriptive name/variables to it in IDA."""
    # Step 1: Gather data if not provided
    if code is None or strings is None:
        try:
            code = get_code_fast(ea)
            if not code or not isinstance(code, str):
                log_fn(f"Decompilation failed for 0x{ea:X} - skipping", 'warn')
                node.status = "decompilation_failed"
                return node.name, 0
            strings = get_strings_fast(ea) or []
        except Exception as e:
            log_fn(f"Error fetching code for 0x{ea:X}: {e}", 'err')
            node.status = "error"
            return node.name, 0
    
    # Ensure code is string
    if isinstance(code, list): code = "\n".join(code)
    code_str = str(code)

    if len(code_str.strip()) < 10:
        log_fn("Skipping 0x%X: Empty or trivial code" % ea, 'warn')
        final_name = "tiny_func_0x%X" % ea
        def _do_set_tiny():
            ida_name.set_name(ea, final_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
        idaapi.execute_sync(_do_set_tiny, idaapi.MFF_WRITE)
        node.name = final_name
        node.status = "renamed"
        node.confidence = 5
        save_graph_to_disk(graph, output_dir, entry_ea=node.ea) # approximation
        return final_name, 5
    
    # Step 2: Initial save
    save_decompiled_to_disk(ea, node.name, code, output_dir)
    
    # Step 3: Find named callees for context
    named_callees = []
    for c_ea in node.callees:
        c_node = graph.get(c_ea)
        if c_node and not c_node.is_unnamed and not c_node.is_library:
            named_callees.append(c_node.name)
            
    # Step 4: Build prompt
    var_instr = ""
    if do_var_rename:
        var_instr = "5. Also suggest meaningful names for local variables (v1, a1, etc.) if their purpose is clear."

    prompt = f"""You are a reverse engineering assistant analyzing decompiled code. Suggest a descriptive function name based ONLY on observable operations.

GROUNDING RULES:
1. Base the name ONLY on what you can see: API calls, string literals, arithmetic operations, control flow.
2. Do NOT infer purpose from context if the code doesn't show it.
3. If the function is unclear, use generic names like "wrapper" or "helper".
4. Do NOT invent functionality.
5. Identify variables or global data with generic names (v1, a1, result, qword_1234, dword_5678) and suggest descriptive names for them based on usage.

Known named callees:
{chr(10).join(f'  - {n}' for n in named_callees) if named_callees else '  (none)'}

String literals:
{chr(10).join(f'  - {s}' for s in strings[:8]) if strings else '  (none)'}

Decompiled pseudocode:
{truncate_code_lines(code) if code else '(not available)'}

STRICT OUTPUT FORMAT:
{{
  "suggested_name": "snake_case_name",
  "confidence": 85,
  "var_renames": {{"v1": "new_name"}} // only if obvious
}}

Reply with ONLY the JSON object."""
    
    if char_count_cb:
        char_count_cb(len(prompt), 32000)

    # Step 5: Request AI analysis
    log_fn("Requesting AI analysis for 0x%X (Var rename: %s)..." % (ea, do_var_rename), 'info')
    if state_cb: state_cb("requesting")
    
    # We use a wrapper to emit 'receiving' on first chunk if possible
    first_chunk = [True]
    def _chunk_cb(c):
        if first_chunk[0]:
            if state_cb: state_cb("receiving")
            first_chunk[0] = False
        if char_count_cb: char_count_cb(0, 0) # Trigger activity

    response = _validated_ai_request(
        ai_cfg, 
        prompt, 
        sys_prompt="You are a technical reverse engineering assistant. Analyze decompiled code factually.", 
        logger=lambda m: log_fn(m, 'warn'),
        on_cooldown=cooldown_cb,
        on_chunk=_chunk_cb
    )
    if state_cb: state_cb("idle")
    log_fn("Received AI response for 0x%X." % ea, 'info')
    
    if not response or not response.strip():
        log_fn("AI returned empty response for 0x%X" % ea, 'warn')
        node.status = "skipped"
        return node.name, 0
    
    # Step 6: Parse response (JSON)
    suggested_name = "unresolved"
    confidence = 10
    var_renames = {}
    
    try:
        r_text = response.strip('` \n')
        if r_text.find('{') != -1: 
            item = json.loads(r_text[r_text.find('{'):r_text.rfind('}')+1])
            suggested_name = item.get("suggested_name", "unresolved")
            confidence = int(item.get("confidence", 0))
            var_renames = item.get("var_renames", {})
    except:
        # Fallback to old regex if JSON fails
        match = re.search(r'([A-Za-z_][A-Za-z0-9_]{1,39})\s*\[(\d+)\]', response)
        if match:
            suggested_name = match.group(1)
            confidence = int(match.group(2))
    
    raw_name = suggested_name
    
    if not raw_name or raw_name == "unresolved":
        log_fn("AI returned empty or unresolved response for 0x%X" % ea, 'warn')
        node.status = "skipped"
        return node.name, 0
        
    # Step 7: Finalize name (respecting CONFIG options for prefix / address)
    raw_name = re.sub(r'[^A-Za-z0-9_]', '_', raw_name)
    if raw_name and raw_name[0].isdigit(): raw_name = "_" + raw_name
    # Apply prefix if configured
    prefix = ""
    if getattr(CONFIG, 'deep_use_prefix', False) and getattr(CONFIG, 'deep_prefix', ''):
        prefix = CONFIG.deep_prefix
    # Apply address postfix if configured
    if getattr(CONFIG, 'deep_append_address', True):
        if getattr(CONFIG, 'deep_use_0x', False):
            addr_suffix = "_0x%X" % ea
        else:
            addr_suffix = "_%X" % ea
    else:
        addr_suffix = ""
    final_name = "%s%s%s" % (prefix, raw_name[:80], addr_suffix)
    final_name = final_name[:96]
    
    # Step 8: Apply to IDA
    try:
        res_set = {"success": False}
        def _do_rename():
            try:
                # Mark as dirty to ensure decompiler sees update
                if idc.get_func_name(ea):
                    ida_hexrays.mark_cfunc_dirty(ea)
                res_set["success"] = ida_name.set_name(ea, final_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
            except:
                res_set["success"] = False
        
        idaapi.execute_sync(_do_rename, idaapi.MFF_WRITE)
        
        old_name_before = node.name
        if res_set["success"]:
            node.name = final_name
            node.is_unnamed = False
            node.status = "renamed"
            node.confidence = confidence
            
            # Apply Variable Renames if enabled
            if do_var_rename and var_renames:
                clean_vars = extract_variable_renames_from_analysis({"var_renames": var_renames}, code)
                apply_variable_renames_in_ida(ea, clean_vars, log_fn)

            log_fn("Renamed 0x%X -> %s [%d%%]" % (ea, final_name, confidence), 'ok')
        else:
            log_fn("IDA failed to set name %s for 0x%X" % (final_name, ea), 'warn')
            final_name = node.name
            confidence = 0
    except Exception as e:
        import traceback
        log_fn("Exception while renaming 0x%X: %s\n%s" % (ea, e, traceback.format_exc()), 'err')
        final_name = node.name
        confidence = 0
            
    # Step 9: Post-Rename Refresh & Save (Readable C Code)
    def _fetch_fresh_code():
        ida_hexrays.mark_cfunc_dirty(ea) # Force fresh decompilation
        return get_code_fast(ea) or (code if 'code' in locals() else "")
    
    fresh_code = idaapi.execute_sync(_fetch_fresh_code, idaapi.MFF_READ)
    save_decompiled_to_disk(ea, final_name, fresh_code, output_dir)
    
    idaapi.execute_sync(lambda: save_to_idb(ea, "renamed_by_analyzer", tag=84), idaapi.MFF_WRITE)
    if update_cb: update_cb(ea, old_name_before, final_name, confidence)
    
    # Step 11: Sync graph
    save_graph_to_disk(graph, output_dir)
    
    return final_name, confidence

def rename_batch_functions(batch_data: List[Tuple], graph: Dict[int, FuncNode], output_dir: str, ai_cfg: dict, log_fn: Callable, 
                           char_count_cb: Optional[Callable] = None, cooldown_cb: Optional[Callable] = None, 
                           update_cb: Optional[Callable] = None, state_cb: Optional[Callable] = None, 
                           do_var_rename: bool = True) -> List[Tuple[int, str, int]]:
    if not batch_data: return []
    
    var_instr = ""
    if do_var_rename:
        var_instr = " Also suggest meaningful names for local variables or global data (v1, a1, qword_1234, etc.) if their purpose is clear."

    prompt = f"You are analyzing multiple small functions. For EACH function, suggest a descriptive name based ONLY on observable operations.{var_instr}\n\n"
    prompt += "CRITICAL: Base names ONLY on what you see: API calls, strings, arithmetic operations. Do NOT speculate.\n\n"
    for idx, (ea, node, code, strings) in enumerate(batch_data):
        prompt += f"--- Function {idx} (0x{ea:X}) ---\n"
        prompt += f"Strings: {', '.join(strings[:3]) if strings else 'none'}\n"
        prompt += f"Code:\n{truncate_code_lines(code)}\n\n"
    prompt += "Reply ONLY with JSON. Format: {\"0\": {\"suggested_name\": \"name\", \"confidence\": 75, \"var_renames\": {\"v1\": \"new_name\"}}, \"1\": ...}\n"
    prompt += "NEVER invent functionality. If unclear, use 'helper' or 'wrapper'."
    if char_count_cb: char_count_cb(len(prompt), 32000)
    
    log_fn("Requesting batch AI analysis for %d functions (Var rename: %s)..." % (len(batch_data), do_var_rename), 'info')
    if state_cb: state_cb("requesting")
    
    # We use a wrapper to emit 'receiving' on first chunk if possible
    received = [False]
    def _batch_chunk_cb(c):
        if not received[0]:
            if state_cb: state_cb("receiving")
            received[0] = True
        if char_count_cb: char_count_cb(0, 0)

    response = _validated_ai_request(
        ai_cfg, 
        prompt, 
        sys_prompt="You are a technical reverse engineering assistant. Base names ONLY on observable operations.", 
        logger=lambda m: log_fn(m, 'warn'), 
        on_cooldown=cooldown_cb, 
        on_chunk=_batch_chunk_cb
    )
    if state_cb: state_cb("idle")
    log_fn("Received batch AI response.", 'info')
    
    parsed = {}
    try:
        r = response.strip('` \n')
        if r.find('{') != -1: parsed = json.loads(r[r.find('{'):r.rfind('}')+1])
    except:
        log_fn("Failed to parse batch JSON response.", "warn")
        
    results = []
    for idx, (ea, node, code, strings) in enumerate(batch_data):
        item = parsed.get(str(idx), {})
        raw_name = item.get("suggested_name", "") or ""
        if not raw_name.strip():
            raw_name = "unresolved"
        confidence = int(item.get("confidence", 0))
        raw_name = re.sub(r'[^A-Za-z0-9_]', '_', raw_name)
        if raw_name and raw_name[0].isdigit(): raw_name = "_" + raw_name
        # Apply prefix / address postfix per CONFIG
        b_prefix = ""
        if getattr(CONFIG, 'deep_use_prefix', False) and getattr(CONFIG, 'deep_prefix', ''):
            b_prefix = CONFIG.deep_prefix
        if getattr(CONFIG, 'deep_append_address', True):
            if getattr(CONFIG, 'deep_use_0x', False):
                b_addr = "_0x%X" % ea
            else:
                b_addr = "_%X" % ea
        else:
            b_addr = ""
        final_name = ("%s%s%s" % (b_prefix, raw_name[:80], b_addr))[:96]
        try:
            res_set = {"success": False}
            def _do_rename():
                try: 
                    if idc.get_func_name(ea):
                        ida_hexrays.mark_cfunc_dirty(ea)
                    res_set["success"] = ida_name.set_name(ea, final_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
                except: res_set["success"] = False
            idaapi.execute_sync(_do_rename, idaapi.MFF_WRITE)
            old_name_before = node.name
            if res_set["success"]:
                node.name = final_name
                node.is_unnamed = False
                node.status = "renamed"
                node.confidence = confidence

                if do_var_rename:
                    v_renames = item.get("var_renames", {})
                    if v_renames:
                        clean_vars = extract_variable_renames_from_analysis({"var_renames": v_renames}, code)
                        apply_variable_renames_in_ida(ea, clean_vars, log_fn)
                
                log_fn("Batch Renamed 0x%X -> %s [%d%%]" % (ea, final_name, confidence), 'ok')
            else:
                final_name = node.name
                confidence = 0
        except:
            final_name = node.name
            confidence = 0
            
        idaapi.execute_sync(lambda ea=ea: save_to_idb(ea, "renamed_by_analyzer", tag=84), idaapi.MFF_WRITE)
        save_decompiled_to_disk(ea, final_name, code, output_dir)
        if update_cb: update_cb(ea, old_name_before, final_name, confidence)
        results.append((ea, final_name, confidence))
    save_graph_to_disk(graph, output_dir)
    return results



class RenameWorker(QThread):
    finished_signal = Signal(int)           # (total_renamed count)
    log_signal = Signal(str, str)           # (message, level)
    progress_signal = Signal(int, int, str)      # (current, total, func_name)
    func_updated_signal = Signal(object, str, str, int)  # (ea, old_name, new_name, confidence)
    cooldown_progress_signal = Signal(int, int)  # (current, total)
    char_count_signal = Signal(int, int)         # (current, max)
    llm_state_signal = Signal(str)               # (state: 'requesting'|'receiving'|'idle')
    stage_signal = Signal(str)                   # (stage_name)
    graph_ready_signal = Signal(object)            # (graph)

    def __init__(self, entry_ea, do_var_rename=True):
        """Initialize worker thread with an entry point EA."""
        super(RenameWorker, self).__init__()
        self.entry_ea = entry_ea
        self.do_var_rename = do_var_rename
        self._stop = False
        self.total_renamed = 0

    def stop(self):
        """Request a stop of the worker and the AI requests."""
        self._stop = True
        _ai_mod.AI_CANCEL_REQUESTED = True

    def run(self):
        """Main orchestrator for the rename pass."""
        try:
            ai_cfg = build_ai_cfg_from_config()
            def log_fn(msg, lvl='info'): 
                self.log_signal.emit(msg, lvl)

            log_fn("\n" + "=" * 40 + "\n# PHASE 1: DISCOVERY & PREPARATION\n" + "=" * 40, "info")
            
            self.stage_signal.emit("STAGE 1 - ENVIRONMENT SETUP")
            log_fn("\n" + "="*15 + " STAGE 1 - ENVIRONMENT SETUP " + "="*15, "info")
            try:
                output_dir = get_output_dir()
                log_fn(f"Workspace initialized: {output_dir}", "ok")
                
                res_env = {"bin_path": ""}
                def _sync_env():
                    res_env["bin_path"] = idc.get_idb_path()
                idaapi.execute_sync(_sync_env, idaapi.MFF_READ)
                bin_path = res_env["bin_path"]
                
                log_fn(f"Analyzing binary: {os.path.basename(bin_path)}", "info")
            except Exception as e:
                log_fn(f"Failed to initialize environment: {e}", "err")
                return

            self.stage_signal.emit("STAGE 2 - RECURSIVE CALL GRAPH DISCOVERY")
            log_fn("\n" + "="*15 + " STAGE 2 - RECURSIVE CALL GRAPH DISCOVERY " + "="*15, "info")
            
            res = {"graph": None}
            def _sync_build():
                try:
                    res["graph"] = build_call_graph(self.entry_ea, stop_checker=lambda: self._stop, log_fn=log_fn)
                except Exception as e:
                    import traceback
                    log_fn(f"Fatal error during call graph discovery:\n{traceback.format_exc()}", "err")
                    res["graph"] = {}

            idaapi.execute_sync(_sync_build, idaapi.MFF_READ)
            graph = res["graph"]
            if self._stop:
                log_fn("Stage 2 cancelled by user.", "warn")
                self.finished_signal.emit(0)
                return
            if not graph:
                log_fn("Error: Call graph is empty. Ensure the entry point is valid and reachable.", "err")
                self.finished_signal.emit(0)
                return
            
            self.graph = graph 
            self.graph_ready_signal.emit(graph)
            
            # Persist graph early
            idaapi.execute_sync(lambda: save_graph_to_disk(graph, output_dir, entry_ea=self.entry_ea), idaapi.MFF_READ)

            waves = get_rename_waves(graph)
            unnamed_count = sum(len(w) for w in waves)
            self.stage_signal.emit("STAGE 3 - Initial function and variable renaming")
            log_fn("\n" + "="*15 + " STAGE 3 - INITIAL FUNCTION AND VARIABLE RENAMING " + "="*15, "info")
            
            if unnamed_count == 0:
                log_fn("Discovery: No generic function names (sub_*) found. Analysis proceeding with existing names.", "ok")
            else:
                log_fn(f"Discovery: Identified {unnamed_count} functions for renaming across {len(waves)} execution waves.", "info")

            for i, wave in enumerate(waves):
                if self._stop or _ai_mod.AI_CANCEL_REQUESTED:
                    break
                
                log_fn(f"-> Round {i+1}/{len(waves)}: Processing {len(wave)} leaf functions...", "info")
                self.progress_signal.emit(0, len(wave), "")
                
                res_data = {}
                def _gather_wave():
                    for ea in wave:
                        if self._stop: break
                        c = get_code_fast(ea) or ""
                        s = get_strings_fast(ea)
                        res_data[ea] = {"code": c, "strings": s}
                idaapi.execute_sync(_gather_wave, idaapi.MFF_READ)

                wave_tasks = []
                current_batch = []
                
                for ea in wave:
                    node = graph.get(ea)
                    if not node: continue
                    d = res_data.get(ea, {"code":"", "strings":[]})
                    lc = len(d["code"].splitlines())
                    if 10 <= len(d["code"].strip()) and lc <= 20:
                        current_batch.append((ea, node, d["code"], d["strings"]))
                        if len(current_batch) >= 5:
                            wave_tasks.append(("batch", current_batch))
                            current_batch = []
                    else:
                        wave_tasks.append(("single", (ea, d)))
                        
                if current_batch:
                    wave_tasks.append(("batch", current_batch))

                futures = []
                # Ensure it's an int and at least 1
                try: 
                    max_workers = int(ai_cfg.get('parallel_workers', 1))
                except (ValueError, TypeError): 
                    max_workers = 1
                if max_workers < 1: max_workers = 1
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for task_type, payload in wave_tasks:
                        if task_type == "single":
                            ea, d = payload
                            node = graph.get(ea)
                            if not node: continue
                            node.status = "in_progress"
                            self.func_updated_signal.emit(ea, node.name, node.name, 0)
                            
                            def _single_wrapper(ea_val=ea, node_val=node, data_val=d):
                                if self._stop or _ai_mod.AI_CANCEL_REQUESTED: return [(ea_val, node_val.name, 0)]
                                # Log attempt
                                try:
                                    res = rename_single_function(
                                        ea_val, node_val, graph, output_dir, ai_cfg, log_fn,
                                        char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                                        cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                                        update_cb=lambda u_ea, u_old, u_new, u_conf: self.func_updated_signal.emit(u_ea, u_old, u_new, u_conf),
                                        code=data_val["code"],
                                        strings=data_val["strings"],
                                        state_cb=lambda s: self.llm_state_signal.emit(s),
                                        do_var_rename=self.do_var_rename
                                    )
                                    new_name, conf = res
                                    if conf > 0 and new_name:
                                        node_val.analysis_wave_confidence = conf
                                    return [(ea_val, node_val.name, conf)]
                                except Exception as e:
                                    log_fn(f"   [-] AI Rename failed for 0x{ea_val:X}: {e}", "err")
                                    return [(ea_val, node_val.name, 0)]
                            futures.append(executor.submit(_single_wrapper))
                        else:
                            batch = payload
                            for ea, node, _, _ in batch:
                                node.status = "in_progress"
                                self.func_updated_signal.emit(ea, node.name, node.name, 0)
                                
                            def _batch_wrapper(b=batch):
                                if self._stop or _ai_mod.AI_CANCEL_REQUESTED: return [(ea, n.name, 0) for ea, n, _, _ in b]
                                try:
                                    results = rename_batch_functions(
                                        b, graph, output_dir, ai_cfg, log_fn,
                                        char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                                        cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                                        update_cb=lambda u_ea, u_old, u_new, u_conf: self.func_updated_signal.emit(u_ea, u_old, u_new, u_conf),
                                        state_cb=lambda s: self.llm_state_signal.emit(s),
                                        do_var_rename=self.do_var_rename
                                    )
                                    for br_ea, br_name, br_conf in results:
                                        if br_conf > 0:
                                            if br_ea in graph: graph[br_ea].analysis_wave_confidence = br_conf
                                    return results
                                except Exception as e:
                                    log_fn(f"   [-] AI Batch Rename failed: {e}", "err")
                                    return [(ea, n.name, 0) for ea, n, _, _ in b]
                            futures.append(executor.submit(_batch_wrapper))

                    completed = 0
                    for f in concurrent.futures.as_completed(futures):
                        if self._stop or _ai_mod.AI_CANCEL_REQUESTED:
                            break
                        try:
                            results = f.result()
                            for res_ea, res_name, res_conf in results:
                                if res_conf > 0:
                                    self.total_renamed += 1
                                # Signal already emitted via update_cb in worker loop
                                completed += 1
                                self.progress_signal.emit(completed, len(wave), res_name)
                        except Exception as ex:
                            import traceback
                            log_fn("Error on task: %s\n%s" % (ex, traceback.format_exc()), 'err')
                            
                        # No cooldown during rename pass

                if self._stop or _ai_mod.AI_CANCEL_REQUESTED:
                    break

            # Final persistence
            save_graph_to_disk(graph, output_dir, entry_ea=self.entry_ea)
            log_fn("Rename pass complete. %d functions renamed." % self.total_renamed, "ok")
            self.finished_signal.emit(self.total_renamed)

        except Exception as e:
            import traceback
            self.log_signal.emit("Worker Fatal Exception: %s\n%s" % (e, traceback.format_exc()), "err")

# === SECTION 3: ANALYSIS PASS, MARKDOWN WRITER & REFINEMENT ===

# load_decompiled_from_disk moved to report_generator.py



# In-memory cache so we don't call load_from_idb inside build_known_functions_digest
# on every single analysis request. Updated by analyze_single_function on completion.
# Bug #6: Cache deserialized objects to reduce JSON overhead
_analysis_cache = {}  # ea -> full dict result (deserialized)
_one_liner_cache = {} # ea -> short string


def build_known_functions_digest(graph, analyzed_eas):
    """Summarize already analyzed functions for AI context with semantic tags."""
    if not analyzed_eas:
        return ""
    MAX_DIGEST = 20
    MAX_ONE_LINER = 80
    lines = []
    # Show the most recently analyzed (highest-depth = deeper callees first)
    sorted_eas = sorted(list(analyzed_eas), key=lambda x: graph[x].depth if x in graph else 0, reverse=True)
    for ea in sorted_eas[:MAX_DIGEST]:
        node = graph.get(ea)
        if not node: continue
        tags_list = []
        if node.semantic_tags:
            for t in node.semantic_tags:
                if len(tags_list) >= 3: break
                tags_list.append(str(t))
        tags_str = f" [{' '.join(tags_list)}]" if tags_list else ""
        raw_one_liner = str(_analysis_cache.get(ea, "(pending)"))
        one_liner = raw_one_liner[:MAX_ONE_LINER] if len(raw_one_liner) > MAX_ONE_LINER else raw_one_liner
        lines.append(f"  - {node.name}{tags_str}: {one_liner}")
    return "Context (recently analyzed routines):\n" + "\n".join(lines) + "\n"

# === SECTION A: LIVE IDA RENAMING DURING ANALYSIS ===

def extract_variable_renames_from_analysis(result, code):
    """Clean and validate variable renames suggested by the LLM."""
    raw_renames = result.get("var_renames", {})
    if not isinstance(raw_renames, dict):
        return {}
    
    C_KEYWORDS = {
        'auto','break','case','char','const','continue','default','do',
        'double','else','enum','extern','float','for','goto','if','inline',
        'int','long','register','restrict','return','short','signed',
        'sizeof','static','struct','switch','typedef','union','unsigned',
        'void','volatile','while','_Bool','_Complex','_Imaginary'
    }
    
    clean_map = {}
    for old_name, new_name in raw_renames.items():
        if not old_name or not new_name:
            continue
        old_name = str(old_name).strip()
        new_name = str(new_name).strip()
        if old_name == new_name:
            continue
            
        # Sanitize new name
        sanitized = re.sub(r'[^A-Za-z0-9_]', '_', str(new_name))
        if not sanitized or sanitized[0].isdigit():
            sanitized = '_' + sanitized
        sanitized = sanitized[:60]
        
        if sanitized in C_KEYWORDS:
            continue
            
        clean_map[str(old_name)] = sanitized
        
    return clean_map

def apply_variable_renames_in_ida(ea, var_map, log_fn):
    """Apply the suggested variable renames directly into IDA."""
    if not var_map:
        if log_fn: log_fn(f"  Trace: No variable renames to apply for 0x{ea:X}", 'info')
        return 0

    if log_fn: 
        log_fn(f"  Trace: Applying {len(var_map)} var renames to 0x{ea:X}...", 'info')
        for old, new in var_map.items():
            log_fn(f"    - Variable Rename Suggestion: '{old}' -> '{new}'", 'info')

    try:
        from pseudonote.var_renamer import apply_var_renames
    except Exception as ex:
        log_fn(f"  Could not import var_renamer for var rename at 0x{ea:X}: {ex}", 'warn')
        return 0

    # Wrap the actual renaming AND the pre-checks in execute_sync to ensure they run on the main thread
    res_box = {"applied": 0, "failed": 0, "skipped": False}
    def _do_rename():
        # Move IDA API checks inside the main thread wrapper
        if is_sys_func(idc.get_func_name(ea) or "") or not is_valid_seg(ea):
            res_box["skipped"] = True
            return

        func_obj = idaapi.get_func(ea)
        if not func_obj:
            if log_fn: log_fn(f"  Could not get func_obj for 0x{ea:X} during var rename.", 'warn')
            return
        res_box["applied"], res_box["failed"], _ = apply_var_renames(func_obj.start_ea, var_map, log_fn=log_fn)
        # Persistence call inside main thread
        save_to_idb(ea, "var_renamed_by_analyzer", tag=86)
        # Mark cfunc dirty to force re-decompilation and show new names
        ida_hexrays.mark_cfunc_dirty(ea)
    
    try:
        idaapi.execute_sync(_do_rename, idaapi.MFF_WRITE)
    except Exception as e:
        if log_fn: log_fn(f"  Critical: execute_sync(MFF_WRITE) failed for var rename at 0x{ea:X}: {e}", "err")
        return 0

    if res_box["skipped"]:
        return 0

    applied = res_box["applied"]
    failed = res_box["failed"]

    
    if applied > 0:
        log_fn(f"  Applied {applied} variable renames in 0x{ea:X}", 'ok')
    if failed > 0:
        log_fn(f"  {failed} variable rename(s) failed in 0x{ea:X}", 'warn')
    return applied

def apply_function_rename_from_analysis(ea, node, result, log_fn):
    """Update function name if LLM suggests a descriptive one during analysis."""
    if node.is_library or is_sys_func(node.name):
        return node.name

    suggested = result.get("suggested_func_name", "").strip()
    if not suggested:
        return node.name
        
    generic_prefixes = ("sub_", "unknown_", "wrap_", "tiny_func_")
    if suggested.lower().startswith(generic_prefixes):
        return node.name
        
    if not node.name.lower().startswith(generic_prefixes):
        # Already has a non-generic name, keep it
        return node.name
        
    # Sanitize and apply CONFIG prefix / address options
    sanitized = re.sub(r'[^A-Za-z0-9_]', '_', suggested)[:40]
    prefix = CONFIG.deep_prefix or ""

    if getattr(CONFIG, 'deep_use_prefix', False) and prefix:
        if not sanitized.startswith(prefix):
            sanitized = prefix + sanitized
    if getattr(CONFIG, 'deep_append_address', True):
        if getattr(CONFIG, 'deep_use_0x', False):
            a_addr = f"_0x{ea:X}"
        else:
            a_addr = f"_{ea:X}"
    else:
        a_addr = ""
    final_name = f"{sanitized}{a_addr}"
    
    if final_name == node.name:
        return node.name
        
    try:
        def _do_set_name():
            if idc.get_func_name(ea):
                ida_hexrays.mark_cfunc_dirty(ea)
            if ida_name.set_name(ea, final_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
                save_to_idb(ea, "renamed_by_analyzer", tag=84)
                return True
            return False

        if idaapi.execute_sync(_do_set_name, idaapi.MFF_WRITE):
            old_name = node.name
            node.name = final_name
            # NOTE: Do NOT set node.status here — status is owned by Stage 4/5.
            # Setting "renamed" overwrites "analyzed" for Stage 5 nodes, making
            # them appear as unanalyzed in the final coverage diagnostic.
            log_fn(f"  Function renamed: {old_name} -> {final_name}", 'ok')
            return final_name
    except Exception as e:
        log_fn(f"  Function rename failed for 0x{ea:X} -> {final_name}: {e}", 'warn')
        
    return node.name

def apply_function_comment(ea, result, log_fn):
    """Apply the analysis one-liner as a repeatable comment."""
    if is_sys_func(idc.get_func_name(ea) or "") or not is_valid_seg(ea):
        return
        
    one_liner = result.get("one_liner", "").strip()
    if not one_liner: return
    
    if len(one_liner) > 200:
        one_liner = one_liner[:197] + "..."
        
    res_cmt = {"existing": None}
    def _get_cmt():
        res_cmt["existing"] = idc.get_func_cmt(ea, 1)
    idaapi.execute_sync(_get_cmt, idaapi.MFF_READ)
    
    existing = res_cmt["existing"]
    if existing and existing.strip():
        # Keep existing human or previous AI comment if it's there
        return
        
    prefix = "[PseudoNote] "
    def _set_cmt():
        idc.set_func_cmt(ea, prefix + one_liner, 1)
    idaapi.execute_sync(_set_cmt, idaapi.MFF_WRITE)
    log_fn(f"  Comment set at 0x{ea:X}: {one_liner[:300]}...", 'info')

def validate_analysis_response(result, code, strings, callee_names):
    """Post-process LLM response to catch and fix hallucinations."""
    warnings = []
    
    # Check 1: Suspicious indicators must reference actual code elements
    suspicious = result.get("suspicious", [])
    for item in suspicious:
        item_str = str(item.get("name") if isinstance(item, dict) else item)
        item_lower = item_str.lower()
        # Check if suspicious indicator references actual APIs or strings
        has_evidence = any(callee.lower() in item_lower for callee in callee_names)
        has_string_ref = any(s[:20].lower() in item_lower for s in strings)
        
        # Use taxonomy-aware indicators if possible
        has_code_ref = False
        for api_lower in api_tax.API_MAP.keys():
            if api_lower in item_lower:
                has_code_ref = True
                break

        if not (has_evidence or has_string_ref or has_code_ref):
            warnings.append(f"Suspicious indicator lacks code evidence: {item[:300]}")
    
    # Check 2: Malicious risk_tag requires specific indicators
    if result.get("risk_tag") == "malicious":
        code_lower = code.lower()
        
        # Check for injection or persistence patterns from taxonomy
        has_serious_indicator = False
        serious_categories = ["Injection", "Persistence", "Ransomware", "Rootkit", "Exploit"]
        for api_lower, data in api_tax.API_MAP.items():
            if data.get("category") in serious_categories:
                if api_lower in code_lower:
                    has_serious_indicator = True
                    break
        
        if not has_serious_indicator:
            warnings.append("Risk tag 'malicious' without explicit high-severity evidence - downgrading to 'suspicious'")
            result["risk_tag"] = "suspicious"
    
    # Check 3: Decrypt/inject/exploit in names without evidence
    suggested_names = result.get("suggested_names", [])
    if not suggested_names and "suggested_func_name" in result:
        suggested_names = [result["suggested_func_name"]]
    
    problematic_terms = ['decrypt', 'inject', 'exploit', 'bypass', 'shellcode', 'payload']
    code_lower = code.lower()
    
    for name in suggested_names:
        name_lower = str(name).lower()
        for term in problematic_terms:
            if term in name_lower:
                if term == 'decrypt' and not any(x in code_lower for x in ['xor', 'aes', 'crypt', 'rc4', 'cipher']):
                    warnings.append(f"Suggested name '{name}' contains '{term}' without crypto evidence")
                elif term == 'inject' and not any(x in code_lower for x in ['writeprocessmemory', 'ntwritevirtualmemory', 'createremotethread']):
                    warnings.append(f"Suggested name '{name}' contains '{term}' without injection evidence")
    
    return result, warnings


def validate_variable_renames(ea, raw_var_map, log_fn):
    """Validate AI variable renames against real Hex-Rays lvars.

    Returns a cleaned dict {old_name: new_name} containing ONLY local variable renames.
    """
    if not raw_var_map:
        return {}
    if not hasattr(ida_hexrays, 'decompile'):
        log_fn("  Hex-Rays not available — skipping var rename validation", 'warn')
        return {}

    cleaned = {}
    lvar_names = []

    # Decompile and collect lvars under execute_sync to be thread-safe
    data_box = {"lvar_names": [], "err": None}
    def _gather():
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                data_box["lvar_names"] = [lv.name for lv in cfunc.get_lvars()]
            else:
                data_box["err"] = "Decompile returned None"
        except Exception as ex:
            data_box["err"] = str(ex)

    try:
        idaapi.execute_sync(_gather, idaapi.MFF_READ)
    except Exception as ex:
        log_fn(f"  execute_sync failed during lvar gathering: {ex}", 'warn')
        return {}

    if data_box["err"]:
        log_fn(f"  Failed to read lvars for 0x{ea:X}: {data_box['err']}", 'warn')
        return {}

    lvar_names = data_box["lvar_names"]
    if not lvar_names:
        log_fn(f"  No lvars found for 0x{ea:X} — skipping var renames. (Check if code is decompilable)", 'warn')
        return {}

    lvar_set = set(lvar_names)
    invalid = []

    for old_name, new_name in raw_var_map.items():
        if old_name not in lvar_set:
            invalid.append(old_name)
            continue
        cleaned[old_name] = new_name

    if invalid:
        log_fn(f"  Ignoring {len(invalid)} rename(s) not in lvars: {invalid[:10]}", 'warn')
    log_fn(f"  Var rename candidates: {len(cleaned)}/{len(raw_var_map)} matched lvars", 'info')
    return cleaned

# ---------------------------------------------------------------------------
# Two-Stage Strategy Helpers
# ---------------------------------------------------------------------------

def build_caller_context(node, graph):
    """Build rich context from all callers and their purposes.
    
    This tells the function: "You were called to do X in the context of Y"
    
    Returns:
        dict: {
            "call_chain": ["main", "setup_exploit", "allocate_buffer"],
            "caller_purposes": [{"function": "main", "purpose": "..."}],
            "sibling_functions": ["enable_debug_priv", "open_lsass"],
            "execution_phase": "main execution branch",
            "data_flow": []
        }
    """
    context = {
        "call_chain": [],
        "caller_purposes": [],
        "sibling_functions": [],
        "execution_phase": "",
        "data_flow": []
    }
    
    # Build call chain from entry to this node
    call_chain = find_path_from_entry(node.ea, graph)
    context["call_chain"] = [graph[ea].name for ea in call_chain if ea in graph]
    
    # Get caller purposes from their analyses
    for caller_ea in node.callers:
        if caller_ea not in graph:
            continue
        caller = graph[caller_ea]
        
        # Load caller's analysis (might be preliminary or final)
        caller_raw = load_from_idb(caller_ea, tag=85)
        if caller_raw:
            try:
                data = json.loads(caller_raw)
                context["caller_purposes"].append({
                    "function": caller.name,
                    "purpose": data.get("one_liner", ""),
                    "risk": data.get("risk_tag", "unknown"),
                    "suspicious": data.get("suspicious", [])
                })
            except Exception as e:
                pass
        # Get sibling functions (other functions caller uses)
        siblings = [graph[c].name for c in caller.callees 
                   if c in graph and c != node.ea and not graph[c].is_library]
        context["sibling_functions"].extend(siblings)
    
    # Deduplicate siblings
    context["sibling_functions"] = list(set(context["sibling_functions"]))
    
    # Determine execution phase based on depth
    if node.depth == 1:
        context["execution_phase"] = "main execution branch (direct child of entry)"
    elif node.depth <= 3:
        context["execution_phase"] = "primary operation"
    elif node.depth <= 6:
        context["execution_phase"] = "supporting utility"
    else:
        context["execution_phase"] = "deep helper function"
    
    return context


def find_path_from_entry(target_ea, graph):
    """Find shortest path from entry point to target function using BFS.
    
    Returns:
        list: [entry_ea, intermediate_ea, ..., target_ea]
    """
    # Find entry point (node with depth=0 or lowest depth)
    entry_ea = None
    min_depth = float('inf')
    for ea, node in graph.items():
        if not node.is_library and node.depth < min_depth:
            min_depth = node.depth
            entry_ea = ea
    
    if not entry_ea or entry_ea == target_ea:
        return [target_ea]
    
    # BFS to find path
    queue = [(entry_ea, [entry_ea])]
    visited = {entry_ea}
    
    while queue:
        curr_ea, path = queue.pop(0)
        
        if curr_ea == target_ea:
            return path
        
        if curr_ea not in graph:
            continue
        
        for callee_ea in graph[curr_ea].callees:
            if callee_ea not in visited and callee_ea in graph:
                visited.add(callee_ea)
                queue.append((callee_ea, path + [callee_ea]))
    
    # If no path found, return just the target
    return [target_ea]


def get_malicious_context_semantic(node, graph):
    """Identify malicious analysis red flags using semantic analysis instead of keyword matching.
    
    Uses multiple detection layers:
    1. API semantic categories (what APIs are called)
    2. Behavioral patterns (what the code does)
    3. Call chain analysis (what the program flow suggests)
    4. String content analysis (what strings reference)
    
    Returns:
        list: ["⚠️ Credential access behavior detected", ...]
    """
    markers = []
    
    # ═══════════════════════════════════════════════════════════════
    # LAYER 1: API SEMANTIC CATEGORIES
    # ═══════════════════════════════════════════════════════════════
    
    api_markers = detect_sensitive_api_patterns(node, graph)
    markers.extend(api_markers)
    
    # ═══════════════════════════════════════════════════════════════
    # LAYER 2: BEHAVIORAL PATTERN DETECTION
    # ═══════════════════════════════════════════════════════════════
    
    behavior_markers = detect_behavioral_patterns(node, graph)
    markers.extend(behavior_markers)
    
    # ═══════════════════════════════════════════════════════════════
    # LAYER 3: CALL CHAIN SEMANTIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    
    chain_markers = analyze_call_chain_semantics(node, graph)
    markers.extend(chain_markers)
    
    # ═══════════════════════════════════════════════════════════════
    # LAYER 4: STRING CONTENT ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    
    string_markers = analyze_string_content(node, graph)
    markers.extend(string_markers)
    
    return list(set(markers))  # Deduplicate


# ═══════════════════════════════════════════════════════════════════════
# LAYER 1: API SEMANTIC CATEGORIES
# ═══════════════════════════════════════════════════════════════════════

def detect_sensitive_api_patterns(node, graph):
    """Detect security-relevant behavior based on API taxonomy and combination rules."""
    markers = []
    
    hits = get_api_tags_for_function(node.ea, node.callees if hasattr(node, 'callees') else [])
    if not hits:
        return markers
    
    # Per-category markers
    for cat, apis in hits.items():
        api_list = ", ".join(apis[:5])
        if len(apis) > 5:
            api_list += f" (+{len(apis)-5} more)"
            
        # Lookup severity for icon
        severity = _CATEGORY_TO_SEVERITY.get(cat, 'LOW')
            
        icon = "[!]" if severity == "HIGH" else "[?]" if severity == "MEDIUM" else "[i]"
        markers.append(f"{icon} [{cat}] {api_list}")
        
    # Combination rule markers
    combos = evaluate_combination_rules(hits)
    for combo in combos:
        boost = " (multiple indicators)" if combo["boosted"] else ""
        markers.append(f"[!] PATTERN [{combo['name']}]: {combo['description']}{boost}")
        
    return markers



# ═══════════════════════════════════════════════════════════════════════
# LAYER 2: BEHAVIORAL PATTERN DETECTION
# ═══════════════════════════════════════════════════════════════════════

def detect_behavioral_patterns(node, graph):
    """Detect malicious behavior patterns along the call chain using taxonomy and AI semantics."""
    markers = []
    call_chain = find_path_from_entry(node.ea, graph)
    
    # Track observed capabilities along the path
    path_capabilities = set()
    
    for ea in call_chain:
        # 1. Direct API hits
        ea_node = graph.get(ea)
        hits = get_api_tags_for_function(ea, ea_node.callees if ea_node and hasattr(ea_node, 'callees') else [])
        for cat in hits.keys():
            path_capabilities.add(cat)
            
        # 2. AI semantic fallback (for things APIs might miss like custom XOR)
        analysis_raw = load_from_idb(ea, tag=85)
        if analysis_raw:
            try:
                analysis = json.loads(analysis_raw)
                text = f"{analysis.get('summary', '')} {analysis.get('one_liner', '')} {' '.join(analysis.get('bullets', []))}".lower()
                
                if any(x in text for x in ['xor', 'encrypt', 'decrypt', 'cipher', 'aes', 'rc4']):
                    path_capabilities.add("Crypto")
                if any(x in text for x in ['privilege', 'token', 'sedebug', 'elevation', 'adjust', 'impersonate']):
                    path_capabilities.add("Token_Privilege")
                if any(x in text for x in ['registry', 'regset', 'regopen', 'hkey', 'run key']):
                    path_capabilities.add("Registry_Persistence")
                if any(x in text for x in ['inject', 'remote thread', 'writeprocessmemory', 'ntwrite']):
                    path_capabilities.add("Injection_Memory")
                if any(x in text for x in ['lsass', 'sam ', 'credential', 'dumping', 'password', 'vault']):
                    path_capabilities.add("Credential_Access")
            except Exception as e:
                pass

    # Pattern Detection based on observed capabilities path-wide
    if "Token_Privilege" in path_capabilities and "Injection_Memory" in path_capabilities:
        markers.append("⚠️ Path behavior: Privilege escalation + Process manipulation (Injection)")
    
    if "Injection_Memory" in path_capabilities and "Crypto" in path_capabilities and "Networking" in path_capabilities:
        markers.append("⚠️ Path behavior: Code Injection + Crypto + Network (possible C2 beaconing)")
        
    if "Registry_Persistence" in path_capabilities and "Injection_Memory" in path_capabilities:
        markers.append("⚠️ Path behavior: Persistence indicators + Process injection")

    if "Credential_Access" in path_capabilities and ("Injection_Memory" in path_capabilities or "Token_Privilege" in path_capabilities):
        markers.append("⚠️ Path behavior: Credential Access activity via memory/privilege primitives")

    if "Ransomware" in path_capabilities and "Crypto" in path_capabilities:
        markers.append("⚠️ Path behavior: Ransomware-class APIs combined with crypto operations")

    return markers


# ═══════════════════════════════════════════════════════════════════════
# LAYER 3: CALL CHAIN SEMANTIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def analyze_call_chain_semantics(node, graph):
    """Use AI-derived semantics to analyze call chain purpose."""
    markers = []
    
    call_chain = find_path_from_entry(node.ea, graph)
    if len(call_chain) < 3:
        return markers
    
    chain_names = []
    for ea in call_chain:
        if ea in graph:
            chain_names.append(graph[ea].name)
    
    if len(chain_names) < 3:
        return markers
    
    chain_lower = ' '.join(chain_names).lower()
    
    suspicious_combinations = [
        (['lsa', 'process', 'memory'], 'Credential dumping call chain'),
        (['privilege', 'open', 'read', 'write'], 'Privileged memory access chain'),
        (['registry', 'run', 'persist'], 'Persistence installation chain'),
        (['inject', 'thread', 'write'], 'Code injection chain'),
        (['dump', 'process', 'file'], 'Process dumping chain'),
        (['http', 'send', 'encrypt'], 'Network exfiltration chain')
    ]
    
    for keywords, description in suspicious_combinations:
        if all(kw in chain_lower for kw in keywords):
            markers.append(f"⚠️ Suspicious call chain: {description}")
            break
    
    return markers


# ═══════════════════════════════════════════════════════════════════════
# LAYER 4: STRING CONTENT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def analyze_string_content(node, graph):
    """Analyze string literals for sensitive targets and indicators."""
    markers = []
    
    call_chain = find_path_from_entry(node.ea, graph)
    all_strings = []
    
    for ea in call_chain:
        if ea not in graph:
            continue
        try:
            strings = get_strings_fast(ea)
            all_strings.extend(strings)
        except Exception as e:
            # Silent fallback for background discovery
            pass
    
    all_strings = list(set(all_strings))
    strings_lower = ' '.join(all_strings).lower()
    
    sensitive_processes = {
        'lsass': 'LSASS (credential store)',
        'sam': 'SAM database',
        'ntds': 'Active Directory database',
        'chrome': 'Chrome browser (credential theft)',
        'firefox': 'Firefox browser (credential theft)',
        'outlook': 'Outlook (email harvesting)',
        'keepass': 'KeePass (password manager)',
        'lastpass': 'LastPass (password manager)'
    }
    
    for process, description in sensitive_processes.items():
        if process in strings_lower:
            markers.append(f"⚠️ String reference: {description}")
    
    persistence_paths = {
        'run': 'Registry Run key',
        'runonce': 'Registry RunOnce key',
        'startup': 'Startup folder',
        'winlogon': 'Winlogon registry key',
        'userinit': 'UserInit registry key',
        'scheduled': 'Scheduled task'
    }
    
    for path, description in persistence_paths.items():
        if path in strings_lower:
            markers.append(f"⚠️ String reference: {description} (persistence location)")
    
    if re.search(r'https?://', strings_lower) or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', strings_lower):
        markers.append("⚠️ String reference: Network URL or IP address")
    
    suspicious_commands = ['cmd.exe', 'powershell', 'wmic', 'reg.exe', 'schtasks']
    if any(cmd in strings_lower for cmd in suspicious_commands):
        markers.append("⚠️ String reference: Suspicious command execution")
    
    return markers


def detect_sibling_patterns(node, graph):
    """Detect malicious patterns from sibling function combinations using taxonomy and AI semantics."""
    patterns = []
    
    for caller_ea in node.callers:
        if caller_ea not in graph: continue
        caller = graph[caller_ea]
        
        # Siblings: non-library callees of our caller (excluding current node)
        siblings = [graph[c] for c in caller.callees 
                   if c in graph and c != node.ea and not graph[c].is_library]
        
        if not siblings: continue
        
        # Track capabilities across all siblings
        sib_caps = set()
        for sibling in siblings:
            # 1. API Taxonomy Hits
            hits = get_api_tags_for_function(sibling.ea, sibling.callees if hasattr(sibling, 'callees') else [])
            for cat in hits.keys():
                sib_caps.add(cat)
                
            # 2. AI Semantic fallbacks
            analysis_raw = load_from_idb(sibling.ea, tag=85)
            if analysis_raw:
                try:
                    analysis = json.loads(analysis_raw)
                    text = f"{analysis.get('one_liner', '')} {analysis.get('summary', '')} {' '.join(analysis.get('bullets', []))}".lower()
                    
                    if any(x in text for x in ['inject', 'remote', 'thread', 'process']): sib_caps.add("Injection_Memory")
                    if any(x in text for x in ['xor', 'encrypt', 'decrypt', 'crypto']): sib_caps.add("Crypto")
                    if any(x in text for x in ['privilege', 'token', 'elevation', 'impersonate']): sib_caps.add("Token_Privilege")
                    if any(x in text for x in ['anti', 'debug', 'vm', 'sandbox']): sib_caps.add("Anti_Debug_Evasion")
                    if any(x in text for x in ['http', 'send', 'reach', 'connect']): sib_caps.add("Networking")
                    if any(x in text for x in ['file', 'directory', 'path', 'filesystem']): sib_caps.add("File_System")
                    if any(x in text for x in ['lsass', 'credential', 'sam ', 'vault']): sib_caps.add("Credential_Access")
                except:
                    pass

        # Pattern identification based on sibling sets (Aligned with taxonomy)
        if "Injection_Memory" in sib_caps:
            if "Token_Privilege" in sib_caps:
                patterns.append("Sibling pattern: Privilege escalation supporting Process Injection")
            if "Networking" in sib_caps:
                patterns.append("Sibling pattern: Injection combined with Network capability (RAT/C2?)")
        
        if "Ransomware" in sib_caps and "Crypto" in sib_caps:
            patterns.append("Sibling pattern: File encryption supporting Ransomware operations")
            
        if "Networking" in sib_caps and "Crypto" in sib_caps:
            patterns.append("Sibling pattern: Encrypted network communication (C2 Beaconing?)")
            
        if "Anti_Debug_Evasion" in sib_caps:
            if any(c in sib_caps for c in ("Injection_Memory", "Ransomware", "Spying_Input", "Rootkit_Driver")):
                 patterns.append("Sibling pattern: Evasive behavior protecting high-severity operations")

        if "Credential_Access" in sib_caps and ("Token_Privilege" in sib_caps or "Injection_Memory" in sib_caps):
             patterns.append("Sibling pattern: Credential harvesting via privileged primitives")

    return list(set(patterns))


def determine_risk_with_context(node, result, context, graph):
    """Determine final risk using both local analysis and contextual information.
    
    Strict logic to avoid 'Malware Hallucination':
    - Explicit ignore-list for CRT/compiler boilerplate.
    - No upgrade to 'malicious' without at least one local technical indicator.
    """
    risk = result.get("risk_tag", "benign")
    suspicious = result.get("suspicious", [])
    
    # 0. EXCEPTION: PROTECT COMPILER/RUNTIME STUBS
    # These are often flagged because they are caller-parents or depth-1
    crt_stubs = [
        '__chkstk', '_fpreset', 'mainCRTStartup', '_start', '__main', 'TlsGetValue',
        '__mingw', '_init_', '_fini_', 'bad_alloc', 'bad_cast', 'exception',
        '_acmdln', '_p__acmdln', 'get_osfhandle', '_isatty', '_setmode', '_cinit',
        '_set_invalid_parameter_handler', '_invalid_parameter', '_pei386_runtime_relocator',
        '_encode_pointer', '_decode_pointer', 'IsProcessorFeaturePresent'
    ]
    if any(stub in node.name for stub in crt_stubs):
        # Forced downgrade for known safe stubs unless they are hijacked (rare)
        result["risk_tag"] = "benign"
        result["suspicious"] = []
        return result

    # Get malicious analysis markers and patterns
    malicious_markers = get_malicious_context_semantic(node, graph)
    sibling_patterns = detect_sibling_patterns(node, graph)
    
    # Store in result for summary generation
    result["context_markers"] = malicious_markers
    result["pattern_matches"] = sibling_patterns
    
    # ═══════════════════════════════════════════════════════════════
    # UPGRADE CONDITIONS (benign/suspicious → malicious)
    # ═══════════════════════════════════════════════════════════════
    
    upgrade_to_malicious = False
    upgrade_reasons = []
    
    # REQUIREMENT: For any upgrade to 'malicious', we require at least ONE
    # local technical indicator (suspicious string, API hit, or high entropy),
    # or a very specific behavior pattern.
    has_local_indicator = (
        len(suspicious) > 0 or 
        (node.entropy and node.entropy > 6.5) or
        get_api_tags_for_function(node.ea, node.callees if hasattr(node, 'callees') else [])
    )

    # Condition 1: Direct child of entry + sensitive operation
    if node.depth == 1 and has_local_indicator:
        if malicious_markers:
            upgrade_to_malicious = True
            upgrade_reasons.append(f"Entry-level function with sensitive operation: {malicious_markers[0]}")
    
    # Condition 2: Part of known attack pattern (High confidence)
    if sibling_patterns:
        # Sibling patterns are strong indicators
        upgrade_to_malicious = True
        for pattern in sibling_patterns:
            upgrade_reasons.append(f"Part of attack pattern: {pattern}")
    
    # Condition 3: Supports malicious caller (TRANSITIVITY - USE WITH CAUTION)
    # Only upgrade if it actually has SOME local suspicion
    if has_local_indicator:
        for caller_ea in node.callers:
            if caller_ea not in graph:
                continue
            
            caller = graph[caller_ea]
            caller_raw = load_from_idb(caller_ea, tag=85)
            if caller_raw:
                try:
                    caller_data = json.loads(caller_raw)
                    if caller_data.get("risk_tag") == "malicious":
                        upgrade_to_malicious = True
                        upgrade_reasons.append(f"Supports malicious function: {caller.name}")
                        break
                except:
                    pass
    
    # Condition 4: Multiple malicious analysis markers
    if len(malicious_markers) >= 2:
        upgrade_to_malicious = True
        upgrade_reasons.append(f"Multiple malicious analysis indicators detected")
    
    # Apply upgrade
    if upgrade_to_malicious and risk != "malicious":
        # Final sanity check: if the name sounds benign (e.g. print, log, string) 
        # and it's a utility, maintain at most 'suspicious' unless indicators are HIGH
        benign_terms = ['print', 'report', 'log', 'string', 'format', 'dump_data']
        if any(term in node.name.lower() for term in benign_terms) and len(malicious_markers) < 2:
            risk = "suspicious"
            suspicious.append("Context suggests potential use in malicious flow, but code remains utility-like.")
        else:
            risk = "malicious"
            suspicious.extend(upgrade_reasons)
            suspicious.append(f"Risk upgraded from suspicious to malicious based on contextual evidence")
    
    # ═══════════════════════════════════════════════════════════
    # DOWNGRADE CONDITIONS (suspicious → benign)
    # ═══════════════════════════════════════════════════════════
    
    downgrade_to_benign = False
    downgrade_reasons = []
    
    # Condition 1: Deep utility function in benign context
    if node.depth > 3: # Lowered threshold for utility protection
        if not malicious_markers and not sibling_patterns and risk == "suspicious":
            # Check if all callers are benign
            all_callers_benign = True
            for caller_ea in node.callers:
                if caller_ea in graph:
                    caller_raw = load_from_idb(caller_ea, tag=85)
                    if caller_raw:
                        try:
                            caller_data = json.loads(caller_raw)
                            if caller_data.get("risk_tag") != "benign":
                                all_callers_benign = False
                                break
                        except:
                            all_callers_benign = False
            
            if all_callers_benign:
                downgrade_to_benign = True
                downgrade_reasons.append("Utility function with benign context")
    
    # Condition 2: Generic C++ runtime code
    generic_patterns = ['exception', 'iostream', 'std::', 'bad_cast', 'bad_alloc', 'vector', 'string']
    if any(p in node.name.lower() for p in generic_patterns):
        if not malicious_markers and not sibling_patterns:
            downgrade_to_benign = True
            downgrade_reasons.append("Standard library/runtime function")
    
    # Apply downgrade
    if downgrade_to_benign and risk == "suspicious":
        suspicious.extend(downgrade_reasons)
        risk = "benign"
    
    # Update result
    result["risk_tag"] = risk
    result["suspicious"] = suspicious
    
    return result


def analyze_with_context(ea, node, graph, output_dir, ai_cfg, analyzed_eas, context, log_fn,
                        char_count_cb=None, cooldown_cb=None, llm_state_cb=None):
    """Perform contextual re-analysis of a function (Contextual Malicious Code Analysis Refinement)."""
    # Call analyze_single_function in contextual mode
    result = analyze_single_function(
        ea, node, graph, output_dir, ai_cfg, analyzed_eas, log_fn,
        mode="contextual",
        context=context,
        char_count_cb=char_count_cb,
        cooldown_cb=cooldown_cb,
        llm_state_cb=llm_state_cb
    )
    
    # Apply contextual risk determination
    def _sync_risk():
        determine_risk_with_context(node, result, context, graph)
    idaapi.execute_sync(_sync_risk, idaapi.MFF_READ)
    
    return result


def build_preliminary_analysis_prompt(node, code, strings, caller_names, callee_names, 
                                     line_count, code_snippet, digest, graph):
    """Build prompt for Initial Assessment preliminary analysis (bottom-up, with indicators)."""
    
    # API Behavior Tags injection (Step 5)
    api_tags_block = ""
    api_hits = get_api_tags_for_function(node.ea, node.callees if hasattr(node, 'callees') else [])
    local_risk = "unknown"
    if api_hits:
        api_tags_block = "API Behavior Indicators (malware taxonomy):\n"
        for cat, apis in api_hits.items():
            # Lookup severity for the category (high-performance lookup)
            severity = _CATEGORY_TO_SEVERITY.get(cat, 'LOW').upper()
            if severity == "HIGH":
                local_risk = "malicious"
            elif severity == "MEDIUM" and local_risk != "malicious":
                local_risk = "suspicious"
            
            api_tags_block += f"  - [{cat}] APIs: {', '.join(apis[:8])}  (Severity: {severity})\n"
        
        # Evaluate Rule-based Combinations (Step 4 improvement)
        combos = evaluate_combination_rules(api_hits)
        if combos:
            api_tags_block += "\nIdentified Attack Patterns:\n"
            for c in combos:
                c_sev = c.get("severity", "LOW").upper()
                c_boost = " [CRITICAL]" if c.get("boosted") else ""
                api_tags_block += f"  [!] {c['name']}: {c['description']}{c_boost} (Severity: {c_sev})\n"
                if c_sev == "HIGH": local_risk = "malicious"
                elif c_sev == "MEDIUM" and local_risk != "malicious": local_risk = "suspicious"

        api_tags_block += f"\n>> PRELIMINARY LOCAL HEURISTIC RISK LEVEL: {local_risk.upper()}\n"
        if local_risk == "malicious":
            api_tags_block += "   Malware Note: This function contains signatures highly characteristic of malicious intent.\n"
    
    # Child Assessments injection (Bottom-Up)
    child_assessments_block = ""
    analyzed_callees = []
    for c_ea in node.callees:
        if c_ea in graph and not graph[c_ea].is_library:
            raw_data = load_from_idb(c_ea, tag=85)
            risk_label = "unknown"
            one_liner = ""
            if raw_data:
                try:
                    d = json.loads(raw_data)
                    one_liner = d.get("one_liner", "")
                    risk_label = d.get("risk_tag", "benign")
                except: pass
            
            if one_liner:
                tags = f" [{' '.join(graph[c_ea].semantic_tags[:2])}]" if graph[c_ea].semantic_tags else ""
                analyzed_callees.append(f"  - {graph[c_ea].name}{tags} [Risk: {risk_label.upper()}]: {one_liner.strip()}")
    
    if analyzed_callees:
        child_assessments_block = "Child Function Assessments (summarized in previous waves):\n"
        child_assessments_block += "\n".join(analyzed_callees[:20]) + "\n\n"

    prompt = f"""You are analyzing a decompiled function in ISOLATION (preliminary pass).
Focus ONLY on what the code does technically. You will NOT see why this function exists
or who calls it yet - that comes in the final analysis pass.

CRITICAL: This is the Initial Assessment phase. Provide objective technical descriptions. 
If clearly malicious patterns are observed (e.g. process injection, credential theft, token impersonation, ransomware behavior), assign the appropriate risk level without hesitation. 
However, if the code is generic or ambiguous, remain conservative until context is provided in later stages.

STRICT RULE: Do NOT flag standard compiler stubs or runtime logic as suspicious (e.g., __chkstk, _main, _fpreset, CRT initialization). These are BENIGN boilerplate.
DO NOT hallucinate intent. If the code just prints text or formats data, it is BENIGN regardless of the binary's overall nature.

{child_assessments_block}
{digest}

Function: {node.name}
Address: 0x{node.ea:X}
Call depth: {node.depth}
Called by: {', '.join(caller_names) if caller_names else 'entry point or unknown'}
Calls: {', '.join(callee_names) if callee_names else 'no named functions'}

TECHNICAL INDICATORS:
- Structural Complexity: {node.complexity.get('branches', 0)} branches, {node.complexity.get('loops', 0)} loops
- Data Entropy: {node.entropy} (high entropy > 6.0 suggests crypto/packing)
- Renaming Confidence (Phase 1): {node.analysis_wave_confidence}%
- Heuristic Interest Score: {calculate_interest_score(node)}/100
- Analysis Depth: {'DEEP DIVE REQUIRED' if calculate_interest_score(node) > 60 else 'Standard Assessment'}

{api_tags_block}
String literals: {', '.join(strings[:8]) if strings else 'none'}

DECOMPILED CODE ({line_count} lines):
{code_snippet if code_snippet else '(decompilation not available)'}

Respond with JSON containing:
{{
  "one_liner": "Technical description of operations (e.g., 'Allocates memory and copies buffer')",
  
  "summary": "1-2 sentences describing what APIs are called and what data transformations occur",
  
  "bullets": [
    "Observable operation 1 (e.g., 'Calls VirtualAlloc with size parameter')",
    "Observable operation 2",
    "Observable operation 3"
  ],
  
  "confidence": 85, // Integer 0-100 based on code clarity, NOT assumed importance
  
  "var_renames": {{"v1": "descriptive_name"}}, // only if usage is crystal clear
  
  "suggested_names": ["technical_name_1", "technical_name_2", "technical_name_3"], // TOP 3 descriptive names
  
  "return_value": "Technical description of return value",
  
  "risk_tag": "benign", // MUST be exactly one of: benign, suspicious, malicious. MATCH the Heuristic Risk Level if the code confirms it.
  
  "capabilities": ["List of high-level capabilities: e.g. Injection, Persistence, Cryptography, Networking"],
  
  "semantic_tags": ["SHORT_TAGS", "EX: [FILE_IO]", "[INJECTION]", "[CRYPTO]"],
  
  "suspicious": ["List of observable technical red flags found in isolation"],
  
  "contextual_purpose": "Explain what this function appears to be doing at a high level",
  
  "risk_logic": "Explain why you assigned this risk level. If you see APIs like ImpersonateLoggedOnUser or OpenProcess(PROCESS_ALL_ACCESS), explain the forensic significance.",
  
  "clean_code": "Author a READABLE C version of this function that a human malware analyst can easily understand. Requirements:\n    - Write real, idiomatic C — DO NOT return decompiler output. No compiler-specific keywords.\n    - Give ALL variables and parameters descriptive names based on their observed usage.\n    - CRITICAL: Remove ALL typecasts: e.g., NO (int), NO (DWORD), NO (unsigned __int64), NO (void *).\n    - Remove ALL calling conventions: NO __fastcall, NO __cdecl, etc.\n    - Resolve virtual calls: Rewrite (* (* obj + offset))(obj, ...) as obj->vtable[index](obj, ...) where index = offset/8 (64-bit) or offset/4 (32-bit).\n    - Rewrite pointer arithmetic into logical struct member access (obj->field_X).\n    - Add a //comment on each significant line explaining the malware action.\n    - Output raw C code only. Include the function signature."
}}

IMPORTANT RULES:
1. Reference the Child Function Assessments provided above to understand what your sub-routines do.
2. If Heuristic Interest Score is HIGH (>60), perform an extremely deep dive into the logic.
3. If API Behavior Tags are listed, reference the category name in your bullets (e.g., 'Injection_Memory-class API: VirtualAllocEx called with PAGE_EXECUTE_READWRITE')
4. Describe WHAT the code does, not WHY or what it might be for unless malicious intent is technically undeniable (e.g. process hollowing).
5. If the Preliminary Heuristic Risk Level is MALICIOUS, do not downgrade it unless you can definitively prove the context is benign.

Reply with ONLY valid JSON. No markdown backticks."""
    
    return prompt


def build_contextual_analysis_prompt(node, code, strings, context, graph, line_count, code_snippet):
    """Build prompt for Contextual Malicious Code Analysis Refinement re-analysis (top-down, with full context)."""
    
    # API Behavior Tags injection (Step 5)
    api_tags_block = ""
    note_line = ""
    api_hits = get_api_tags_for_function(node.ea, node.callees if hasattr(node, 'callees') else [])
    if api_hits:
        api_tags_block = "\nAPI Behavior Tags (taxonomy-matched):\n"
        matched_cats = []
        for cat, apis in api_hits.items():
            # Lookup severity for the category
            severity = "LOW"
            entry = next((v for k, v in _API_MAP.items() if v["category"] == cat), {})
            if entry:
                severity = entry.get("severity", "LOW")
            
            api_tags_block += f"  [{cat}] {', '.join(apis[:10])}  (severity: {severity})\n"
            
            # Categories that trigger the special warning note
            if severity == "HIGH" or cat in ("Injection", "Ransomware", "Rootkit", "Spying", "Evasion"):
                matched_cats.append(cat)
        
        if matched_cats:
            note_line = f"\nNOTE: This function uses APIs classified as {', '.join(set(matched_cats))}. Weight this heavily when assigning risk_tag."
    
    # Format call chain
    call_chain_str = ' → '.join(context['call_chain']) if context['call_chain'] else 'unknown'
    
    # Format caller purposes
    caller_purposes_str = ""
    for cp in context['caller_purposes'][:3]:
        caller_purposes_str += f"  - {cp['function']}: {cp['purpose']}\n"
        if cp['risk'] != "benign":
            caller_purposes_str += f"    Risk: {cp['risk']}\n"
        if cp['suspicious']:
            caller_purposes_str += f"    Suspicious: {cp['suspicious'][0]}\n"
    
    # Format siblings
    siblings_str = ', '.join(context['sibling_functions'][:10]) if context['sibling_functions'] else 'none'
    
    # Get preliminary analysis
    prelim_str = "(not available)"
    prelim_raw = load_from_idb(node.ea, tag=85)
    if prelim_raw:
        try:
            prelim = json.loads(prelim_raw)
            prelim_str = f"Technical operations: {prelim.get('one_liner', 'N/A')}\n"
            prelim_str += f"  Preliminary risk: {prelim.get('risk_tag', 'N/A')}"
        except Exception as e:
            print(f"[PseudoNote] Warning: Error parsing preliminary analysis for {hex(node.ea)}: {e}")
    
    prompt = f"""You are performing CONTEXTUAL RE-ANALYSIS with full call chain visibility.

═══════════════════════════════════════════════════════════════
PRELIMINARY ANALYSIS (Initial Malicious Code Analysis Assessment):
═══════════════════════════════════════════════════════════════
{prelim_str}

═══════════════════════════════════════════════════════════════
CONTEXTUAL INFORMATION (Contextual Malicious Code Analysis Refinement):
═══════════════════════════════════════════════════════════════

Call Chain from Entry:
{call_chain_str}

Execution Phase:
{context['execution_phase']}

Called By (with their purposes):
{caller_purposes_str if caller_purposes_str else '  (no analyzed callers)'}

Sibling Functions (others that caller also uses):
{siblings_str}

═══════════════════════════════════════════════════════════════
FUNCTION CODE:
═══════════════════════════════════════════════════════════════
{api_tags_block}
TECHNICAL INDICATORS:
- Structural Complexity: {node.complexity.get('branches', 0)} branches, {node.complexity.get('loops', 0)} loops
- Data Entropy: {node.entropy}
- Heuristic Interest Score: {calculate_interest_score(node)}/100
- Previous Semantic Tags: {', '.join(node.semantic_tags) if node.semantic_tags else 'none'}

String literals: {', '.join(strings[:8]) if strings else 'none'}

Code ({line_count} lines):
{code_snippet if code_snippet else '(decompilation not available)'}

═══════════════════════════════════════════════════════════════
TASK: CONTEXTUAL RE-EVALUATION
═══════════════════════════════════════════════════════════════

NOW WITH THIS CONTEXT, re-evaluate the function's role and risk:

CONTEXTUAL ANALYSIS RULES:
1. Consider WHY the caller needs this function.
2. Look for patterns when combined with sibling functions.
3. UPGRADE risk ONLY if the code itself performs a sensitive operation that directly supports a malicious goal.
4. DO NOT upgrade a function to 'malicious' just because its caller is malicious if the code is a generic utility (e.g., printing, formatting, string copying).
5. If call chain contains sensitive targets (LSASS, Registry, etc.), context matters, but the code must still show relevant logic.
6. STUBS/CRT: Never upgrade compiler-generated boilerplate.
{note_line}

EXAMPLES OF CONTEXT-BASED RISK CHANGES:

Example 1 - UPGRADE from benign to malicious:
  Preliminary: "Allocates buffer" [benign]
  Context: Called by "dump_lsass_credentials"
          Siblings: ["enable_debug_privilege", "open_lsass_process"]
          Call chain: main → setup_credential_dump → allocate_buffer
  → UPGRADE to malicious: "Allocates buffer for stolen credential storage"

Example 2 - KEEP suspicious:
  Preliminary: "Calls VirtualAlloc with RWX" [suspicious]
  Context: Called by "jit_compiler_init"
          Siblings: ["parse_bytecode", "optimize_ir"]
          Call chain: main → init_runtime → jit_compiler_init → allocate_rwx
  → KEEP suspicious: "RWX allocation for JIT (legitimate but unusual)"

Example 3 - DOWNGRADE from suspicious to benign:
  Preliminary: "Pointer arithmetic operations" [suspicious]
  Context: Called by "iostream_format"
          Siblings: ["std::bad_cast", "std::exception"]
          Call chain: main → console_output → iostream_format → ptr_operation
  → DOWNGRADE to benign: "Standard C++ iostream implementation"

Respond with JSON:
{{
  "one_liner": "Contextual purpose (why this function exists in the program)",
  
  "summary": "1-2 paragraphs explaining role in the larger program and contribution to behavior",
  
  "bullets": [
    "Context-aware observation 1",
    "Context-aware observation 2",
    "Context-aware observation 3"
  ],
  
  "confidence": 85, // Integer 0-100 based on your confidence
  "var_renames": {{"v1": "local_name", "a1": "param_name"}},
  
  "suggested_names": ["contextual_name_1", "contextual_name_2", "contextual_name_3"], // TOP 3 names
  "risk_tag": "benign", // MUST be exactly one of: benign, suspicious, malicious
  
  "suspicious": [
    "Context-aware indicator 1 (cite specific evidence)",
    "Context-aware indicator 2"
  ],
  
  "return_value": "Context-aware description of return value and its significance",
  
  "contextual_purpose": "High-level explanation of why this function exists",
  
  "risk_logic": "Explain why the risk level was UPGRADED, DOWNGRADED, or KEPT from the preliminary assessment",
  
  "clean_code": "Author a READABLE C version of this function that a human malware analyst can easily understand. Use the FULL CONTEXT (call chain, purpose) for naming. Requirements:\n    - Write real, idiomatic C — DO NOT return decompiler output.\n    - Apply ALL descriptive variable renames you determined above.\n    - CRITICAL: Remove ALL typecasts: e.g., NO (int), NO (DWORD), NO (void *).\n    - Remove ALL calling conventions: NO __fastcall, NO __stdcall, etc.\n    - Resolve virtual calls: Rewrite (* (* obj + offset))(obj, ...) as obj->vtable[index](obj, ...) where index = offset/8 (64-bit) or offset/4 (32-bit).\n    - Add a //comment on each significant line explaining the action in this malware context.\n    - Output raw C code only. Include the function signature."
}}

REMEMBER: Base your risk assessment on the FULL PICTURE, not just isolated operations.
If the call chain shows LSASS targeting + privilege escalation + memory dumping, 
even a simple buffer allocation is part of a credential theft attack.

Reply with ONLY valid JSON. No markdown backticks."""
    
    return prompt

def analyze_single_function(ea, node, graph, output_dir, ai_cfg, analyzed_eas, log_fn, 
                           mode="preliminary", context=None,
                           char_count_cb=None, cooldown_cb=None, llm_state_cb=None, update_cb=None):
    """Perform a deep analysis of a function using AI and store results in JSON."""
    
    # Last-mile library/sys skip defense
    if node.is_library or is_sys_func(node.name) or not is_valid_seg(ea):
        node.is_library = True
        return {
            "risk_tag": "benign", 
            "confidence": 100, 
            "one_liner": "Standard library / compiler-generated helper function (skipped analysis).",
            "summary": "This function was identified as a system/compiler helper. It is automatically classified as benign.",
            "risk_logic": "Verified via static name/signature matching against standard signatures."
        }

    # For contextual mode (Stage 5), always fetch fresh code so lvar names reflect
    # any renames applied during Stage 4 — NOT the stale pre-rename disk cache.
    res_data = {"code": None, "strings": []}
    
    def _gather_data():
        if mode == "contextual":
            # Fresh decompilation picks up current lvar names (post-rename)
            res_data["code"] = get_code_fast(ea, max_len=15000)
        else:
            disk_code = load_decompiled_from_disk(ea, node.name, output_dir)
            res_data["code"] = disk_code or get_code_fast(ea, max_len=15000)
        res_data["strings"] = get_strings_fast(ea)
        
    idaapi.execute_sync(_gather_data, idaapi.MFF_READ)
    
    analysis_code = res_data["code"] or ""
    strings = res_data["strings"]
    digest = build_known_functions_digest(graph, analyzed_eas)
    
    caller_names = [graph[c].name for c in node.callers if c in graph and not graph[c].is_library][:5]
    callee_names = [graph[c].name for c in node.callees if c in graph and not graph[c].is_library][:10]
    
    line_count = node.line_count if node.line_count > 0 else (len(analysis_code.splitlines()) if analysis_code else 0)
    
    # TOKEN OPTIMIZATION (Stage 5 Improvement)
    # If in contextual mode and Stage 4 was high confidence + low interest, skip the full code
    skip_code = False
    if mode == "contextual":
        interest = calculate_interest_score(node)
        if node.confidence > 85 and interest < 30:
            skip_code = True
    
    code_snippet = "" if skip_code else truncate_code_lines(analysis_code, 1500)

    # Choose prompt and system prompt based on mode
    if mode == "preliminary":
        prompt = build_preliminary_analysis_prompt(
            node, analysis_code, strings, caller_names, callee_names, 
            line_count, code_snippet, digest, graph
        )
        sys_prompt = "You are a malware analyst. Provide a technically detailed assessment of the code's behavior. Assign the 'malicious' risk level if clear malicious patterns (injection, persistence, theft) are identified. Otherwise be objective and specify observable facts. Reply only with valid JSON."
    else:  # contextual
        prompt = build_contextual_analysis_prompt(
            node, analysis_code, strings, context, graph, line_count, code_snippet
        )
        sys_prompt = "You are a lead malware analyzer performing contextual refinement. Use the provided call chain and sibling context to determine the ultimate intent of the code. Heavily weight high-severity API indicators and identified attack patterns. Reply only with valid JSON."

    if llm_state_cb: llm_state_cb("requesting")
    
    first_chunk = [True]
    def _chunk_cb(c):
        if first_chunk[0]:
            if llm_state_cb: llm_state_cb("receiving")
            first_chunk[0] = False
        if char_count_cb: char_count_cb(0, 0)

    response = _validated_ai_request(
        ai_cfg, 
        prompt, 
        sys_prompt=sys_prompt, 
        logger=lambda m: log_fn(m, 'warn'),
        on_cooldown=cooldown_cb,
        on_chunk=_chunk_cb,
        max_tokens=2500
    )
    if llm_state_cb: llm_state_cb("idle")

    # JSON Parsing with multi-level fallback
    result = {}
    
    # Clean up potential markdown wrapper
    json_str = response.replace("```json", "").replace("```", "").strip()
    
    def fix_and_parse_single(text):
        try: return json.loads(text)
        except: pass
        
        # Aggressive repair
        t = text
        if t.count('"') % 2 != 0: t += '"'
        opens = t.count('{') - t.count('}')
        if opens > 0: t += '}' * opens
        obrak = t.count('[') - t.count(']')
        if obrak > 0: t += ']' * obrak
        t = re.sub(r',\s*([\]}])', r'\1', t)
        
        try: return json.loads(t)
        except:
            try: return json.loads(t + '"' + '}' * 10)
            except: return None

    # Attempt 1: Direct or simple repair
    parsed = fix_and_parse_single(json_str)
    
    # Attempt 2: Try to find substring if there's garbage text around it
    if not parsed:
        start = response.find('{')
        end = response.rfind('}')
        if start != -1 and (end == -1 or end <= start):
            parsed = fix_and_parse_single(response[start:])
        elif start != -1 and end != -1:
            parsed = fix_and_parse_single(response[start:end+1])
            
    if parsed and isinstance(parsed, dict):
        result = parsed
    else:
        log_fn(f"   [-] Unrecoverable JSON from AI. Start of response: {response[:100]}", "err")
        
        # Scrape partial data as absolute fallback
        one_liner = "Analysis failed"
        sum_text = "Could not parse AI response."
        
        m1 = re.search(r'"one_liner":\s*"([^"]+)', response)
        if m1: one_liner = m1.group(1).strip()
        
        m2 = re.search(r'"summary":\s*"([^"]+)', response)
        if m2: sum_text = m2.group(1).strip()
        
        result = {
            "one_liner": one_liner, 
            "summary": sum_text, 
            "confidence": 0,
            "risk_tag": "pending" # Force pending on error so it isn't blindly trusted
        }
    
    # Post-processing validation
    if result and isinstance(result, dict):
        result, validation_warnings = validate_analysis_response(result, analysis_code, strings, callee_names)
        for warning in validation_warnings:
            log_fn(f"   [!] Validation: {warning}", 'warn')
    
    if char_count_cb:
        char_count_cb(len(prompt), 100000)

    # Validation and Clamping
    if not isinstance(result, dict):
        result = {"one_liner": "Error: Not a dict", "summary": str(result), "bullets": [], "confidence": 0, "suspicious": []}
    
    if "risk_tag" in result and isinstance(result["risk_tag"], str):
        result["risk_tag"] = result["risk_tag"].lower().strip()
    
    # Robust confidence parsing
    try:
        conf_val = result.get("confidence", 0)
        if isinstance(conf_val, str):
             # Try to extract number if string like "85%"
             m = re.search(r'(\d+)', conf_val)
             conf_val = int(m.group(1)) if m else 0
        result["confidence"] = max(0, min(100, int(conf_val)))
    except:
        result["confidence"] = 0

    if not isinstance(result.get("bullets"), list): result["bullets"] = []
    if not isinstance(result.get("suspicious"), list): result["suspicious"] = []
    if not isinstance(result.get("var_renames"), dict): result["var_renames"] = {}
    if not isinstance(result.get("suggested_func_name"), str): result["suggested_func_name"] = ""

    # Force risk to pending unless this is final Stage 5 (contextual refinement)
    if mode != "contextual":
        result["risk_tag"] = "pending"

    # Persistence
    idaapi.execute_sync(lambda: save_to_idb(ea, json.dumps(result), tag=85), idaapi.MFF_WRITE)

    # Always save raw Hex-Rays code to decomp/ (source of truth for decompiler output)
    save_decompiled_to_disk(ea, node.name, analysis_code, output_dir)

    # Handle LLM produced clean_code (save it, but KEEP it in result for markdown if needed)
    clean_code = result.get("clean_code") 
    if clean_code and isinstance(clean_code, str) and len(clean_code.strip()) > 20:
        save_readable_to_disk(ea, node.name, clean_code.strip(), output_dir)
    
    # Now that it's saved to disk, we can pop it before IDB/JSON to save space if it's very large
    # but for now we keep it to ensure it reaches report synthesis.
    # result.pop("clean_code", None) 
    
    # Restore dropped fields from preliminary phase so TTPs aren't lost from artifacts
    if mode == "contextual" and hasattr(node, "preliminary_analysis") and isinstance(node.preliminary_analysis, dict):
        for field in ("semantic_tags", "capabilities"):
            if field in node.preliminary_analysis and field not in result:
                result[field] = node.preliminary_analysis[field]

    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', node.name)[:60]
    json_path = os.path.join(output_dir, "analysis", "%s_0x%X.json" % (safe_name, ea))
    try:
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        if log_fn:
             log_fn(f"   [!] Artifact Save Error (0x{ea:X}): {e}", "warn")
    
    # Update node status based on mode
    node.status = mode
    node.confidence = result.get("confidence", 0)
    
    if mode == "preliminary":
        node.preliminary_analysis = result
        # Extract and store semantic tags for digest use
        t_list = []
        tags_raw = result.get("semantic_tags")
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if len(t_list) >= 5: break
                t_list.append(str(t).upper().strip())
        node.semantic_tags = t_list
    else:  # contextual
        node.contextual_analysis = result
        # Also sync tags if they changed
        t_list = []
        tags_raw = result.get("semantic_tags")
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if len(t_list) >= 5: break
                t_list.append(str(t).upper().strip())
        if t_list: node.semantic_tags = t_list
        
    save_graph_to_disk(graph, output_dir)
    
    # Store full one-liner untruncated — used for both UI display and prompt digest
    _analysis_cache[ea] = result.get("one_liner", "")
    
    log_fn(f"   [+] Analyzed {node.name} ({node.confidence}% confidence)", "ok")
    
    if update_cb: update_cb(ea, node.name, node.name, node.confidence)
    return result

def analyze_batch_functions(batch, graph, output_dir, ai_cfg, analyzed_eas, log_fn,
                           char_count_cb=None, cooldown_cb=None, llm_state_cb=None):
    """Analyze multiple small functions in a single batch request."""
    if not batch:
        return []

    # 1. Gather code for all functions in the batch
    batch_data = [] # list of (ea, node, code, strings)
    
    def _gather_batch():
        for ea, node, lc in batch:
            code = load_decompiled_from_disk(ea, node.name, output_dir)
            if not code:
                code = get_code_fast(ea, max_len=100000)
            strings = get_strings_fast(ea)
            batch_data.append((ea, node, code or "", strings))
            
    idaapi.execute_sync(_gather_batch, idaapi.MFF_READ)

    # 2. Build the aggregate prompt
    digest = build_known_functions_digest(graph, analyzed_eas)
    
    functions_block = ""
    for ea, node, code, strings in batch_data:
        api_hits = get_api_tags_for_function(ea, node.callees if hasattr(node, 'callees') else [])
        api_str = ""
        if api_hits:
            api_str = "API Indicators: " + ", ".join([f"[{cat}] {', '.join(apis[:5])}" for cat, apis in api_hits.items()]) + "\n"
        
        functions_block += f"--- FUNCTION: {node.name} (0x{ea:X}) ---\n"
        functions_block += f"Calls: {', '.join([graph[c].name for c in node.callees if c in graph and not graph[c].is_library][:5])}\n"
        functions_block += f"{api_str}"
        functions_block += f"Strings: {', '.join(strings[:5])}\n"
        functions_block += f"CODE:\n{truncate_code_lines(code, 400)}\n\n"

    prompt = f"""You are analyzing a BATCH of small functions in isolation.
{digest}

FUNCTIONS TO ANALYZE:
{functions_block}

TASK: Provide a technical assessment for EACH function.
Respond with a JSON object where keys are the indices ("0", "1", "2"...):
{{
  "0": {{
    "one_liner": "Technical purpose",
    "summary": "1-2 sentence description of behavior",
    "bullets": ["observable detail 1", "observable detail 2"],
    "confidence": 85,
    "suggested_func_name": "new_name",
    "var_renames": {{"v1": "descriptive_name", "a1": "param_1"}},
    "capabilities": ["High-level capability: e.g. Persistence, Cryptography"],
    "semantic_tags": ["[TAG1]", "[TAG2]"],
    "risk_tag": "benign",
    "suspicious": ["concrete indicator 1"],
    "return_value": "Technical return value description",
    "contextual_purpose": "High-level summary of intent",
    "risk_logic": "Why this risk level was assigned",
    "clean_code": "Author a READABLE C version of this function for a malware analyst. Give variables descriptive names based on usage. Remove all casts (int)/(DWORD)/(__int64), remove __fastcall/__cdecl, rewrite virtual calls (* (* obj + 0x18))(obj) as obj->vtable[3](obj). Add // comments explaining what each significant line does. Preserve all logic and control flow exactly. Raw C only, include the function signature."
  }}
}}
Note: For semantic_tags, use max 3 labels like "[FILE_IO]", "[NETWORK]", "[INJECTION]".
Reply with ONLY the JSON."""

    if llm_state_cb: llm_state_cb("requesting")
    
    first_chunk = [True]
    response_chars = [0]
    def _chunk_cb(c):
        response_chars[0] += len(c)
        if first_chunk[0]:
            if llm_state_cb: llm_state_cb("receiving")
            first_chunk[0] = False
        if char_count_cb: char_count_cb(response_chars[0], 0)

    response = _validated_ai_request(
        ai_cfg, prompt, 
        sys_prompt="You are a binary analyst. Respond only with JSON mapping function names to assessments.",
        logger=lambda m: log_fn(m, 'warn'),
        on_cooldown=cooldown_cb,
        on_chunk=_chunk_cb,
        max_tokens=10000
    )
    if llm_state_cb: llm_state_cb("idle")

    # 3. Parse and map back to nodes
    results = []
    try:
        # Simple extraction if LLM adds markdown
        start = response.find('{')
        end = response.rfind('}')
        if start != -1:
            # 1. Prepare initial json_str
            if end == -1 or end <= start:
                log_fn("   [!] Batch JSON appears truncated. Attempting aggressive repair...", "warn")
                json_str = response[start:]
            else:
                json_str = response[start:end+1]
            
            # Helper for surgical extraction
            def fix_and_parse(text):
                # Remove markdown clutter
                t = text.replace("```json", "").replace("```", "").strip()
                try: return json.loads(t)
                except: pass
                
                # Aggressive repair for truncation
                # Fix unclosed string if odd number of quotes
                if t.count('"') % 2 != 0: t += '"'
                # Balance braces
                opens = t.count('{') - t.count('}')
                if opens > 0: t += '}' * opens
                # Balance brackets 
                obrak = t.count('[') - t.count(']')
                if obrak > 0: t += ']' * obrak
                # Clean up trailing commas before closing marks
                t = re.sub(r',\s*([\]}])', r'\1', t)
                
                try: return json.loads(t)
                except:
                    # Final attempt: try to close a mid-sentence truncation
                    try: return json.loads(t + '"' + '}' * 10) # Very aggressive
                    except: return {}

            # Attempt 2: Direct parse
            try:
                raw_json = json.loads(json_str)
            except json.JSONDecodeError:
                # Attempt 3: Cleaned/Repaired parse
                raw_json = fix_and_parse(json_str)
            
            # Attempt 4: Surgical extraction of individual indices (if full parse failed or part missing)
            if not isinstance(raw_json, dict) or len(raw_json) < len(batch_data):
                surgical = {}
                for i in range(len(batch_data)):
                    search_key = '"%d":' % i
                    k_idx = json_str.find(search_key)
                    if k_idx == -1: continue
                    
                    # Target start of value object
                    v_start = json_str.find('{', k_idx + len(search_key))
                    if v_start == -1: continue
                    
                    # Find potential end (next index or end of string)
                    next_key = '"%d":' % (i + 1)
                    v_end = json_str.find(next_key, v_start)
                    if v_end == -1: v_end = len(json_str)
                    
                    chunk = json_str[v_start:v_end].strip().rstrip(',').rstrip('}')
                    parsed_chunk = fix_and_parse(chunk)
                    if parsed_chunk:
                        surgical[str(i)] = parsed_chunk
                
                # Merge or replace
                if isinstance(raw_json, dict):
                    for k, v in surgical.items():
                        if k not in raw_json or not raw_json[k]:
                            raw_json[k] = v
                else:
                    raw_json = surgical

            # If still nothing, log snippet
            if not raw_json:
                 snippet = (response[:150] + "...") if len(response) > 150 else response
                 log_fn(f"   [-] Batch JSON repair failed. Start of response: {snippet}", "err")
            
            for idx, (ea, node, code, strings) in enumerate(batch_data):
                res = raw_json.get(str(idx), {})
                # Normalize and ensure all keys exist
                if not isinstance(res, dict): res = {"one_liner": str(res)}
                if "confidence" not in res: res["confidence"] = 70
                if "risk_tag" in res and isinstance(res["risk_tag"], str):
                    res["risk_tag"] = res["risk_tag"].lower().strip()
                else:
                    res["risk_tag"] = "pending"
                if "bullets" not in res: res["bullets"] = [res.get("one_liner", "Analyzed via batch.")]
                if "suspicious" not in res: res["suspicious"] = []
                
                # PERSIST PER FUNCTION (IDB)
                idaapi.execute_sync(lambda e=ea, r=res: save_to_idb(e, json.dumps(r), tag=85), idaapi.MFF_WRITE)
                _analysis_cache[ea] = res.get("one_liner", "")

                # PERSIST ARTIFACTS (Disk)
                save_decompiled_to_disk(ea, node.name, code, output_dir)
                # Save readable code artifact
                clean_code = res.get("clean_code")
                if clean_code and isinstance(clean_code, str) and len(clean_code.strip()) > 20:
                    save_readable_to_disk(ea, node.name, clean_code.strip(), output_dir)
                
                # We retain clean_code in 'res' for the build_function_markdown_piece call
                
                safe_name = re.sub(r'[^A-Za-z0-9_]', '_', node.name)[:60]
                json_path = os.path.join(output_dir, "analysis", "%s_0x%X.json" % (safe_name, ea))
                try:
                    os.makedirs(os.path.dirname(json_path), exist_ok=True)
                    with open(json_path, 'w') as f:
                        json.dump(res, f, indent=2)
                except: pass

                t_list = []
                for t in res.get("semantic_tags", []):
                    if len(t_list) >= 5: break
                    t_list.append(str(t).upper().strip())
                node.semantic_tags = t_list
                # Always advance node status
                node.status = "preliminary"
                node.confidence = max(0, min(100, int(res.get("confidence", 70))))
                results.append((node, res))
                log_fn(f"   [+] Batch: Analyzed {node.name} (Risk: {res['risk_tag']} {node.confidence}%)", "ok")
        else:
            snippet = (response[:100] + "...") if len(response) > 100 else response
            log_fn(f"   [-] Batch JSON parsing failed (No '{{' or '}}' found). First 100 chars: {snippet}", "err")
    except Exception as e:
        log_fn(f"   [-] Batch processing error: {e}", "err")

    return results

# --- REDUNDANT MARKDOWN GENERATORS REMOVED (MOVED TO report_generator.py) ---
# --- CONSOLIDATED REPORTING MOVED TO report_generator.py ---

class AnalysisWorker(QThread):
    log_signal = Signal(str, str)             # (message, level)
    progress_signal = Signal(int, int, str)   # (current, total, func_name)
    func_updated_signal = Signal(object, str, str, int)  # (ea, old_name, new_name, confidence)
    markdown_updated_signal = Signal(str)     # (output_dir)
    finished_signal = Signal(str)             # (output_dir)
    cooldown_progress_signal = Signal(int, int)  # (current, total)
    char_count_signal = Signal(int, int)         # (current, max)
    llm_state_signal = Signal(str)               # (state: 'requesting'|'receiving'|'idle')
    stage_signal = Signal(str)                   # (stage_name)

    def __init__(self, entry_ea, graph, do_var_rename=True, do_func_comment=True, do_analysis_rename=False, max_workers=5, batch_funcs=5, batch_lines=300):
        """Initialize analysis worker with the built graph."""
        super(AnalysisWorker, self).__init__()
        self.entry_ea = entry_ea
        self.graph = graph
        self._stop = False
        self.do_refinement = True
        self.do_var_rename = do_var_rename
        self.do_func_comment = do_func_comment
        self.do_analysis_rename = do_analysis_rename
        self.max_workers = max_workers
        self.batch_funcs = batch_funcs
        self.batch_lines = batch_lines
        self.total_vars_renamed = 0
        self.total_funcs_commented = 0

    def stop(self):
        """Cancel the analysis worker."""
        self._stop = True
        _ai_mod.AI_CANCEL_REQUESTED = True

    def run(self):
        """Execute the Analysis Phase 2 pipeline (Stages 4-7).

        Architecture contract
        ─────────────────────
        Stage 4  — Initial Code Analysis Assessment + Get Readable C code
        Stage 5  — Contextual Malicious Code Analysis Refinement
        Stage 6  | Malicious Code Analysis Report Synthesis
                 | Logic Flow Mapping (Execution Map)
        Stage 7  — Interactive HTML Report Generation

        analysis_complete is set True ONLY when:
          • The task loop ran to natural completion (no break due to _stop / AI_CANCEL)
          • The refinement stage also ran to natural completion (or was skipped)
          • Pre-synthesis diagnostic confirms zero in_progress nodes remain
        """
        # Sentinel: guards Stage 5. Never set inside any loop or callback.
        analysis_complete = False
        # Sentinel: set to True if worker was explicitly stopped at any point.
        was_interrupted = False

        try:
            # DEFENSIVE CATCH: PySide signals sometimes serialize dicts of custom objects into dicts of dicts.
            for ea, n in list(self.graph.items()):
                if isinstance(n, dict):
                    node = FuncNode(n.get("ea", ea), n.get("name", f"sub_{ea:X}"))
                    node.depth = n.get("depth", 0)
                    node.callers = n.get("callers", [])
                    node.callees = n.get("callees", [])
                    node.is_library = n.get("is_library", False)
                    node.is_unnamed = n.get("is_unnamed", False)
                    node.is_leaf = n.get("is_leaf", False)
                    raw_status = n.get("status", "pending")
                    # "in_progress" is a transient sentinel — never valid at analysis start.
                    # If PySide serialized it across the signal boundary, reset to "pending"
                    # so Stage 4 re-processes the node rather than skipping it.
                    node.status = raw_status if raw_status != "in_progress" else "pending"
                    node.confidence = n.get("confidence", 0)
                    node.line_count = n.get("line_count", 0)
                    node.is_callback = n.get("is_callback", False)
                    node.preliminary_analysis = n.get("preliminary_analysis")
                    node.context_markers = n.get("context_markers", [])
                    node.pattern_matches = n.get("pattern_matches", [])
                    node.semantic_tags = n.get("semantic_tags", [])
                    node.complexity = n.get("complexity", {"branches": 0, "loops": 0})
                    node.entropy = n.get("entropy", 0.0)
                    node.analysis_wave_confidence = n.get("analysis_wave_confidence", n.get("wave_conf", 0))
                    self.graph[ea] = node
            
            # Sanitize entire graph: "in_progress" must never survive across runs.
            # Any node in this state was interrupted mid-batch and should re-enter Stage 4.
            for _n in self.graph.values():
                if isinstance(_n, FuncNode) and _n.status == "in_progress":
                    _n.status = "pending"
            
            # --- PROACTIVE LIBRARY/SYS RE-CHECK ---
            # Catch cases where whitelist was updated (e.g. pformat added to renamer.py) 
            # but existing graph session already has them as not-library.
            for node in self.graph.values():
                if not node.is_library and is_library_like(node.ea, node.name):
                    node.is_library = True
                    node.status = "Library"
                    node.risk_tag = "benign"
                    node.confidence = 100
            # ---------------------------------------

            ai_cfg = build_ai_cfg_from_config()
            output_dir = get_output_dir()
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            entry_node = self.graph.get(self.entry_ea)
            entry_name = entry_node.name if entry_node else f"sub_{self.entry_ea:X}"

            def log_fn(msg, lvl='info'): self.log_signal.emit(msg, lvl)

            log_fn("\n" + "=" * 40 + "\n# PHASE 2: DEEP MALICIOUS CODE ANALYSIS\n" + "=" * 40, "info")

            def log_stage(stage_no, title, extra=''):
                name = f"STAGE {stage_no} - {title}"
                self.stage_signal.emit(name)
                banner = "\n" + ("=" * 6) + f" {name} " + ("=" * 6)
                if extra: banner += f"  [{extra}]"
                log_fn(banner, "info")

            # ── STAGE 4 — Initial Malicious Code Analysis Assessment (Bottom-Up approach) ────────────
            candidates = [n for n in self.graph.values()
                          if not n.is_library and n.status in ("pending", "renamed")]
            total_total = len(candidates)

            t_stage4 = time.time()
            log_stage('4', "Initial Malicious Code Analysis Assessment (Bottom-Up approach)", f"{total_total} functions")
            log_fn("Traversing from leaf routines to parent functions for baseline understanding.", "info")

            header = write_markdown_header(output_dir, entry_name, self.entry_ea, total_total, ts)
            if header:
                self.markdown_updated_signal.emit(header)

            # Circular Wave Discovery
            candidate_eas = [n.ea for n in candidates]
            waves = get_analysis_waves(self.graph, candidate_eas)
            log_fn(f"Discovery: Identified {len(waves)} rounds of dependency patterns.", "info")
            
            analyzed_eas = set()
            completed = 0
            ts_start_ana = time.time()
            
            # Ensure artifact directories exist
            os.makedirs(os.path.join(output_dir, "decomp"), exist_ok=True)
            os.makedirs(os.path.join(output_dir, "analysis"), exist_ok=True)

            # Step 4 Loop: Process in Rounds (Bottom-Up)
            stage4_loop_complete = False
            for round_idx, wave_eas in enumerate(waves):
                if self._stop or _ai_mod.AI_CANCEL_REQUESTED: break
                
                # Step 3b: gather wave pseudocode + ASM counts (Read Phase)
                res_data_ana = {}
                def _gather_wave():
                    for ea in wave_eas:
                        if self._stop: break
                        c = get_code_fast(ea) or ""
                        res_data_ana[ea] = c
                        node = self.graph.get(ea)
                        if node:
                            try:
                                f = ida_funcs.get_func(ea)
                                node._asm_count = len(list(idautils.FuncItems(f.start_ea))) if f else 0
                                # GATHER TECHNICAL INDICATORS (Stage 4 Improvement)
                                node.complexity = count_cfg_complexity(ea)
                                node.entropy = calculate_data_entropy(ea)
                            except: 
                                node._asm_count = 0
                                node.complexity = {"branches": 0, "loops": 0}
                                node.entropy = 0.0
                idaapi.execute_sync(_gather_wave, idaapi.MFF_READ)

                # Step 3c: Single task generation for this wave (batching disabled for Stage 4)
                wave_tasks = []
                for ea in wave_eas:
                    node = self.graph[ea]
                    if not node: continue
                    c = res_data_ana.get(ea, "")
                    lc = len(c.splitlines()); node.line_count = lc
                    
                    # HEURISTIC FAST-PATH (Stage 4 Improvement)
                    interest = calculate_interest_score(node)
                    is_trivial = (interest == 0 and getattr(node, '_asm_count', 0) <= 12 and lc <= 8)
                    
                    if is_trivial:
                        dummy_res = {
                            "one_liner": "Trivial or wrapper routine (heuristic).", 
                            "summary": "Code performs basic operations with no heuristic indicators of sensitivity.",
                            "bullets": ["Trivial implementation"], 
                            "confidence": 100, 
                            "risk_tag": "benign",
                            "semantic_tags": ["TRIVIAL"]
                        }
                        node.status = "preliminary" # Mark as having initial analysis
                        node.confidence = 100
                        node.semantic_tags = ["TRIVIAL"]
                        _analysis_cache[ea] = dummy_res["one_liner"]
                        def _sd(ea_val=ea, dr=dummy_res): save_to_idb(ea_val, json.dumps(dr), tag=85)
                        idaapi.execute_sync(_sd, idaapi.MFF_WRITE)
                        completed += 1
                        self.func_updated_signal.emit(ea, node.name, node.name, 100)
                        analyzed_eas.add(ea)
                        continue

                    # Process every function individually (single task) to avoid token/timeout issues
                    # with high-quality code generation in Stage 4.
                    wave_tasks.append(("single", node))

                # Step 3d: Sequential Task Execution for this Round
                for task_idx, (task_type, payload) in enumerate(wave_tasks):
                    if self._stop or _ai_mod.AI_CANCEL_REQUESTED: break
                    current_task_nodes = []
                    processed_nodes = set()  # pre-init so finally can always reference it safely
                    try:
                        if task_type == "single":
                            node = payload; node.status = "in_progress"; current_task_nodes = [node]
                            node.stage4_status = "IN_PROGRESS"
                            self.func_updated_signal.emit(node.ea, node.name, node.name, 0)
                            
                            try:
                                res = analyze_single_function(
                                    node.ea, node, self.graph, output_dir, ai_cfg, analyzed_eas, log_fn, mode="preliminary", 
                                    char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                                    cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                                    llm_state_cb=lambda s: self.llm_state_signal.emit(s)
                                )
                                results = [("single", node, res)] if res else []
                            except Exception as e:
                                log_fn(f"   [-] Assessment failed for {node.name}: {e}", "err")
                                results = []
                        else:  # batch
                            batch = payload
                            for ea, n, _ in batch:
                                n.status = "in_progress"; current_task_nodes.append(n)
                                n.stage4_status = "IN_PROGRESS"
                                self.func_updated_signal.emit(n.ea, n.name, n.name, 0)
                            log_fn(f"   [*] Analyzing batch of {len(batch)} functions...", "info")
                            try:
                                raw_results = analyze_batch_functions(
                                    batch, self.graph, output_dir, ai_cfg, analyzed_eas, log_fn,
                                    char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                                    cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                                    llm_state_cb=lambda s: self.llm_state_signal.emit(s)
                                )
                                results = [("batch", n, r) for n, r in raw_results] if raw_results else []
                            except Exception as e:
                                log_fn(f"   [-] Batch analysis failed: {e}", "err")
                                results = []

                            # If batch produced no results (e.g. JSON parse error) — retry each node individually
                            if not results:
                                succeeded_in_batch = {n for _, n, _ in results}
                                failed_nodes = [(r_ea, r_n, r_c) for r_ea, r_n, r_c in batch if r_n not in succeeded_in_batch]
                                if failed_nodes:
                                    log_fn(f"   [~] Retrying {len(failed_nodes)} failed batch nodes individually...", "warn")
                                    for r_ea, r_node, _ in failed_nodes:
                                        try:
                                            r_res = analyze_single_function(
                                                r_node.ea, r_node, self.graph, output_dir, ai_cfg, analyzed_eas, log_fn, mode="preliminary",
                                                char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                                                cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                                                llm_state_cb=lambda s: self.llm_state_signal.emit(s)
                                            )
                                            if r_res:
                                                results.append(("single", r_node, r_res))
                                        except Exception as re_e:
                                            log_fn(f"   [-] Retry failed for {r_node.name}: {re_e}", "err")


                        # Record & Export
                        processed_nodes = set()  # reset for this task's results
                        for r_type, node, result in results:
                            processed_nodes.add(node)
                            ea = node.ea; analyzed_eas.add(ea)
                            node.status = "preliminary"; node.confidence = result.get("confidence", 0)
                            node.stage4_status = "OK"
                            _analysis_cache[ea] = result.get("one_liner", "")

                            # Step 3e: Apply Renames first
                            if self.do_analysis_rename:
                                def _sr(ea=ea, n=node, rs=result): apply_function_rename_from_analysis(ea, n, rs, log_fn)
                                idaapi.execute_sync(_sr, idaapi.MFF_WRITE)
                            if self.do_var_rename:
                                var_map = extract_variable_renames_from_analysis(result, res_data_ana.get(ea, ""))
                                if var_map:
                                    def _sv(): apply_variable_renames_in_ida(ea, var_map, log_fn)
                                    idaapi.execute_sync(_sv, idaapi.MFF_WRITE)
                            if self.do_func_comment:
                                def _sc(): apply_function_comment(ea, result, log_fn)
                                idaapi.execute_sync(_sc, idaapi.MFF_WRITE)

                            # Step 3f: Fetch Fresh Code for artifacts
                            _fresh_res = [""]
                            def _fetch_fresh(): 
                                ida_hexrays.mark_cfunc_dirty(ea)
                                _fresh_res[0] = get_code_fast(ea, max_len=100000) or res_data_ana.get(ea, "")
                            idaapi.execute_sync(_fetch_fresh, idaapi.MFF_READ)
                            fresh_c = _fresh_res[0]

                            # Save Artifacts
                            p_json, _ = get_function_artifact_path(output_dir, "analysis", ea, node.name, "json")
                            with open(p_json, 'w', encoding='utf-8') as f:
                                json.dump(result, f, indent=2)
                            save_decompiled_to_disk(ea, node.name, fresh_c, output_dir)

                            md_piece = build_function_markdown_piece(ea, node, result, self.graph, code=fresh_c)
                            if md_piece:
                                append_function_to_markdown(output_dir, md_piece)
                                self.markdown_updated_signal.emit(md_piece)

                            completed += 1
                            self.func_updated_signal.emit(ea, node.name, node.name, node.confidence)
                            self.progress_signal.emit(completed, total_total, node.name)

                         # Cooldown
                        if CONFIG.deep_cooldown > 0 and not self._stop and task_idx < len(wave_tasks) - 1:
                            total_ticks = int(CONFIG.deep_cooldown * 10)
                            for tick in range(total_ticks):
                                if self._stop: break
                                self.cooldown_progress_signal.emit(tick + 1, total_ticks)
                                time.sleep(0.1)
                            self.cooldown_progress_signal.emit(0, 100)

                    except Exception as e:
                        log_fn(f"   [!] Fatal error in round processing: {e}", "err")
                        import traceback; log_fn(traceback.format_exc(), "err")
                    finally:
                        # Graceful recovery: ALWAYS runs, even after exceptions in Record & Export.
                        # Any node that was set to "in_progress" but didn't make it into
                        # processed_nodes (e.g. due to a mid-loop exception) is marked "error"
                        # here instead of being left permanently stranded.
                        for task_node in current_task_nodes:
                            if task_node not in processed_nodes:
                                task_node.status = "error"
                                task_node.stage4_status = "ERROR"
                                self.func_updated_signal.emit(task_node.ea, task_node.name, task_node.name, 0)
            else:
                stage4_loop_complete = not self._stop

            log_fn("Initial Malicious Code Analysis Assessment stage complete in %.1fs — %d/%d analyzed." % (
                time.time() - t_stage4, completed, total_total), "ok")

            # ── STAGE 5: CONTEXTUAL MALICIOUS CODE ANALYSIS REFINEMENT ────────────────────────
            # Top-down re-analysis for risk assessment.
            # Stage 5 is the universal fallback: pick up ANY non-library node that is not
            # yet fully resolved (analyzed / error).  This covers three cases:
            #   (1) "preliminary"  — normal Stage 4 graduates
            #   (2) "in_progress"  — Stage 4 casualties (AI call failed mid-batch)
            #   (3) "pending" / "renamed" — nodes the Stage 4 wave loop never reached
            _UNRESOLVED = ("preliminary", "in_progress", "pending", "renamed")
            context_candidates = [n for n in self.graph.values()
                                  if n.status in _UNRESOLVED
                                  and not n.is_library]
            # Normalise all pre-preliminary statuses → preliminary so Stage 5
            # processes them with the contextual analysis path cleanly.
            for _n in context_candidates:
                if _n.status != "preliminary":
                    log_fn(f"   [~] Stage 5 rescue: {_n.name} (was '{_n.status}') — queuing for refinement.", "warn")
                    _n.status = "preliminary"
            total_ctx = len(context_candidates)
            stage5_complete = False

            if not self._stop and stage4_loop_complete and total_ctx > 0:
                t_stage5 = time.time()
                log_stage('5', "CONTEXTUAL MALICIOUS CODE ANALYSIS REFINEMENT", f"{total_ctx} functions")
                log_fn("Contextual malicious code analysis refinement stage: refining risks top-down (%d functions)" % total_ctx, "info")
                
                # Order by depth: entry points first (0, 1, 2...)
                context_candidates.sort(key=lambda n: n.depth)
                
                completed_ctx = 0
                for task_idx, node in enumerate(context_candidates):
                    if self._stop or _ai_mod.AI_CANCEL_REQUESTED:
                        was_interrupted = True
                        break
                    
                    ea = node.ea
                    node.status = "in_progress"
                    node.stage5_status = "IN_PROGRESS"
                    self.func_updated_signal.emit(ea, node.name, node.name, 0)
                    
                    log_fn("Contextual malicious code analysis re-analysis of %s..." % node.name, "info")
                    self.llm_state_signal.emit("requesting")
                    
                    try:
                        # Build context for Contextual Malicious Code Analysis Refinement (Synchronized)
                        ctx_res = {}
                        def _sync_ctx():
                            ctx_res["context"] = build_caller_context(node, self.graph)
                        idaapi.execute_sync(_sync_ctx, idaapi.MFF_READ)
                        context = ctx_res.get("context", {})
                        
                        result = analyze_with_context(
                            ea, node, self.graph, output_dir, ai_cfg, analyzed_eas, context, log_fn,
                            char_count_cb=lambda c, m: self.char_count_signal.emit(c, m),
                            cooldown_cb=lambda c, t: self.cooldown_progress_signal.emit(c, t),
                            llm_state_cb=lambda s: self.llm_state_signal.emit(s)
                        )
                        self.llm_state_signal.emit("idle")
                        
                        if result:
                            node.status = "analyzed"
                            node.stage5_status = "OK"
                            node.confidence = result.get("confidence", 100)
                            # Sync the final risk decision from Stage 5 back into the node.
                            # IMPORTANT: result["risk_tag"] here is the POST-determine_risk_with_context
                            # value (may have been UPGRADED or DOWNGRADED from the raw AI output).
                            raw_risk = str(result.get("risk_tag") or "benign").lower().strip()
                            node.risk_tag = raw_risk if raw_risk in ("malicious", "suspicious", "benign") else "benign"
                            result["risk_tag"] = node.risk_tag  # ensure result dict is consistent

                            # ── Flush final authoritative risk to storage ─────────────────────
                            # Both IDB and disk JSON were written INSIDE analyze_single_function,
                            # BEFORE determine_risk_with_context ran — so they may have a stale
                            # risk value.  Re-patch just the risk_tag and re-write both stores.
                            try:
                                raw_stored = load_from_idb(ea, tag=85)
                                stored = json.loads(raw_stored) if raw_stored else {}
                                if stored.get("risk_tag") != node.risk_tag:
                                    stored["risk_tag"] = node.risk_tag
                                    idaapi.execute_sync(
                                        lambda e=ea, s=stored: save_to_idb(e, json.dumps(s), tag=85),
                                        idaapi.MFF_WRITE
                                    )
                                    # Patch disk analysis JSON too
                                    _sn = re.sub(r'[^A-Za-z0-9_]', '_', node.name)[:60]
                                    _jp = os.path.join(output_dir, "analysis", "%s_0x%X.json" % (_sn, ea))
                                    if os.path.isfile(_jp):
                                        try:
                                            with open(_jp, "r", encoding="utf-8") as _f:
                                                _d = json.load(_f)
                                            _d["risk_tag"] = node.risk_tag
                                            with open(_jp, "w", encoding="utf-8") as _f:
                                                json.dump(_d, _f, indent=2)
                                        except: pass
                            except: pass
                            # ─────────────────────────────────────────────────────────────────

                            _analysis_cache[ea] = result.get("one_liner", "")

                            
                            # Re-apply rename if needed (context might suggest better name)
                            if self.do_analysis_rename:
                                res_name = {"name": node.name}
                                def _sync_rename_ctx(ea=ea, n=node, res=result):
                                    res_name["name"] = apply_function_rename_from_analysis(ea, n, res, log_fn)
                                idaapi.execute_sync(_sync_rename_ctx, idaapi.MFF_WRITE)
                            
                            # Re-apply comment
                            if self.do_func_comment:
                                idaapi.execute_sync(
                                    lambda ea=ea, res=result: apply_function_comment(ea, res, log_fn),
                                    idaapi.MFF_WRITE)
                            
                            # Variable renames in Stage 5 (Contextual Refinement)
                            if self.do_var_rename:
                                log_fn(f"  Trace: Contextual Malicious Code Analysis Refinement var rename for 0x{ea:X}", 'info')
                                # Fetch FRESH code (not disk cache) so lvar names match
                                # current IDA state, not the stale pre-rename Stage 4 snapshot.
                                _fresh_var_code = [""]
                                def _fetch_var_code(e=ea):
                                    _fresh_var_code[0] = get_code_fast(e) or ""
                                idaapi.execute_sync(_fetch_var_code, idaapi.MFF_READ)
                                var_code = _fresh_var_code[0]
                                var_map = extract_variable_renames_from_analysis(result, var_code)
                                if var_map:
                                    var_map = validate_variable_renames(ea, var_map, log_fn)
                                    # Synchronize variable renaming for Contextual Malicious Code Analysis Refinement
                                    if var_map:
                                        _var_res = [0]
                                        def _sync_p2_vars():
                                            _var_res[0] = apply_variable_renames_in_ida(ea, var_map, log_fn)
                                        idaapi.execute_sync(_sync_p2_vars, idaapi.MFF_WRITE)
                                        
                                        self.total_vars_renamed += _var_res[0]
                                        if _var_res[0] > 0:
                                            self.func_updated_signal.emit(ea, node.name, node.name, node.confidence)
                                else:
                                    log_fn(f"  Trace: Contextual Malicious Code Analysis Refinement no valid var renames for 0x{ea:X}", 'info')
                            
                            # Append updated section to markdown
                            # Note: Usually Stage 1 creates the section, Stage 2 could replace it or append.
                            # For simplicity we append it as "Refined Analysis" or similar.
                            md_section = build_function_markdown_piece(ea, node, result, self.graph, code="")
                            self.func_updated_signal.emit(ea, node.name, node.name, node.confidence)
                            self.markdown_updated_signal.emit(md_section)
                            
                        else:
                            node.status = "error"
                            self.func_updated_signal.emit(ea, node.name, node.name, 0)
                            
                    except Exception as ex:
                        self.llm_state_signal.emit("idle")
                        log_fn("Contextual re-analysis error for %s: %s" % (node.name, ex), "err")
                        node.status = "error"
                        self.func_updated_signal.emit(ea, node.name, node.name, 0)
                        
                    completed_ctx += 1
                    self.progress_signal.emit(completed_ctx, total_ctx, node.name)
                    
                    # Per-task cooldown
                    if CONFIG.deep_cooldown > 0 and not self._stop and task_idx < total_ctx - 1:
                        total_ticks = int(CONFIG.deep_cooldown * 10)
                        for tick in range(total_ticks):
                            if self._stop: break
                            self.cooldown_progress_signal.emit(tick + 1, total_ticks)
                            time.sleep(0.1)
                        self.cooldown_progress_signal.emit(0, 100)

                # Defensive flush: drain any in_progress nodes that didn't get resolved
                # (e.g. interrupted by break, or edge-case where result was None)
                for _n in self.graph.values():
                    if not _n.is_library and _n.status == "in_progress":
                        log_fn(f"   [~] Stage 5 flush: {_n.name} still in_progress — marking error", "warn")
                        _n.status = "error"
                        self.func_updated_signal.emit(_n.ea, _n.name, _n.name, 0)

                stage5_complete = True
                t_stage5_end = time.time()
                log_fn("Stage 5 complete in %.1fs — %d/%d refined." % (
                    t_stage5_end - t_stage5, completed_ctx, total_ctx), "ok")
            else:
                stage5_complete = True # Skipped stage

            # ── STAGE 6: MALICIOUS CODE ANALYSIS REPORT SYNTHESIS ───────────────────────────
            # ── SINGLE GUARANTEED ENTRY POINT ─────────────────────────────
            # This block is the ONLY place Stage 6 is ever triggered.
            # It is structurally impossible for it to fire mid-loop because
            # analysis_complete can only become True here, after both Stage 4
            # and Stage 5 have fully completed.
            # ────────────────────────────────────────────────────────────────

            # Pre-synthesis diagnostic
            _ANALYZED_STATS = ("analyzed", "preliminary", "contextual")
            non_lib_nodes = [n for n in self.graph.values() if not n.is_library]
            n_total    = len(non_lib_nodes)
            n_analyzed = sum(1 for n in non_lib_nodes if n.status in _ANALYZED_STATS)
            n_error    = sum(1 for n in non_lib_nodes if n.status == "error")
            n_pending  = sum(1 for n in non_lib_nodes if n.status in ("pending", "renamed"))
            n_inprog   = sum(1 for n in non_lib_nodes if n.status == "in_progress")
            pct        = (n_analyzed / n_total * 100) if n_total > 0 else 0

            log_fn("", "info")
            log_fn("─── Pre-synthesis diagnostic ───────────────────────────", "info")
            log_fn("  Total non-library functions : %d" % n_total,    "info")
            log_fn("  Analyzed                    : %d" % n_analyzed,  "info")
            log_fn("  Errors                      : %d" % n_error,     "info")
            log_fn("  Pending / unvisited         : %d" % n_pending,   "info")
            log_fn("  Still in-progress           : %d" % n_inprog,    "info")
            log_fn("  Coverage                    : %.0f%%" % pct,     "info")
            log_fn("────────────────────────────────────────────────────────", "info")

            # Gate 1: worker was stopped or AI cancel was requested
            if self._stop or was_interrupted:
                log_fn("Final summary SKIPPED — analysis was interrupted by user or rate-limit.", "warn")
                finalize_markdown(output_dir, self.graph,
                    "⚠️ Final summary not generated — analysis was interrupted. "
                    "Resume to continue analyzing the remaining functions.",
                    self.entry_ea)
                self.finished_signal.emit(output_dir)

            # Gate 2: any node is still in-progress — auto-heal and continue rather than abort
            elif n_inprog > 0:
                log_fn("Pre-synthesis: %d node(s) still in_progress — auto-healing to 'error' and continuing." % n_inprog, "warn")
                for _n in self.graph.values():
                    if not _n.is_library and _n.status == "in_progress":
                        _n.status = "error"
                        self.func_updated_signal.emit(_n.ea, _n.name, _n.name, 0)
                # Recompute counts after healing
                _ANALYZED_STATS = ("analyzed", "preliminary", "contextual")
                non_lib_nodes = [n for n in self.graph.values() if not n.is_library]
                n_total    = len(non_lib_nodes)
                n_analyzed = sum(1 for n in non_lib_nodes if n.status in _ANALYZED_STATS)
                n_error    = sum(1 for n in non_lib_nodes if n.status == "error")
                n_pending  = sum(1 for n in non_lib_nodes if n.status in ("pending", "renamed"))
                n_inprog   = 0
                pct        = (n_analyzed / n_total * 100) if n_total > 0 else 0
                log_fn("  Recount after heal — analyzed: %d  errors: %d  coverage: %.0f%%" % (n_analyzed, n_error, pct), "warn")
                # Fall through to Gate 3 check
                if pct < 80 and n_pending > 0:
                    log_fn(
                        "Final summary SKIPPED — only %d/%d functions analyzed (%.0f%%). "
                        "Need 80%% coverage. Use Resume to finish the remaining %d functions."
                        % (n_analyzed, n_total, pct, n_total - n_analyzed - n_error),
                        "warn"
                    )
                    finalize_markdown(output_dir, self.graph,
                        f"⚠️ Final summary not generated — only {n_analyzed}/{n_total} functions analyzed "
                        f"({pct:.0f}%). Resume analysis to cover the remaining functions.",
                        self.entry_ea)
                    self.finished_signal.emit(output_dir)
                else:
                    analysis_complete = True

            # Gate 3: not enough functions analyzed to produce a meaningful summary
            elif pct < 80 and n_pending > 0:
                log_fn(
                    "Final summary SKIPPED — only %d/%d functions analyzed (%.0f%%). "
                    "Need 80%% coverage. Use Resume to finish the remaining %d functions."
                    % (n_analyzed, n_total, pct, n_total - n_analyzed - n_error),
                    "warn"
                )
                finalize_markdown(output_dir, self.graph,
                    f"⚠️ Final summary not generated — only {n_analyzed}/{n_total} functions analyzed "
                    f"({pct:.0f}%). Resume analysis to cover the remaining functions.",
                    self.entry_ea)
                self.finished_signal.emit(output_dir)

            else:
                # ✅ All gates passed — analysis is complete enough for synthesis
                analysis_complete = True

                t_stage6 = time.time()
                log_stage('6', "MALICIOUS CODE ANALYSIS REPORT SYNTHESIS")
                log_fn("Generating executive program summary (%d/%d analyzed, %d errors)..."
                       % (n_analyzed, n_total, n_error), "ok")

                entry_name = self.graph[self.entry_ea].name if self.entry_ea in self.graph else hex(self.entry_ea)
                digest, entry_children_count, all_strings = build_analysis_digest(self.graph, self.entry_ea, log_fn=log_fn)
                sections = {}

                self.llm_state_signal.emit("requesting")
                try:
                    sections["assessment"] = generate_malware_analysis_assessment(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Executive summary (Malware analysis)", "ok")
                except Exception as e:
                    log_fn(f"Section failed: assessment - {e}", "err")
                    sections["assessment"] = f"Error generating assessment: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["overview"] = generate_technical_overview(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Technical Code analysis overview", "ok")
                except Exception as e:
                    log_fn(f"Section failed: overview - {e}", "err")
                    sections["overview"] = f"Error generating overview: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["execution_flow"] = generate_execution_flow_overview(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Execution Flow Overview", "ok")
                except Exception as e:
                    log_fn(f"Section failed: execution_flow - {e}", "err")
                    sections["execution_flow"] = f"Error generating execution flow: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["c2_analysis"] = generate_c2_analysis(digest, ai_cfg, log_fn)
                    log_fn("Section complete: C2/Backdoor Analysis", "ok")
                except Exception as e:
                    log_fn(f"Section failed: c2_analysis - {e}", "err")
                    sections["c2_analysis"] = f"Error generating C2 analysis: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["persistence"] = generate_persistence_mechanisms(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Persistence Mechanisms", "ok")
                except Exception as e:
                    log_fn(f"Section failed: persistence - {e}", "err")
                    sections["persistence"] = f"Error generating persistence analysis: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["recon_infostealer"] = generate_recon_infostealer_analysis(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Reconnaissance or Info Stealer", "ok")
                except Exception as e:
                    log_fn(f"Section failed: recon_infostealer - {e}", "err")
                    sections["recon_infostealer"] = f"Error generating recon analysis: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["file_registry_interaction"] = generate_file_registry_interaction(digest, ai_cfg, log_fn)
                    log_fn("Section complete: File / Registry / Process Interaction", "ok")
                except Exception as e:
                    log_fn(f"Section failed: file_registry_interaction - {e}", "err")
                    sections["file_registry_interaction"] = f"Error generating interaction analysis: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["api_resolving"] = generate_api_resolving_logic(digest, ai_cfg, log_fn)
                    log_fn("Section complete: API Hashing / Resolving / PEB Walk", "ok")
                except Exception as e:
                    log_fn(f"Section failed: api_resolving - {e}", "err")
                    sections["api_resolving"] = f"Error generating API resolving analysis: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["anti_analysis"] = generate_anti_analysis_logic(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Packer/Obfuscation or Anti-Analysis", "ok")
                except Exception as e:
                    log_fn(f"Section failed: anti_analysis - {e}", "err")
                    sections["anti_analysis"] = f"Error generating anti-analysis logic: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["crypto_artifacts"] = generate_crypto_artifacts(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Cryptographic Artifacts", "ok")
                except Exception as e:
                    log_fn(f"Section failed: crypto_artifacts - {e}", "err")
                    sections["crypto_artifacts"] = f"Error generating crypto findings: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["capabilities"] = generate_key_capabilities(digest, ai_cfg, log_fn)
                    log_fn("Section complete: General Capability Discovery", "ok")
                except Exception as e:
                    log_fn(f"Section failed: capabilities - {e}", "err")
                    sections["capabilities"] = f"Error generating general capabilities: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["behavioral"] = generate_behavioral_indicators(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Indicator of Compromise", "ok")
                except Exception as e:
                    log_fn(f"Section failed: behavioral - {e}", "err")
                    sections["behavioral"] = f"Error generating behavioral indicators: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                # Deterministic static sections (Extracted in Stage 7, but logged here for sequence)
                log_fn("Section complete: Suspicious Imports", "ok")
                log_fn("Section complete: TTP Mapping (MITRE ATTACK)", "ok")

                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                log_fn("Section complete: Strings analysis", "ok")
                log_fn("Section complete: Call chain analysis", "ok")

                sections["call_graph"] = get_graph_ascii(self.graph, self.entry_ea)
                log_fn("Section complete: Call Graph (Tree View)", "ok")
                self.markdown_updated_signal.emit(output_dir)

                # ── Logic Flow Mapping (Execution Map) ────────────────────
                log_fn("Generating deterministic Mermaid.js call-flow storyboard...", "info")
                
                # Fetch all analysis results from IDB for visualization
                analyzed_results_map = {}
                for n in self.graph.values():
                    if not n.is_library:
                        raw_r = load_from_idb(n.ea, tag=85)
                        if raw_r:
                            try: analyzed_results_map[n.ea] = json.loads(raw_r)
                            except: pass
                
                mermaid_code = generate_call_flow_mermaid(
                    self.graph, self.entry_ea, analyzed_results_map, log_fn
                )
                
                # Save Mermaid to its own file
                mermaid_path = os.path.join(output_dir, "callflow.mmd")
                if mermaid_code:
                    try:
                        with open(mermaid_path, 'w', encoding='utf-8') as f:
                            f.write(mermaid_code)
                        log_fn("Section complete: Mermaid Visual Call Flow - HTML (callflow.mmd created)", "ok")
                    except Exception as e:
                        log_fn(f"Error saving callflow.mmd: {e}", "warn")
                else:
                    log_fn("Section skipped: Mermaid Visual Call Flow - HTML (no meaningful custom data)", "info")

                self.llm_state_signal.emit("requesting")
                try:
                    sections["malicious"] = generate_malicious_functions(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Malicious functions", "ok")
                except Exception as e:
                    log_fn(f"Section failed: malicious - {e}", "err")
                    sections["malicious"] = f"Error generating malicious functions: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                self.llm_state_signal.emit("requesting")
                try:
                    sections["suspicious"] = generate_suspicious_functions(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Suspicious functions", "ok")
                except Exception as e:
                    log_fn(f"Section failed: suspicious - {e}", "err")
                    sections["suspicious"] = f"Error generating suspicious functions: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                log_fn("Generating per-function sections...", "info")
                functions_markdown = []
                non_lib_nodes = sorted([n for n in self.graph.values() if not n.is_library], key=lambda x: (x.depth, x.name))
                for node in non_lib_nodes:
                    if self._stop: break
                    self.llm_state_signal.emit("idle")

                    # ── Load richest available result ──────────────────────────
                    # Priority: disk analysis JSON (Stage 5 enriched) > IDB tag 85 (Stage 4)
                    # Rationale: Stage 5 overwrites the disk JSON with contextual_purpose,
                    # risk_logic, refined summary, etc. — IDB may only have the Stage 4 snapshot.
                    res = {}

                    # 1. IDB baseline (Stage 4)
                    raw = load_from_idb(node.ea, tag=85)
                    if raw:
                        try: res = json.loads(raw)
                        except: pass

                    # 2. Disk JSON overlay (Stage 5 — richer, may add/replace any field)
                    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', node.name)[:60]
                    json_path = os.path.join(output_dir, "analysis", "%s_0x%X.json" % (safe_name, node.ea))
                    if os.path.isfile(json_path):
                        try:
                            with open(json_path, "r", encoding="utf-8") as jf:
                                disk_res = json.load(jf)
                            if isinstance(disk_res, dict):
                                # Overlay: disk fields win over IDB fields
                                for k, v in disk_res.items():
                                    # Only override if disk value is non-empty / non-null
                                    if v or v == 0:
                                        res[k] = v
                        except: pass

                    # 3. Always use node's live risk_tag (set by Stage 5, authoritative)
                    node_rt = getattr(node, "risk_tag", "")
                    if node_rt and node_rt not in ("pending", ""):
                        res["risk_tag"] = node_rt

                    # Prefer LLM-authored readable C (readable/), fall back to raw Hex-Rays (decomp/)
                    _raw = (load_readable_from_disk(node.ea, node.name, output_dir)
                            or load_decompiled_from_disk(node.ea, node.name, output_dir))
                    code = cleanup_decompiled_code(_raw) if _raw else None
                    func_md = build_function_markdown_piece(node.ea, node, res, self.graph, code=code)
                    functions_markdown.append(func_md)
                    # Update partially so user sees progress
                    sections["function_analysis"] = "\n\n".join(functions_markdown)
                    self.markdown_updated_signal.emit(output_dir)

                log_fn("Section complete: Function Decomposition", "ok")

                # ── FINAL ASSEMBLY: FULL SOURCE CODE ──────────────────────────
                log_fn("Assembling full malware source code library...", "info")
                sections["full_source"] = assemble_malware_source(self.graph, self.entry_ea, output_dir)
                log_fn("Section complete: full_source", "ok")

                finalize_markdown(output_dir, self.graph, sections, self.entry_ea)

                # Store mermaid in sections for the final report
                sections["mermaid"] = mermaid_code or ""
                sections["execution_map"] = "" # Explicitly empty to avoid leftovers

                self.llm_state_signal.emit("requesting")
                try:
                    sections["risk_assessment"] = generate_risk_assessment(digest, ai_cfg, log_fn)
                    log_fn("Section complete: Risk Assessment", "ok")
                except Exception as e:
                    log_fn(f"Section failed: risk assessment - {e}", "err")
                    sections["risk_assessment"] = f"Error generating risk assessment: {e}"
                self.llm_state_signal.emit("idle")
                self.markdown_updated_signal.emit(output_dir)

                log_fn("Final synthesis complete in %.1fs (Stages 6 & 7)." % (time.time() - t_stage6), "ok")
                self.markdown_updated_signal.emit(output_dir)

                # ── STAGE 7: HTML REPORT ──────────────────────────────────────
                log_stage('7', "HTML REPORT GENERATION", "Interactive report")
                try:
                    html_path = generate_html_report(self.graph, self.entry_ea, output_dir, sections, log_fn=log_fn)
                    if html_path:
                        log_fn(f"HTML report saved: {html_path}", "ok")
                except Exception as _he:
                    import traceback as _tb
                    log_fn(f"HTML report generation failed: {_he}\n{_tb.format_exc()}", "warn")

                self.finished_signal.emit(output_dir)

        except Exception as e:
            import traceback
            self.log_signal.emit(
                "Analysis Worker Fatal Exception: %s\n%s" % (e, traceback.format_exc()), "err")


# === SECTION 4: UI DIALOG & PLUGIN INTEGRATION ===


class SortableTreeItem(QTreeWidgetItem):
    """QTreeWidgetItem with numeric-aware column sorting."""
    # Columns that should sort numerically (by index)
    _NUMERIC_COLS = {2, 3, 5}  # Address(hex), Depth, Confidence%

    def __lt__(self, other):
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        a_text = self.text(col)
        b_text = other.text(col)
        if col in self._NUMERIC_COLS:
            try:
                # Handle hex addresses like 0x1A30
                a_val = int(a_text, 16) if a_text.startswith('0x') or a_text.startswith('0X') else int(a_text.rstrip('%'))
                b_val = int(b_text, 16) if b_text.startswith('0x') or b_text.startswith('0X') else int(b_text.rstrip('%'))
                return a_val < b_val
            except (ValueError, AttributeError):
                pass
        return a_text < b_text



class DeepAnalyzerSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super(DeepAnalyzerSettingsDialog, self).__init__(parent)
        self.setWindowTitle("Deep Analyzer Settings")
        self.resize(500, 520)
        self.setStyleSheet(parent.styleSheet())
        
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        
        # 1. API Settings Tab
        self.api_tab = QWidget()
        self.setup_api_tab()
        self.tabs.addTab(self.api_tab, "API Settings")
        
        # 2. Analysis Configuration Tab
        self.analysis_tab = QWidget()
        self.setup_analysis_tab()
        self.tabs.addTab(self.analysis_tab, "Analysis Configuration")
        
        layout.addWidget(self.tabs)
        
        # Buttons
        btns = QHBoxLayout()
        btns.addStretch()
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.setObjectName("primary")
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        btns.addWidget(self.cancel_btn)
        btns.addWidget(self.save_btn)
        layout.addLayout(btns)

    def setup_api_tab(self):
        layout = QVBoxLayout(self.api_tab)
        
        group = QGroupBox("LLM Provider")
        glay = QGridLayout(group)
        
        glay.addWidget(QLabel("Active Provider:"), 0, 0)
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["OpenAI", "Anthropic", "DeepSeek", "Gemini", "Ollama", "LMStudio", "OpenAICompatible"])
        # Set current
        p_map = {"openai": 0, "anthropic": 1, "deepseek": 2, "gemini": 3, "ollama": 4, "lmstudio": 5, "openaicompatible": 6, "custom": 6}
        self.provider_combo.setCurrentIndex(p_map.get(CONFIG.active_provider.lower(), 0))
        glay.addWidget(self.provider_combo, 0, 1)
        
        layout.addWidget(group)
        
        # We'll show setting for the active provider to keep it clean
        self.api_stack = QTabWidget() # Using a tab widget inside for different providers
        self.api_stack.setTabPosition(QTabWidget.West)
        
        # Add provider-specific sub-tabs
        self.setup_provider_tab("OpenAI", CONFIG.openai_url, CONFIG.openai_key, CONFIG.openai_model)
        self.setup_provider_tab("Anthropic", CONFIG.anthropic_url, CONFIG.anthropic_key, CONFIG.anthropic_model)
        self.setup_provider_tab("DeepSeek", CONFIG.deepseek_url, CONFIG.deepseek_key, CONFIG.deepseek_model)
        self.setup_provider_tab("Gemini", "", CONFIG.gemini_key, CONFIG.gemini_model, no_url=True)
        self.setup_provider_tab("Ollama", CONFIG.ollama_host, "", CONFIG.ollama_model, no_key=True)
        self.setup_provider_tab("LMStudio", CONFIG.lmstudio_url, CONFIG.lmstudio_key, CONFIG.lmstudio_model)
        self.setup_provider_tab("OpenAICompatible", CONFIG.custom_url, CONFIG.custom_key, CONFIG.custom_model)
        
        layout.addWidget(self.api_stack)
        layout.addStretch()

    def setup_provider_tab(self, name, url, key, model, no_url=False, no_key=False):
        w = QWidget()
        l = QVBoxLayout(w)
        g = QGroupBox(f"{name} Settings")
        fl = QGridLayout(g)
        
        row = 0
        if not no_url:
            fl.addWidget(QLabel("Base URL:"), row, 0)
            u_edit = QLineEdit(url)
            fl.addWidget(u_edit, row, 1)
            setattr(self, f"{name.lower()}_url_edit", u_edit)
            row += 1
            
        if not no_key:
            fl.addWidget(QLabel("API Key:"), row, 0)
            k_edit = QLineEdit(key)
            k_edit.setEchoMode(QLineEdit.Password)
            fl.addWidget(k_edit, row, 1)
            setattr(self, f"{name.lower()}_key_edit", k_edit)
            row += 1
            
        fl.addWidget(QLabel("Model:"), row, 0)
        m_edit = QLineEdit(model)
        fl.addWidget(m_edit, row, 1)
        setattr(self, f"{name.lower()}_model_edit", m_edit)
        
        l.addWidget(g)
        l.addStretch()
        self.api_stack.addTab(w, name)

    def setup_analysis_tab(self):
        layout = QVBoxLayout(self.analysis_tab)
        
        # Performance Group
        perf_group = QGroupBox("Performance \u0026 Resources")
        playout = QGridLayout(perf_group)
        
        playout.addWidget(QLabel("Parallel Workers:"), 0, 0)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 20)
        self.workers_spin.setValue(getattr(CONFIG, 'deep_parallel_workers', 1))
        playout.addWidget(self.workers_spin, 0, 1)
        
        playout.addWidget(QLabel("Batch Size (Functions):"), 1, 0)
        self.batch_funcs_spin = QSpinBox()
        self.batch_funcs_spin.setRange(1, 50)
        self.batch_funcs_spin.setValue(getattr(CONFIG, 'deep_batch_size', 10))
        playout.addWidget(self.batch_funcs_spin, 1, 1)
        
        playout.addWidget(QLabel("Max Lines per Function:"), 2, 0)
        self.batch_lines_spin = QSpinBox()
        self.batch_lines_spin.setRange(50, 2000)
        self.batch_lines_spin.setValue(getattr(CONFIG, 'deep_max_lines', 200))
        playout.addWidget(self.batch_lines_spin, 2, 1)
        
        playout.addWidget(QLabel("Batch Cooldown (s):"), 3, 0)
        self.cooldown_spin = QSpinBox()
        self.cooldown_spin.setRange(0, 300)
        self.cooldown_spin.setValue(getattr(CONFIG, 'deep_cooldown', 0))
        playout.addWidget(self.cooldown_spin, 3, 1)
        
        layout.addWidget(perf_group)
        
        # Features Group
        feat_group = QGroupBox("Analysis Features")
        flay = QVBoxLayout(feat_group)
        
        # Only Variable Renaming is user-configurable, everything else is mandatory
        self.do_var_rename_chk = QCheckBox("Automated variable renaming")
        self.do_var_rename_chk.setChecked(getattr(CONFIG, 'deep_do_var_rename', True))
        flay.addWidget(self.do_var_rename_chk)
        
        layout.addWidget(feat_group)
        
        # Naming Group
        naming_group = QGroupBox("Naming Options")
        nlay = QGridLayout(naming_group)
        
        self.deep_use_prefix_chk = QCheckBox("Use Prefix")
        self.deep_use_prefix_chk.setChecked(getattr(CONFIG, 'deep_use_prefix', True))
        nlay.addWidget(self.deep_use_prefix_chk, 0, 0)
        
        self.deep_prefix_edit = QLineEdit(getattr(CONFIG, 'deep_prefix', 'da_'))
        self.deep_prefix_edit.setFixedWidth(80)
        nlay.addWidget(self.deep_prefix_edit, 0, 1)
        
        self.deep_append_addr_chk = QCheckBox("Append address postfix")
        self.deep_append_addr_chk.setChecked(getattr(CONFIG, 'deep_append_address', True))
        nlay.addWidget(self.deep_append_addr_chk, 1, 0)
        
        self.deep_use_0x_chk = QCheckBox("Use 0x prefix for address")
        self.deep_use_0x_chk.setChecked(getattr(CONFIG, 'deep_use_0x', False))
        nlay.addWidget(self.deep_use_0x_chk, 1, 1)
        
        layout.addWidget(naming_group)
        layout.addStretch()

    def save_to_config(self):
        # API Settings
        CONFIG.active_provider = self.provider_combo.currentText().lower()
        
        def _get_val(name, type='url'):
            attr = f"{name.lower()}_{type}_edit"
            if hasattr(self, attr):
                return getattr(self, attr).text().strip()
            return ""

        CONFIG.openai_url = _get_val("OpenAI", "url")
        CONFIG.openai_key = _get_val("OpenAI", "key")
        CONFIG.openai_model = _get_val("OpenAI", "model")
        
        CONFIG.anthropic_url = _get_val("Anthropic", "url")
        CONFIG.anthropic_key = _get_val("Anthropic", "key")
        CONFIG.anthropic_model = _get_val("Anthropic", "model")
        
        CONFIG.deepseek_url = _get_val("DeepSeek", "url")
        CONFIG.deepseek_key = _get_val("DeepSeek", "key")
        CONFIG.deepseek_model = _get_val("DeepSeek", "model")
        
        CONFIG.gemini_key = _get_val("Gemini", "key")
        CONFIG.gemini_model = _get_val("Gemini", "model")
        
        CONFIG.ollama_host = _get_val("Ollama", "url")
        CONFIG.ollama_model = _get_val("Ollama", "model")
        
        CONFIG.lmstudio_url = _get_val("LMStudio", "url")
        CONFIG.lmstudio_key = _get_val("LMStudio", "key")
        CONFIG.lmstudio_model = _get_val("LMStudio", "model")
        
        CONFIG.custom_url = _get_val("OpenAICompatible", "url")
        CONFIG.custom_key = _get_val("OpenAICompatible", "key")
        CONFIG.custom_model = _get_val("OpenAICompatible", "model")
        
        # Analysis Settings
        CONFIG.deep_parallel_workers = self.workers_spin.value()
        CONFIG.deep_batch_size = self.batch_funcs_spin.value()
        CONFIG.deep_max_lines = self.batch_lines_spin.value()
        CONFIG.deep_cooldown = self.cooldown_spin.value()
        

        # Mandatory features (internal defaults)
        CONFIG.deep_do_bottom_up_rename = True
        CONFIG.deep_do_func_comment = True
        CONFIG.deep_do_analysis_rename = True
        CONFIG.deep_do_refinement = True
        
        # Configurable feature
        CONFIG.deep_do_var_rename = self.do_var_rename_chk.isChecked()
        
        CONFIG.deep_use_prefix = self.deep_use_prefix_chk.isChecked()
        CONFIG.deep_prefix = self.deep_prefix_edit.text()
        CONFIG.deep_append_address = self.deep_append_addr_chk.isChecked()
        CONFIG.deep_use_0x = self.deep_use_0x_chk.isChecked()
        

        CONFIG.save()


class DeepAnalyzerDialog(QDialog):
    def _repolish(self, btn):

        """Force Qt to re-evaluate the button style (needed when objectName-based :disabled rules change)."""
        btn.style().unpolish(btn)
        btn.style().polish(btn)
        btn.update()

    def update_action_buttons(self, running=None):
        """Single source of truth for all button enabled/disabled state."""
        if running is None:
            running = (
                (hasattr(self, 'rename_worker') and self.rename_worker and self.rename_worker.isRunning()) or
                (hasattr(self, 'analysis_worker') and self.analysis_worker and self.analysis_worker.isRunning()) or
                (hasattr(self, 'graph_worker') and self.graph_worker and self.graph_worker.isRunning())
            )

        # Stopped/idle state: start enabled, stop disabled
        if not running:
            self.stop_btn.setEnabled(False)
            self.start_btn.setEnabled(True)
        else:
            # Running: only stop enabled
            self.stop_btn.setEnabled(True)
            self.start_btn.setEnabled(False)

        # Force Qt to recompute disabled-state styles for named buttons
        for btn in (self.stop_btn, self.start_btn, getattr(self, 'open_html_btn', None)):
            if btn and hasattr(self, '_repolish'):
                self._repolish(btn)
    
    def __init__(self, parent=None):
        # Pass None as parent to make it a completely separate top-level window 
        # that doesn't stay on top of IDA or minimize/restore with it.
        super(DeepAnalyzerDialog, self).__init__(None)
        self.setWindowTitle("PseudoNote — Deep Analyzer")
        self.resize(1200, 800)
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowMaximizeButtonHint | QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        
        self.setStyleSheet(STYLES_ANALYZER)
        
        # Instance state
        self.entry_ea = None
        self.graph = {}
        self.output_dir = None
        self.rename_worker = None
        self.analysis_worker = None
        self._all_tree_items = {}
        self._stop_requested = False
        
        # Keep reference to prevent GC
        self._progress_ref = None

        self.setup_ui()
        
        # Bug #1: Taxonomy Health Check
        healthy, err = is_taxonomy_healthy()
        if not healthy:
            self.taxonomy_warning.setText(f"⚠️ CRITICAL: Taxonomy Loading Failure - {err}. Malware detection will be severely limited. Classes will default to 'benign'.")
            self.taxonomy_warning.setVisible(True)
            # We don't necessarily disable it if they want to use LLM only, 
            # but we show a big warning. Actually, let's disable it to enforce fix.
            self.start_btn.setEnabled(False)
            self.append_log(f"Taxonomy failure: {err}", "err")
        
        # Auto-load current function, then check for a saved session
        QtCore.QTimer.singleShot(100, self._auto_load_and_restore)
        import pseudonote.plugin as _plugin
        if hasattr(_plugin, '_view_module'):
            _plugin._view_module._deep_analyzer_dlg = self

    def _auto_load_and_restore(self):
        """Load current function and automatically restore the last session if one exists."""
        self.on_use_current_function()
        # After loading the function, try to restore its last analysis
        if self.entry_ea and self.entry_ea != idaapi.BADADDR:
            QtCore.QTimer.singleShot(50, self._try_auto_restore)

    def _try_auto_restore(self):
        """Check if there's a saved analysis session for the current entry EA and restore it."""
        if not self.entry_ea or self.entry_ea == idaapi.BADADDR:
            return

        # Load the saved output directory from the IDB (tag 89)
        saved_dir = [None]
        def _load():
            saved_dir[0] = load_from_idb(self.entry_ea, tag=89)
        try:
            idaapi.execute_sync(_load, idaapi.MFF_READ)
        except Exception:
            return

        out_dir = saved_dir[0]
        if not out_dir or not os.path.isdir(out_dir):
            return  # No previous session or folder was deleted

        g_path = os.path.join(out_dir, "graph.json")
        if not os.path.exists(g_path):
            return

        self.append_log(f"Restoring previous session from: {os.path.basename(out_dir)}", "ok")
        
        # Re-use the existing on_resume logic, but pointed at the saved directory
        # We temporarily override get_output_dir's global so on_resume finds the right folder
        global _SESSION_OUTPUT_DIR
        _SESSION_OUTPUT_DIR = out_dir
        self.output_dir = out_dir
        self.on_resume()

    def setup_ui(self):
        # ===================== ROOT LAYOUT =====================
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Global stylesheet (clean, modern, consistent)
        # Stylesheet is already set in __init__ using STYLES_ANALYZER

        # ===================== HEADER =====================
        header = QHBoxLayout()
        title = QLabel("Deep Analyzer")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        subtitle = QLabel("Complete Function/Variable Renaming + Deep LLM and Contextual Analysis + Summary")
        subtitle.setStyleSheet("color: #636366; font-size: 11px; margin-left:8px;")

        header.addWidget(subtitle)
        header.addStretch()
        layout.addLayout(header)

        # Bug #1: Taxonomy Warning Banner (Hidden by default)
        self.taxonomy_warning = QLabel("")
        self.taxonomy_warning.setStyleSheet("""
            background-color: #fee2e2; 
            color: #991b1b; 
            padding: 12px; 
            border-radius: 8px; 
            border: 1px solid #f87171; 
            font-weight: bold; 
            margin-bottom: 10px;
        """)
        self.taxonomy_warning.setWordWrap(True)
        self.taxonomy_warning.setVisible(False)
        layout.addWidget(self.taxonomy_warning)

        # ===================== TARGET SECTION =====================
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout(target_group)
        target_layout.setContentsMargins(14, 12, 14, 14)
        target_layout.setSpacing(12)

        entry_lbl = QLabel("Entry")
        entry_lbl.setFixedWidth(50)

        self.entry_edit = QLineEdit()
        self.entry_edit.setReadOnly(True)
        self.entry_edit.setFont(QFont("Consolas", 10))
        self.entry_edit.setPlaceholderText("Select a function in IDA → Load Current Function")

        self.entry_change_btn = QPushButton("Load Current Function")
        self.entry_change_btn.setObjectName("primary")
        self.entry_change_btn.clicked.connect(self.on_use_current_function)

        target_layout.addWidget(entry_lbl)
        target_layout.addWidget(self.entry_edit, 1)
        target_layout.addWidget(self.entry_change_btn)

        # Optional Features Column
        opt_layout = QVBoxLayout()
        self.var_rename_cb = QCheckBox("Enable Local/Global Variable Renaming")
        # Load from QSettings if exists, default True for premium feel
        self.var_rename_cb.setChecked(True) 
        opt_layout.addWidget(self.var_rename_cb)
        target_layout.addLayout(opt_layout)

        self.settings_btn = QPushButton("Settings")
        self.settings_btn.setObjectName("secondary")
        self.settings_btn.clicked.connect(self.open_settings)
        target_layout.addWidget(self.settings_btn)

        layout.addWidget(target_group)


        # ===================== ACTION BAR =====================
        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.on_start)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.on_stop)

        self.open_folder_btn = QPushButton("Open Folder")
        self.open_folder_btn.setEnabled(False)
        self.open_folder_btn.clicked.connect(self.on_open_folder)

        self.open_html_btn = QPushButton("Open HTML Report")
        self.open_html_btn.setObjectName("primary")
        self.open_html_btn.setEnabled(False)
        self.open_html_btn.clicked.connect(self.on_open_html)

        self.reset_btn = QPushButton("Reset")
        self.reset_btn.setObjectName("danger")
        self.reset_btn.clicked.connect(self.on_reset)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("status_msg")

        action_bar.addWidget(self.start_btn)
        action_bar.addWidget(self.stop_btn)
        action_bar.addWidget(self.open_folder_btn)
        action_bar.addWidget(self.open_html_btn)
        action_bar.addWidget(self.reset_btn)
        action_bar.addStretch()
        action_bar.addWidget(self.status_label)

        layout.addLayout(action_bar)

        # Progress / Activity section (minimized)
        self.activity_group = QGroupBox("Activity")
        self.activity_group.setVisible(False)
        progress_area = QVBoxLayout(self.activity_group)
        progress_area.setContentsMargins(14, 18, 14, 14)
        progress_area.setSpacing(10)

        # Row 1: Current Stage + Progress Bar
        stage_row = QHBoxLayout()
        stage_row.setSpacing(10)
        self.cur_stage_lbl = QLabel("Current stage:")
        self.cur_stage_lbl.setStyleSheet("color: #636366; font-size: 9pt; font-weight: bold; min-width: 100px;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(22)
        self.progress_bar.setFormat("Initializing...")
        
        stage_row.addWidget(self.cur_stage_lbl)
        stage_row.addWidget(self.progress_bar, 1)

        # Row 2: Request/Receive + Mini Bar
        llm_row = QHBoxLayout()
        llm_row.setSpacing(10)
        
        self.req_rec_lbl = QLabel("Request/Receive:")
        self.req_rec_lbl.setStyleSheet("color: #636366; font-size: 9pt; font-weight: bold; min-width: 100px;")
        
        self.llm_state_label = QLabel("Idle")
        self.llm_state_label.setStyleSheet("color: #8E8E93; font-size: 9pt; font-weight: 600; min-width: 70px;")
        
        self.llm_activity_bar = QProgressBar()
        self.llm_activity_bar.setRange(0, 1)
        self.llm_activity_bar.setValue(0)
        self.llm_activity_bar.setTextVisible(False)
        self.llm_activity_bar.setFixedHeight(8)

        llm_row.addWidget(self.req_rec_lbl)
        llm_row.addWidget(self.llm_state_label)
        llm_row.addWidget(self.llm_activity_bar, 1)

        progress_area.addLayout(stage_row)
        progress_area.addLayout(llm_row)

        # Row 3: Cooldown countdown bar
        cooldown_row = QHBoxLayout()
        cooldown_row.setSpacing(10)

        self.cooldown_lbl = QLabel("Cooldown:")
        self.cooldown_lbl.setStyleSheet("color: #636366; font-size: 9pt; font-weight: bold; min-width: 100px;")

        self.cooldown_state_label = QLabel("-")
        self.cooldown_state_label.setStyleSheet("color: #8E8E93; font-size: 9pt; font-weight: 600; min-width: 70px;")

        self.cooldown_bar = QProgressBar()
        self.cooldown_bar.setRange(0, 100)
        self.cooldown_bar.setValue(0)
        self.cooldown_bar.setTextVisible(False)
        self.cooldown_bar.setFixedHeight(8)
        self.cooldown_bar.setStyleSheet("QProgressBar::chunk { background-color: #FF9500; border-radius: 4px; }")

        cooldown_row.addWidget(self.cooldown_lbl)
        cooldown_row.addWidget(self.cooldown_state_label)
        cooldown_row.addWidget(self.cooldown_bar, 1)

        progress_area.addLayout(cooldown_row)
        
        self.char_label = QLabel() # Hidden legacy compatibility
        self.char_label.setVisible(False)
        
        layout.addWidget(self.activity_group)

        # ===================== SPLITTER (VERTICAL: TREE top, DATA bottom) =====================
        self.splitter = QSplitter(QtCore.Qt.Vertical)
        
        # --- Top Half: Tree ---
        tree_container = QWidget()
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(0, 0, 0, 4)
        tree_layout.setSpacing(6)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter functions...")
        self.filter_edit.textChanged.connect(self.on_filter_changed)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Risk", "Name", "Address", "Depth layers", "Analysis Status", "Confidence", "Function's Node Type"])
        self.tree.setColumnWidth(0, 100)
        self.tree.setColumnWidth(1, 300)
        self.tree.setColumnWidth(2, 110)
        self.tree.setColumnWidth(3, 100)
        self.tree.setColumnWidth(4, 280)
        self.tree.setColumnWidth(5, 100)
        self.tree.setColumnWidth(6, 100)
        self.tree.setSortingEnabled(True)
        self.tree.header().setSortIndicator(4, QtCore.Qt.AscendingOrder)
        self.tree.header().setSectionsClickable(True)
        self.tree.setAlternatingRowColors(True)
        # Styles applied via STYLES_analyzer
        self.tree.itemClicked.connect(self.on_tree_item_clicked)
        self.tree.itemDoubleClicked.connect(self.on_tree_item_double_clicked)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_context_menu)
        
        tree_layout.addWidget(self.filter_edit)
        tree_layout.addWidget(self.tree)
        self.splitter.addWidget(tree_container)
        
        # --- Bottom Half: Results ---
        results_container = QWidget()
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(0, 4, 0, 0)
        results_layout.setSpacing(6)

        # Info panel — shows one-liner purpose of clicked node
        self.node_info_label = QLabel("Click a node in the table to see function's purpose")
        self.node_info_label.setWordWrap(True)
        self.node_info_label.setStyleSheet(
            "background: #F0F4FF; color: #1C1C1E; padding: 6px 10px; "
            "border: 1px solid #C0D0F0; border-radius: 5px; font-size: 10pt;"
        )
        self.node_info_label.setMinimumHeight(35)
        results_layout.addWidget(self.node_info_label)

        self.tabs = QTabWidget()
        # Log
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        # Match renamer's white background for logs
        self.log_view.setStyleSheet("background: #FFFFFF; color: #1C1C1E; font-size: 10pt; border: none;")
        self.tabs.addTab(self.log_view, "Log")
        
        # Graph
        self.graph_view = QTextBrowser()
        self.graph_view.setLineWrapMode(QTextBrowser.NoWrap)
        self.graph_view.setStyleSheet("background: #FAF9F6; color: #1C1C1E; border: none; font-size: 10pt;")
        self.tabs.addTab(self.graph_view, "Call Graph Map")

        # Mermaid JS call-flow diagram (raw code viewer)
        self.mermaid_view = QTextEdit()
        self.mermaid_view.setReadOnly(True)
        self.mermaid_view.setLineWrapMode(QTextEdit.NoWrap)
        self.mermaid_view.setStyleSheet("background: #0d1117; color: #c9d1d9; border: none; font-size: 10pt;")
        self.mermaid_view.setFont(QFont("Consolas", 10))
        self.mermaid_view.setPlaceholderText("Mermaid.js call-flow diagram will appear here after analysis.\n\nPaste this code into https://mermaid.live to visualize it.")
        self.tabs.addTab(self.mermaid_view, "Mermaid Flow")
        
        results_layout.addWidget(self.tabs)
        self.splitter.addWidget(results_container)
        
        self.splitter.setSizes([400, 400])
        layout.addWidget(self.splitter, 1)

    # ---------------------------------------------------------------------------
    # Core Logic
    # ---------------------------------------------------------------------------

    def open_settings(self):
        # Use shared SettingsDialog with analyzer mode
        dlg = SettingsDialog(CONFIG, self, hide_extra_tabs=True, mode='deep_analyzer')
        if dlg.exec_():
            CONFIG.reload()
            self.append_log("Settings reloaded.", "info")

    def on_resume(self):
        """Restore previous session from graph.json and output folder."""
        # Check output directory
        out_dir = get_output_dir()
        if not os.path.exists(out_dir):
            self.append_log("No previous session found (missing folder).", "err")
            return
            
        g_path = os.path.join(out_dir, "graph.json")
        if not os.path.exists(g_path):
            self.append_log("No graph.json found in output folder.", "err")
            return

        try:
            with open(g_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Format detection: new format has 'nodes' key, old format is a flat dict
            if isinstance(data, dict) and "nodes" in data:
                entry_ea_val = data.get("entry_ea", 0)
                if entry_ea_val:
                    self.entry_ea = entry_ea_val
                nodes_source = data.get("nodes", [])
            else:
                # Flat dictionary format
                nodes_source = data.values() if isinstance(data, dict) else []

            if self.entry_ea:
                self.entry_edit.setText(f"0x{self.entry_ea:X}")
                
            restored = {}
            for d in nodes_source:
                ea = d.get("ea")
                if ea is None:
                    hex_ea = d.get("ea_hex")
                    if hex_ea: 
                        try: ea = int(hex_ea, 16)
                        except: continue
                    else: continue

                n = FuncNode(ea, d["name"], d.get("depth", 0))
                n.callers = d.get("callers", [])
                if n.callers and isinstance(n.callers[0], str):
                    n.callers = [int(c, 16) for c in n.callers if isinstance(c, str)]

                n.callees = d.get("callees", [])
                if n.callees and isinstance(n.callees[0], str):
                    n.callees = [int(c, 16) for c in n.callees if isinstance(c, str)]

                n.is_library = d.get("is_library", False)
                n.is_leaf = d.get("is_leaf", False)
                n.status = d.get("status", "pending")
                n.confidence = d.get("confidence", 0)
                n.line_count = d.get("line_count", 0)
                restored[n.ea] = n
                
            self.append_log(f"Resumed previous session: {len(restored)} functions loaded.", "ok")
            self.on_graph_ready(restored)

            # Load log
            log_path = os.path.join(out_dir, "execution.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        log_text = f.read()
                    self.log_view.setText(log_text)
                    self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
                except Exception as e:
                    self.append_log(f"Error reading session log: {e}", "warn")

            # Load report

            # Load report
            report_path = os.path.join(out_dir, "summary_final.md")
            if os.path.exists(report_path):
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        md = f.read()
                    pass
                except Exception as e:
                    self.append_log(f"Error reading session log: {e}", "warn")

            # Load Mermaid call-flow diagram
            mermaid_path = os.path.join(out_dir, "callflow.mmd")
            if os.path.exists(mermaid_path) and hasattr(self, 'mermaid_view'):
                try:
                    with open(mermaid_path, 'r', encoding='utf-8') as f:
                        self.mermaid_view.setPlainText(f.read())
                except Exception as e:
                    self.append_log(f"Error reading callflow.mmd: {e}", "warn")
            
        except Exception as e:
            self.append_log(f"Failed to resume session: {e}", "err")


    def on_use_current_function(self):
        """Set the entry point to the function at the current screen cursor."""
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            self.entry_ea = f.start_ea
            name = ida_name.get_name(self.entry_ea)
            self.entry_edit.setText(f"0x{self.entry_ea:X} - {name}")
            self.log_view.clear()
            self.tree.clear()
            self.graph_view.clear()
            self.append_log(f"Target locked onto {name}", "ok")
        else:
            self.append_log("No function found at cursor.", "warn")

    def on_start(self):
        """Initialize and start the rename or analysis workers."""
        # 0. Proactive check: if Entry is 0, try to grab it from cursor now
        if self.entry_ea is None or self.entry_ea == 0 or self.entry_ea == idaapi.BADADDR:
            self.on_use_current_function()

        if self.entry_ea is None or self.entry_ea == 0 or self.entry_ea == idaapi.BADADDR:
            QMessageBox.warning(self, "No Target Function", 
                "Could not determine a target function. Please click inside a function in IDA and try again.")
            return

        # Explicitly update config with UI state before passing to workers
        CONFIG.deep_do_var_rename = self.var_rename_cb.isChecked()

        # 1. Persist settings and clear UI
        self._save_settings()
        self._reset_session_ui()

        # 2. Start Work
        self.append_log("Target: 0x%X" % self.entry_ea, "info")
        
        # pass always True as it's essential
        graph = build_call_graph(
            self.entry_ea,
            stop_checker=lambda: getattr(self, '_stop_requested', False),
            log_fn=lambda m, lvl: self.on_log(m, lvl)
        )

        # 2️⃣ Show table immediately BEFORE rename starts
        self.graph = graph
        self.populate_tree(graph)
        self.render_graph_tab(graph)

        QtWidgets.QApplication.processEvents()

        # 3️⃣ Now start rename worker (pass graph into it)
        if getattr(CONFIG, 'deep_do_bottom_up_rename', True):
            self.rename_worker = RenameWorker(self.entry_ea, do_var_rename=CONFIG.deep_do_var_rename)
            self.rename_worker.graph = graph  # important: reuse existing graph

            self.rename_worker.log_signal.connect(lambda m, l: self.on_log(m, l))
            self.rename_worker.progress_signal.connect(lambda c, t, n: self.on_progress(c, t, n))
            self.rename_worker.func_updated_signal.connect(self.on_func_updated)
            self.rename_worker.cooldown_progress_signal.connect(self.on_cooldown_progress)
            self.rename_worker.llm_state_signal.connect(self.on_llm_state)
            self.rename_worker.stage_signal.connect(self.on_stage_changed)
            self.rename_worker.finished_signal.connect(lambda tr: self.on_rename_finished(tr))

            self.rename_worker.start()
        else:
            self.append_log("Skipping Stage 2 Rename (disabled in settings).", "info")
            self.start_analysis_only()

        self.update_action_buttons()

    def _save_settings(self):
        """Persist state before starting."""
        # Note: API and Analysis settings are now handled via the Settings dialog and CONFIG.save()

        # Legacy local INI for state that doesn't belong in global config (like EntryEA)
        _CONFIG_FILE = os.path.join(idaapi.get_user_idadir(), "pseudonote_analyzer.ini")
        settings = QSettings(_CONFIG_FILE, QSettings.IniFormat)
        if self.entry_ea is None:
            settings.setValue("EntryEA", str(self.entry_ea))
            settings.setValue("EntryName", self.entry_edit.text())
        settings.setValue("DoVariableRename", self.var_rename_cb.isChecked())

    def _reset_session_ui(self):
        """Clear the UI and reset state before a new analysis start."""
        _ai_mod.AI_CANCEL_REQUESTED = False # Reset cancel flag for new session
        self._stop_requested = False         # Reset stop gate for new session

        # UI State
        self.start_btn.setEnabled(False)
        self.open_html_btn.setEnabled(False)
        self.activity_group.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_view.clear()
        self.tree.clear()
        self._all_tree_items = {}
        self.graph = {}
        global _SESSION_OUTPUT_DIR
        _SESSION_OUTPUT_DIR = None
        self.output_dir = None
        if hasattr(self, 'mermaid_view'):
            self.mermaid_view.clear()
        
        # Delete old log on fresh start
        od = get_output_dir(create=False)
        if od:
            lp = os.path.join(od, "execution.log")
            if os.path.exists(lp):
                try: os.remove(lp)
                except Exception as e:
                    self.append_log(f"Error reading session log: {e}", "warn")

        self.append_log("Starting UI reset...", "info")

    def start_analysis_only(self):
        """If rename pass is skipped, build graph first then analyze."""
        class GraphOnlyWorker(QThread):
            graph_ready_signal = Signal(object)
            log_signal = Signal(str, str)
            finished_signal = Signal(int)

            def __init__(self, ea):
                super(GraphOnlyWorker, self).__init__()
                self.ea = ea
            def run(self):
                res = {"graph": {}}
                def _sync_build():
                    try:
                        res["graph"] = build_call_graph(self.ea, stop_checker=lambda: getattr(self, '_stop', False), 
                                                       log_fn=lambda m, lvl: self.log_signal.emit(m, lvl))
                    except Exception as e:
                        self.log_signal.emit(f"Graph build failed: {e}", "err")
                        res["graph"] = {}
                idaapi.execute_sync(_sync_build, idaapi.MFF_READ)
                if getattr(self, '_stop', False): 
                    self.finished_signal.emit(0)
                    return
                self.graph_ready_signal.emit(res["graph"])
                self.finished_signal.emit(0)

        self.graph_worker = GraphOnlyWorker(self.entry_ea)
        self.graph_worker._stop = False
        def _stop_worker(): self.graph_worker._stop = True
        self.graph_worker.stop = _stop_worker
        self.graph_worker.graph_ready_signal.connect(lambda g: self.on_graph_built(g))
        self.graph_worker.log_signal.connect(lambda m, l: self.on_log(m, l))
        self.graph_worker.finished_signal.connect(lambda _: None)
        self.graph_worker.start()
        self.update_action_buttons()

    def on_rename_finished(self, total_renamed):
        """Transition from rename worker to analysis worker."""
        # If stop was requested while rename was still running, do NOT proceed to analysis
        if getattr(self, '_stop_requested', False):
            self.append_log("Rename finished after stop — analysis skipped.", "warn")
            self.on_all_finished()
            return
        if hasattr(self.rename_worker, 'graph'):
            self.append_log("Rename pass complete: %d functions renamed" % total_renamed, "ok")
            self.on_graph_ready(self.rename_worker.graph)
        else:
            self.append_log("Error: Graph not available from worker.", "err")
            self.on_all_finished()
            self.update_action_buttons()

    def on_graph_ready(self, graph):
        """Populate tree and start analysis pass if enabled."""
        # Guard: if user already stopped, do not proceed to analysis stage
        if getattr(self, '_stop_requested', False):
            self.append_log("Graph ready but stop was requested — analysis skipped.", "warn")
            self.on_all_finished()
            return
        self.graph = graph
        self.output_dir = get_output_dir()
        self.open_folder_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.start_btn.setEnabled(False)
        
        if not isinstance(self.graph, dict):
            self.append_log("Critical Error: Graph is not a dictionary.", "err")
            return

        self.populate_tree(graph)
        self.render_graph_tab(graph)

        self.analysis_worker = AnalysisWorker(
            self.entry_ea, 
            self.graph,
            do_var_rename=getattr(CONFIG, 'deep_do_var_rename', True),
            do_func_comment=getattr(CONFIG, 'deep_do_func_comment', True),
            do_analysis_rename=getattr(CONFIG, 'deep_do_analysis_rename', True),
            max_workers=getattr(CONFIG, 'deep_parallel_workers', 5),
            batch_funcs=min(5, getattr(CONFIG, 'deep_batch_size', 5)),
            batch_lines=getattr(CONFIG, 'deep_max_lines', 300)
        )
        self.analysis_worker.do_refinement = True
        self.analysis_worker.log_signal.connect(lambda m, l: self.on_log(m, l))
        self.analysis_worker.progress_signal.connect(lambda c, t, n: self.on_progress(c, t, n))
        self.analysis_worker.func_updated_signal.connect(self.on_func_updated)
        self.analysis_worker.cooldown_progress_signal.connect(self.on_cooldown_progress)
        self.analysis_worker.char_count_signal.connect(self.on_char_count)
        self.analysis_worker.llm_state_signal.connect(self.on_llm_state)
        self.analysis_worker.stage_signal.connect(self.on_stage_changed)
        self.analysis_worker.markdown_updated_signal.connect(self._schedule_graph_refresh)
        self.analysis_worker.finished_signal.connect(lambda od: self.on_analysis_finished(od))
        self.start_btn.setEnabled(False) # Ensure button disabled during transition
        self.analysis_worker.start()
        self.update_action_buttons()

    def on_graph_built(self, graph):
        """Populate the tree immediately after graph build (before Stage 3)."""
        if getattr(self, '_stop_requested', False):
            return
        self.graph = graph
        self.populate_tree(graph)
        self.render_graph_tab(graph)

    def on_analysis_finished(self, output_dir):
        """Final clean up of UI after analysis finishes."""
        self.output_dir = output_dir
        self.append_log("Analysis complete! summary_final.md written.", "ok")
        worker = self.analysis_worker
        if worker:
            self.append_log(f"Variables renamed in IDA: {worker.total_vars_renamed}", "ok")
            self.append_log(f"Functions commented: {worker.total_funcs_commented}", "ok")
        self.open_html_btn.setEnabled(True)
        self.on_all_finished()

        # --- Persist the session for this entry function so it can be auto-restored later ---
        if self.entry_ea and self.entry_ea != idaapi.BADADDR and output_dir:
            try:
                idaapi.execute_sync(
                    lambda: save_to_idb(self.entry_ea, output_dir, tag=89),
                    idaapi.MFF_WRITE
                )
            except Exception:
                pass

    def on_all_finished(self):
        """Reset UI buttons and progress state."""
        self.start_btn.setEnabled(True)
        self.update_action_buttons()
        self.activity_group.setVisible(False)
        self.status_label.setText("Stopped" if getattr(self, '_stop_requested', False) else "Complete")
        # Reset LLM state to idle (stay visible but dimmed)
        if hasattr(self, 'graph') and self.graph:
            # Full sync: update every tree row and re-render graph map
            self.sync_tree_from_graph()
            self.render_graph_tab(self.graph)
        if hasattr(self, 'output_dir') and self.output_dir:
            self.append_log("Output folder: %s" % self.output_dir, "info")

    def sync_tree_from_graph(self):
        """Bulk update ALL tree rows from the current graph node states."""
        if not hasattr(self, 'graph') or not self.graph: return
        status_colors = {
            "pending":     "#636366",  # Darker gray for better contrast
            "in_progress": "#007AFF",  # Blue
            "renamed":     "#5856D6",  # Indigo
            "analyzed":    "#248A3D",  # Darker green for white background
            "error":       "#CC3333",  # Stronger red
            "skipped":     "#8E8E93",  # Muted but visible gray
        }
        status_icons = {
            "pending":     "",
            "in_progress": "",
            "renamed":     "",
            "analyzed":    "",
            "error":       "",
            "skipped":     "",
        }
        for ea, node in self.graph.items():
            item = self._all_tree_items.get(ea)
            if not item: continue
            
            s4 = getattr(node, 'stage4_status', 'PENDING')
            s5 = getattr(node, 'stage5_status', 'PENDING')
            if getattr(node, 'is_library', False):
                status_text = "Library (Skipped)"
            else:
                status_text = f"Stage 4 [{s4}], Stage 5 [{s5}]"
            
            color = status_colors.get(node.status, "#d4d4d4")
            item.setText(1, node.name)
            item.setText(4, status_text)
            item.setText(5, "%d%%" % node.confidence)
            
            # Risk Logic
            risk = None
            # FIX: Extract callees from graph node instead of passing entire graph
            graph_node = self.graph.get(ea)
            callees_list = graph_node.callees if graph_node and hasattr(graph_node, 'callees') else []
            api_risk = _derive_risk_from_api_tags(ea, callees_list)
            if node.status in ("analyzed", "preliminary", "contextual") and node.confidence == 0:
                # Try to recover confidence from IDB artifact if node was loaded without it
                raw_conf = load_from_idb(ea, tag=85)
                if raw_conf:
                    try:
                        _conf_dat = json.loads(raw_conf)
                        _conf_val = _conf_dat.get("confidence", 0)
                        if _conf_val:
                            node.confidence = max(0, min(100, int(_conf_val)))
                            item.setText(5, "%d%%" % node.confidence)
                    except: pass

            if getattr(node, 'is_library', False):
                risk = "benign"
            elif node.status == "analyzed":
                raw = load_from_idb(ea, tag=85)
                if raw:
                    try:
                        res = json.loads(raw)
                        risk = res.get("risk_tag", "").lower().strip() or None
                        if not risk:
                            susp = res.get("suspicious", [])
                            if susp:
                                risk = "malicious" if node.confidence >= 75 else "suspicious"
                            else:
                                risk = "benign"
                    except:
                        risk = "benign"
                # Merge API-based risk if available
                risk = _pick_higher_risk(risk, api_risk) or "benign"
            else:
                # Risk stays 'Pending' until the Stage 5 Contextual Refinement pass for this function.
                # This prevents misleading 'Benign' tags during the initial sweep.
                risk = "pending"
            
            risk_color = "#8E8E93"
            if risk == "malicious": risk_color = "#FF3B30"
            elif risk == "suspicious": risk_color = "#FF9500"
            elif risk == "benign": risk_color = "#34C759"

            item.setText(0, risk.capitalize())
            item.setForeground(0, QtGui.QBrush(QtGui.QColor(risk_color)))

            for col in range(1, self.tree.columnCount()):
                item.setForeground(col, QtGui.QBrush(QtGui.QColor(color)))

    def _schedule_graph_refresh(self):
        """Debounce render_graph_tab calls — only re-render at most every 500ms."""
        if hasattr(self, 'graph'):
            if not hasattr(self, '_graph_refresh_timer'):
                self._graph_refresh_timer = QTimer(self)
                self._graph_refresh_timer.setSingleShot(True)
                self._graph_refresh_timer.timeout.connect(lambda: self.render_graph_tab(self.graph))
            if not self._graph_refresh_timer.isActive():
                self._graph_refresh_timer.start(500)
            
            # Update Mermaid flow tab

            # Update Mermaid flow tab
            if self.output_dir and hasattr(self, 'mermaid_view'):
                mmp = os.path.join(self.output_dir, "callflow.mmd")
                if os.path.exists(mmp):
                    try:
                        with open(mmp, 'r', encoding='utf-8') as f:
                            self.mermaid_view.setPlainText(f.read())
                    except Exception as e:
                        self.append_log(f"Error updating mermaid view: {e}", "warn")

    def closeEvent(self, event):
        """Stop all workers and persist dialog settings before closing."""
        self.on_stop()
        self._save_settings()
        event.accept()

    def on_stop(self):
        """Terminate active workers."""
        self._stop_requested = True  # Set BEFORE on_all_finished so in-flight signals are blocked
        _ai_mod.AI_CANCEL_REQUESTED = True
        if hasattr(self, 'rename_worker') and self.rename_worker and self.rename_worker.isRunning():
            self.rename_worker.stop()
        if hasattr(self, 'analysis_worker') and self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.stop()
        if hasattr(self, 'graph_worker') and self.graph_worker and self.graph_worker.isRunning():
            self.graph_worker.stop()
        self.status_label.setText("Stopped")
        self.append_log("Stopped by user.", "warn")
        # Reset LLM state to idle (stay visible but dimmed)
        if hasattr(self, 'cooldown_bar'):
            self.cooldown_bar.setValue(0)
            self.cooldown_state_label.setText("—")
            self.llm_state_label.setStyleSheet("color: #8E8E93; font-size: 10px; font-weight: 600;")
        self.activity_group.setVisible(False)
        self.update_action_buttons(running=False)

    def on_reset(self):
        """Reset the entire session and delete output files."""
        reply = QMessageBox.question(
            self, "Reset Session", 
            "This will stop any active analysis and PERMANENTLY DELETE all generated files in the output folder.\n\nAre you sure?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        # 1. Stop everything
        self.on_stop()
        
        # 2. Delete the folder
        out_dir = get_output_dir(create=False)
        if out_dir and os.path.exists(out_dir):
            def _remove_readonly(func, path, excinfo):
                os.chmod(path, stat.S_IWRITE)
                func(path)

            try:
                shutil.rmtree(out_dir, onerror=_remove_readonly)
                self.append_log("Deleted output folder: %s" % out_dir, "ok")
            except Exception as e:
                self.append_log("Error deleting folder: %s" % e, "err")

        # 3. Clear UI State
        self.graph = {}
        self.output_dir = None
        self.tree.clear()
        self._all_tree_items = {}
        self.log_view.clear()
        self.graph_view.clear()
        
        # 4. Reset Progress
        self.progress_bar.setValue(0)
        self.char_label.setVisible(False)
        self.status_label.setText("Ready")
        
        # 5. Reset Buttons
        self.start_btn.setEnabled(True)
        self.open_folder_btn.setEnabled(False)
        self.open_html_btn.setEnabled(False)
        
        self.append_log("Session reset successfully. Ready for new analysis.", "ok")

    def on_log(self, message, level):
        self.append_log(message, level)

    def append_log(self, message, level):
        """Append a colored log entry to the log tab with a consistent status prefix."""
        colors = {
            'info': '#636366', # Darker gray
            'ok':   '#248A3D', # Darker green
            'warn': '#C67E00', # Darker amber
            'err':  '#CC3333'  # Stronger red
        }
        prefixes = {
            'info': '[INFO]',
            'ok':   '[OK]  ',
            'warn': '[WARN]',
            'err':  '[ERR] '
        }
        
        color = colors.get(level, '#d4d4d4')
        prefix = prefixes.get(level, '[INFO]')
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Format the message with its prefix
        full_message = f"{prefix} {message}"
        
        self.log_view.append(f'<span style="color:{color};">[{ts}] {html.escape(str(full_message))}</span>')
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
        
        # Persist log to disk
        od = self.output_dir or get_output_dir(create=False)
        if od:
            try:
                with open(os.path.join(od, "execution.log"), 'a', encoding='utf-8') as f:
                    f.write(f"[{ts}] {full_message}\n")
            except Exception as e:
                pass
    
    def log_stage(self, title):
        banner = "\n" + "=" * 6 + f" {title} " + "=" * 6
        self.append_log(banner, "info")

    def on_stage_changed(self, stage_name):
        """Update the progress bar text to show current stage."""
        self.progress_bar.setVisible(True)
        # Convert "STAGE X - TITLE" -> "STAGE X/8 - TITLE"
        m = re.match(r"STAGE (\d+) - (.+)", stage_name)
        if m:
            stage_no, stage_title = m.groups()
            display_name = f"STAGE {stage_no}/7 - {stage_title}"
            self.status_label.setText(f"Starting {display_name}...")
            self.progress_bar.setFormat(f"{display_name} | %p%")
        else:
            self.status_label.setText(f"Starting {stage_name}...")
            self.progress_bar.setFormat(f"{stage_name} (%p%)")
            
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100) # Default for stages without total count

    def on_progress(self, current, total, cur_name=""):
        """Update progress bar and status text."""
        if not self.stop_btn.isEnabled(): return
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
            # Maintain the stage name in the format
            fmt = self.progress_bar.format()
            if "(" in fmt: 
                # Keep the prefix before the last "("
                prefix = fmt.rsplit("(", 1)[0].strip()
                self.progress_bar.setFormat(f"{prefix} (%p%)")
        if cur_name:
            self.status_label.setText("Stage progress: %d/%d (Current: %s)" % (current, total, cur_name))
        else:
            self.status_label.setText("Stage progress: %d/%d" % (current, total))

    def on_cooldown_progress(self, current, total):
        if not self.stop_btn.isEnabled(): return
        if not hasattr(self, 'cooldown_bar'): return
        if total <= 0 or current <= 0:
            self.cooldown_bar.setValue(0)
            self.cooldown_state_label.setText("—")
        else:
            self.cooldown_bar.setRange(0, total)
            self.cooldown_bar.setValue(current)
            remaining = round((total - current) * 0.1, 1)
            self.cooldown_state_label.setText(f"{remaining}s")

    _last_char_count = 0
    def on_char_count(self, current, max_val):
        if not self.stop_btn.isEnabled(): return
        self._last_char_count = current
        if self.llm_state_label.text().startswith("Receiving"):
            self.llm_state_label.setText(f"Receiving ({current} chars)...")

    def on_llm_state(self, state):
        """Update the LLM activity bar based on current AI state. Always visible."""
        if not self.stop_btn.isEnabled(): return
        if state == "requesting":
            self.llm_activity_bar.setRange(0, 0)   # marquee / indeterminate
            self.llm_state_label.setText("Requesting...")
            self.llm_state_label.setStyleSheet("color: #FF9500; font-size: 10px; font-weight: 600;")
        elif state == "receiving":
            self.llm_activity_bar.setRange(0, 0)   # marquee / indeterminate
            self.llm_state_label.setText(f"Receiving ({self._last_char_count} chars)...")
            self.llm_state_label.setStyleSheet("color: #5AC8FA; font-size: 10px; font-weight: 600;")
        else:  # 'idle' or anything else
            self._last_char_count = 0
            self.llm_activity_bar.setRange(0, 1)
            self.llm_activity_bar.setValue(0)
            self.llm_state_label.setText("Idle")
            self.llm_state_label.setStyleSheet("color: #8E8E93; font-size: 10px; font-weight: 600;")

    def on_cooldown_changed(self, val):
        CONFIG.deep_cooldown = val
        self.append_log(f"Cooldown updated: {val}s", "info")

    # Track which IDA tags have been confirmed active per-EA to avoid expensive re-queries
    _ida_tag_cache = {}   # ea -> frozenset of active tags (84=renamed, 85=analyzed, 86=vars)

    _STATUS_COLORS = {
        "pending":     "#888888",
        "in_progress": "#ce9178",
        "renamed":     "#569cd6",
        "analyzed":    "#4ec9b0",
        "error":       "#f44747",
        "skipped":     "#D1D1D6",
    }

    def on_func_updated(self, ea, old_name, new_name, confidence):
        """Update a tree item's visuals when its function is renamed or analyzed."""
        item = self._all_tree_items.get(ea)
        if not item: return
        node = self.graph.get(ea)
        if not node: return

        color = self._STATUS_COLORS.get(node.status, "#d4d4d4")
        item.setText(1, new_name)  # Use passed name to show update immediately
        
        s4 = getattr(node, 'stage4_status', 'PENDING')
        s5 = getattr(node, 'stage5_status', 'PENDING')
        status_text = f"Stage 4 [{s4}], Stage 5 [{s5}]"
        
        item.setText(4, status_text)
        item.setText(5, "%d%%" % confidence)

        # Risk Classification (aligned with analyzer.py)
        # Use AI's tag if available, otherwise fall back to logic
        risk = None
        # FIX: Extract callees from graph node instead of passing entire graph
        callees_list = node.callees if node and hasattr(node, 'callees') else []
        api_risk = _derive_risk_from_api_tags(ea, callees_list)
        if node.status == "analyzed":
            raw = load_from_idb(ea, tag=85)
            if raw:
                try:
                    res = json.loads(raw)
                    risk = res.get("risk_tag", "").lower().strip() or None
                    # Fallback if old data doesn't have tag
                    if not risk:
                        susp = res.get("suspicious", [])
                        if susp:
                            risk = "malicious" if confidence >= 75 else "suspicious"
                        else:
                            risk = "benign"
                except:
                    risk = "benign"
            risk = _pick_higher_risk(risk, api_risk) or "benign"
        else:
            # Risk should strictly stay 'Pending' (gray) until Stage 5 Refinement
            risk = "pending"

        risk_display = risk.capitalize()
        risk_color = "#8E8E93" # Benign/Pending (Gray)
        if risk == "malicious": risk_color = "#FF3B30" # Red
        elif risk == "suspicious": risk_color = "#FF9500" # Orange
        elif risk == "benign": risk_color = "#34C759" # Green

        item.setText(0, risk_display)
        item.setForeground(0, QtGui.QBrush(QtGui.QColor(risk_color)))

        for col in range(1, self.tree.columnCount()): # Skip column 0 (Risk)
            item.setForeground(col, QtGui.QBrush(QtGui.QColor(color)))

        # Debounced graph tab refresh (only if graph tab is visible)
        if self.tabs.currentIndex() == 1:   # index 1 = Call Graph tab
            self._schedule_graph_refresh()

    def populate_tree(self, graph):
        """Fill the tree widget with functions from the call graph."""
        self.tree.clear()
        self._all_tree_items = {}
        self.tree.setSortingEnabled(False)  # Disable sorting during bulk insert for performance
        
        # Filter only integer EAs (FuncNode objects) and skip metadata dict
        nodes_to_sort = [(ea, n) for ea, n in graph.items() if isinstance(ea, int)]
        
        for ea, node in sorted(nodes_to_sort, key=lambda x: x[1].depth):
            item = SortableTreeItem([
                "Pending", # Risk
                node.name,
                "0x%X" % ea,
                str(node.depth),
                "pending",
                "0%",
                "Library" if node.is_library else ("Leaf" if node.is_leaf else "non-leaf")
            ])
            item.setForeground(0, QtGui.QBrush(QtGui.QColor("#8E8E93"))) # Pending color
            if node.is_library:
                for col in range(self.tree.columnCount()):
                    item.setForeground(col, QtGui.QBrush(QtGui.QColor("#666666")))
            self.tree.addTopLevelItem(item)
            self._all_tree_items[ea] = item
        self.tree.setSortingEnabled(True)  # Re-enable after population

    def on_filter_changed(self, text):
        """Filter tree items by name or address."""
        text = text.lower()
        for ea, item in self._all_tree_items.items():
            name = item.text(1).lower()
            addr = item.text(2).lower()
            match = (text in name or text in addr) if text else True
            item.setHidden(not match)

    def on_tree_item_clicked(self, item, col):
        """Single-click: show purpose in info panel. Requires no navigation."""
        try:
            ea = int(item.text(2), 16)
        except:
            return
        node = self.graph.get(ea)
        if not node:
            return
        # Show one-liner from cache or IDB
        one_liner = _analysis_cache.get(ea)
        if not one_liner:
            raw = load_from_idb(ea, tag=85)
            if raw:
                try:
                    one_liner = json.loads(raw).get("one_liner", "")
                    if one_liner:
                        _analysis_cache[ea] = one_liner
                except Exception as e:
                    self.append_log(f"Error reading session log: {e}", "warn")
        if one_liner:
            self.node_info_label.setText(f"<b>{node.name}</b>: {html.escape(one_liner)}")
        else:
            status_hint = " (not yet analyzed)" if node.status in ("pending", "renamed") else ""
            self.node_info_label.setText(f"<b>{node.name}</b>{status_hint}")

    def _open_pseudocode(self, ea):
        """Open or focus Hex-Rays pseudocode view for ea (graceful if no Hex-Rays)."""
        try:
            if hasattr(ida_hexrays, 'open_pseudocode'):
                ida_hexrays.open_pseudocode(ea, 0)
            else:
                idaapi.jumpto(ea)
        except Exception:
            idaapi.jumpto(ea)

    def on_tree_item_double_clicked(self, item, col):
        """Double-click: jump to function in IDA and open pseudocode view."""
        addr_text = item.text(2)
        try:
            ea = int(addr_text, 16)
            idaapi.jumpto(ea)
            idaapi.execute_sync(lambda: self._open_pseudocode(ea), idaapi.MFF_WRITE)
        except Exception as e:
            self.append_log(f"Error jumping to function: {e}", "warn")

    def on_tree_context_menu(self, pos):
        """Show context menu for tree items."""
        item = self.tree.itemAt(pos)
        if not item: return
        try:
            ea = int(item.text(2), 16)
        except: return

        menu = QMenu(self)
        view_pseudocode_action = menu.addAction("View in Pseudocode")
        view_pseudocode_action.triggered.connect(lambda: self._open_pseudocode(ea))
        
        jump_action = menu.addAction("Jump to in IDA")
        jump_action.triggered.connect(lambda: idaapi.jumpto(ea))
        
        copy_action = menu.addAction("Copy name")
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(item.text(1)))
        
        menu.addSeparator()
        
        reanalyze_action = menu.addAction("Re-analyze this function")
        def do_reanalyze():
            node = self.graph.get(ea)
            if not node or node.is_library: return
            if not CONFIG.active_provider:
                self.append_log("AI provider not configured", "err"); return
            self.append_log("Re-analyzing %s..." % node.name, "info")
            ai_cfg = build_ai_cfg_from_config()
            analyzed_eas = set(n.ea for n in self.graph.values() if n.status == "analyzed")
            import threading
            def _run():
                import idaapi as _ida
                try:
                    def _log(m, l='info'):
                        _ida.execute_sync(lambda: self.on_log(m, l), _ida.MFF_WRITE)

                    result = analyze_single_function(ea, node, self.graph, self.output_dir or get_output_dir(), ai_cfg, analyzed_eas, _log)
                    if self.output_dir:
                        code = load_decompiled_from_disk(ea, node.name, self.output_dir) or ""
                        md_section = build_function_markdown_piece(ea, node, result, self.graph, code=code)
                        append_function_to_markdown(self.output_dir, md_section)
                    
                    _ida.execute_sync(lambda: self.on_func_updated(ea, node.name, node.name, result.get("confidence", 0)), _ida.MFF_WRITE)
                except Exception as ex:
                    _ida.execute_sync(lambda: self.on_log(f"Re-analyze error: {ex}", "err"), _ida.MFF_WRITE)
            threading.Thread(target=_run, daemon=True).start()
        reanalyze_action.triggered.connect(do_reanalyze)

        view_analysis_action = menu.addAction("View saved analysis")
        def do_view_analysis():
            raw = load_from_idb(ea, tag=85)
            if not raw:
                self.append_log("No saved analysis for %s" % item.text(1), "warn"); return
            try:
                data = json.loads(raw)
                msg = f"Function: {item.text(1)}\n\nOne-liner: {data.get('one_liner','')}\n\nSummary:\n{data.get('summary','')}\n\nDetails:\n"
                msg += "\n".join(f"  - {b}" for b in data.get("bullets",[]))
                if data.get("suspicious"):
                    msg += "\n\nSuspicious:\n" + "\n".join(f"  - {s}" for s in data.get("suspicious",[]))
                QMessageBox.information(self, f"Analysis: {item.text(1)}", msg)
            except: self.append_log("Could not parse saved analysis", "err")
        view_analysis_action.triggered.connect(do_view_analysis)

        menu.exec_(self.tree.viewport().mapToGlobal(pos))

    def render_graph_tab(self, graph):
        """Generate a ASCII tree representation of the call graph."""
        if not self.entry_ea: return
        visited = set()
        lines = []
        
        def _recurse(ea, prefix="", is_last=True):
            node = graph.get(ea)
            if not node: return
            
            marker = "└── " if is_last else "├── "
            
            # If we've already expanded this node, just print it and stop recursing
            if ea in visited:
                lines.append(f"{prefix}{marker}{node.name} [0x{ea:X}]")
                return
                
            visited.add(ea)
            lines.append(f"{prefix}{marker}{node.name} [0x{ea:X}]")
            
            new_prefix = prefix + ("    " if is_last else "│   ")
            
            callees = [c for c in sorted(node.callees) if c in graph and not graph[c].is_library]
            if len(lines) > 2500: 
                if len(lines) == 2501: lines.append(f"{new_prefix}... [Graph truncated due to size]")
                return # higher safety cap
            
            for i, c_ea in enumerate(callees):
                _recurse(c_ea, new_prefix, i == len(callees) - 1)

        # Start from entry
        node = graph.get(self.entry_ea)
        if node:
            lines.append(f"{node.name} [Entry]")
            callees = [c for c in sorted(node.callees) if c in graph and not graph[c].is_library]
            for i, c_ea in enumerate(callees):
                _recurse(c_ea, "", i == len(callees) - 1)

        self.graph_view.setPlainText("\n".join(lines))

    def on_open_folder(self):
        """Open the summary output directory in the file manager."""
        if not self.output_dir: return
        try:
            if sys.platform == "win32":
                os.startfile(self.output_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.output_dir])
            else:
                subprocess.Popen(["xdg-open", self.output_dir])
        except Exception as ex:
            self.append_log("Could not open folder: %s" % ex, "warn")

    def on_open_html(self):
        """Open the interactive HTML report in the default browser."""
        if not self.output_dir: return
        html_path = os.path.join(self.output_dir, "report.html")
        if not os.path.exists(html_path):
            self.append_log("HTML report not found at: %s" % html_path, "warn")
            return
            
        try:
            if sys.platform == "win32":
                os.startfile(html_path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", html_path])
            else:
                subprocess.Popen(["xdg-open", html_path])
            self.append_log("Opening HTML report in browser...", "ok")
        except Exception as ex:
            self.append_log("Could not open HTML report: %s" % ex, "warn")

class DeepAnalyzerHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None
        
    def activate(self, ctx):
        self.dlg = DeepAnalyzerDialog()
        self.dlg.show()
        return 1
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
