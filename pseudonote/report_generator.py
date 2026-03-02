import os
import re
import json
import time
import glob
import html
import collections
from datetime import datetime
from functools import lru_cache

# --- MALWARE API TAXONOMY (Imported) -----------------------------------------
try:
    from pseudonote.api_taxonomy import (
        get_api_tags_for_function, 
        get_category_severity,
        API_MAP as _API_MAP,
        RISK_ORDER as _RISK_ORDER
    )
except ImportError:
    # Fallback/mock for standalone testing or if module is missing
    def get_api_tags_for_function(*args, **kwargs): return {}
    _API_MAP = {}
    _RISK_ORDER = {"pending": -1, "benign": 0, "suspicious": 1, "malicious": 2}

# Import IDA-specific helpers only if available
try:
    import idaapi
    import idc
    import idautils
    import ida_name
    import ida_funcs
    import ida_nalt
    import ida_hexrays
    import ida_segment
    import ida_bytes
except ImportError:
    idaapi = idc = idautils = ida_name = ida_hexrays = ida_funcs = ida_nalt = ida_segment = ida_bytes = None

# MITRE ATT&CK capability -> technique mapping
_MITRE_MAP = {
    "injection":        [("T1055", "Process Injection"),          ("T1055.001", "DLL Injection")],
    "process":          [("T1057", "Process Discovery"),          ("T1059",     "Command and Scripting Interpreter")],
    "persistence":      [("T1547", "Boot or Logon Autostart"),    ("T1053",     "Scheduled Task/Job")],
    "registry":         [("T1112", "Modify Registry"),            ("T1547.001", "Registry Run Keys")],
    "crypto":           [("T1027", "Obfuscated Files/Info"),      ("T1140",     "Deobfuscate/Decode Files")],
    "network":          [("T1071", "Application Layer Protocol"), ("T1105",     "Ingress Tool Transfer")],
    "file_io":          [("T1083", "File and Directory Discovery"),("T1005",    "Data from Local System")],
    "evasion":          [("T1036", "Masquerading"),               ("T1562",     "Impair Defenses")],
    "privilege":        [("T1055", "Process Injection"),          ("T1134",     "Access Token Manipulation")],
    "memory":           [("T1055", "Process Injection"),          ("T1620",     "Reflective Code Loading")],
    "shellcode":        [("T1620", "Reflective Code Loading"),    ("T1055.012", "Process Hollowing")],
    "string_ops":       [("T1027", "Obfuscated Files/Info")],
    "anti_analysis":    [("T1497", "Virtualization/Sandbox Evasion")],
    "credential":       [("T1555", "Credentials from Password Stores"), ("T1003", "OS Credential Dumping")],
    "lateral":          [("T1021", "Remote Services"),            ("T1570",     "Lateral Tool Transfer")],
    "exfil":            [("T1041", "Exfiltration Over C2 Channel")],
    "c2":               [("T1071", "Application Layer Protocol"), ("T1095", "Non-Application Layer Protocol")],
}

# Precompiled regex patterns (Bug #5)
_SAFE_NAME_PATTERN = re.compile(r'[^A-Za-z0-9_]')
_MARKDOWN_CODE_START = re.compile(r'^```[cC]?[a-zA-Z]*\s*\n')
_MARKDOWN_CODE_END = re.compile(r'\n```\s*$')
_CAST_RE = re.compile(r'\(\s*(?:unsigned\s+__int(?:8|16|32|64|128)|__int(?:8|16|32|64|128)|unsigned\s+(?:char|short|int|long(?:\s+long)?)|(?:char|short|int|long(?:\s+long)?)|(?:void|bool|float|double)|__int3264|DWORD|WORD|BYTE|QWORD|size_t|ssize_t|ptrdiff_t|LPVOID|HANDLE|HRESULT)\s*(?:\*+\s*)?\)', re.VERBOSE | re.IGNORECASE)
_VT_CALL_1 = re.compile(r'\(\s*\*\s*\(\s*\*\s*(?P<expr>[A-Za-z_][A-Za-z0-9_>.\[\]]*)\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\)\s*\)\s*\(\s*(?P<args>[^)]*)\)')
_VT_CALL_2 = re.compile(r'\(\s*\*\s*\(\s*\*\s*(?P<expr>[A-Za-z_][A-Za-z0-9_>.\[\]]*)\s*\)\s*\)\s*\(\s*(?P<args>[^)]*)\)')
_MULTI_NEWLINE = re.compile(r'\n{3,}')

@lru_cache(maxsize=1024)
def sanitize_function_name(name):
    """Sanitize function name for safe use in file systems."""
    if not name: return "unknown"
    return _SAFE_NAME_PATTERN.sub('_', name)[:60]

# ===========================================================================
# ARTIFACT & CODE HANDLING
# ===========================================================================

def get_function_artifact_path(output_dir, sub_dir, ea, name, ext):
    """Generate a consistent path for function artifacts."""
    safe_name = sanitize_function_name(name)
    filename = "%s_0x%X.%s" % (safe_name, ea, ext)
    return os.path.join(output_dir, sub_dir, filename), filename

def save_decompiled_to_disk(ea, name, code, output_dir):
    """Save raw Hex-Rays decompiled code for a function to decomp/ subfolder."""
    path, _ = get_function_artifact_path(output_dir, "decomp", ea, name, "c")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            safe_code = str(code) if code and not isinstance(code, str) else code
            f.write(safe_code if safe_code else "// Decompilation failed or unavailable")
        return path
    except Exception as e:
        print("[PseudoNote] Error saving decompiled file: %s" % e)
        return None

def save_readable_to_disk(ea, name, code, output_dir):
    """Save LLM-authored readable C code for a function to readable/ subfolder."""
    path, _ = get_function_artifact_path(output_dir, "readable", ea, name, "c")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Attempt to strip any accidental Markdown block wrapping
        if code:
            code_str = code.strip()
            code_str = _MARKDOWN_CODE_START.sub('', code_str)
            code_str = _MARKDOWN_CODE_END.sub('', code_str)
        else:
            code_str = "// LLM readable code not generated"
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(code_str)
        return path
    except Exception as e:
        print("[PseudoNote] Error saving readable file: %s" % e)
        return None

def load_readable_from_disk(ea, name, output_dir):
    """Load LLM-authored readable C from readable/ subfolder."""
    safe_name = sanitize_function_name(name)
    path = os.path.join(output_dir, "readable", "%s_0x%X.c" % (safe_name, ea))
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except: pass
    hits = glob.glob(os.path.join(output_dir, "readable", "*_0x%X.c" % ea))
    if hits:
        try:
            with open(hits[0], 'r', encoding='utf-8') as f:
                return f.read()
        except: pass
    return None

def load_decompiled_from_disk(ea, name, output_dir):
    """Load decompiled C code from a previously saved file on disk."""
    safe_name = sanitize_function_name(name)
    path = os.path.join(output_dir, "decomp", "%s_0x%X.c" % (safe_name, ea))
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except: pass
    hits = glob.glob(os.path.join(output_dir, "decomp", "*_0x%X.c" % ea))
    if hits:
        try:
            with open(hits[0], 'r', encoding='utf-8') as f:
                return f.read()
        except: pass
    return None

def cleanup_decompiled_code(code):
    """Post-process IDA decompiler output for readability."""
    if not code: return code
    code = _CAST_RE.sub('', code)
    code = re.sub(r'\b(__fastcall|__cdecl|__stdcall|__thiscall|__vectorcall|__pascal)\b', '', code)
    
    def _vtcall_sub(m):
        expr = m.group('expr').strip()
        offset = m.group('offset')
        args = m.group('args').strip()
        if offset:
            try: slot = int(offset.strip(), 0) // 8
            except: slot = offset.strip()
            return f"{expr}->vt[{slot}]({args})"
        return f"{expr}->vt[0]({args})"

    code = _VT_CALL_1.sub(_vtcall_sub, code)
    code = _VT_CALL_2.sub(lambda m: f"{m.group('expr').strip()}->vt[0]({m.group('args').strip()})", code)
    code = _MULTI_NEWLINE.sub('\n\n', code)
    code = '\n'.join(line.rstrip() for line in code.splitlines())
    return code


# ===========================================================================
# HTML COMPONENTS & PARSING
# ===========================================================================

def _escape_html(s):
    if not s: return ""
    return html.escape(str(s))

def _risk_badge(risk):
    colors = {
        "malicious": ("#dc2626", "#ffffff"),
        "suspicious": ("#f59e0b", "#ffffff"), 
        "benign":    ("#16a34a", "#ffffff")
    }
    bg, fg = colors.get(str(risk).lower(), ("#6b7280", "#ffffff"))
    return f'<span style="background:{bg};color:{fg};padding:4px 12px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;box-shadow:0 1px 2px rgba(0,0,0,0.1);">{_escape_html(risk)}</span>'

def _mitre_from_data(functions_data):
    seen = {}
    for fd in functions_data:
        # User wants custom functions only (functions_data already filtered by node.is_library)
        fname = fd.get("name")
        caps = fd.get("capabilities", []) or []
        tags = fd.get("semantic_tags", []) or []
        all_keys = [c.lower().replace(" ","_").replace("-","_") for c in caps]
        all_keys += [t.strip("[]").lower() for t in tags]
        
        for key in all_keys:
            for map_key, techs in _MITRE_MAP.items():
                if map_key in key or key in map_key:
                    for tid, tname in techs:
                        if tid not in seen:
                            seen[tid] = {"name": tname, "funcs": set()}
                        seen[tid]["funcs"].add(fname)
    
    r = []
    for tid, info in sorted(seen.items()):
        flist = sorted(list(info["funcs"]))
        f_display = ", ".join(flist[:10]) + ("..." if len(flist)>10 else "")
        r.append((tid, info["name"], f_display))
    return r

def extract_ida_strings(graph=None, log_fn=None):
    """Extract and categorize strings (ASCII/Unicode) while filtering junk."""
    if not idaapi or not idautils:
        return []

    results_container = []

    def _sync_worker():
        # Defensive imports within the synchronized worker to avoid thread-local SWIG issues
        import idautils
        import idc
        import ida_bytes
        import ida_funcs
        import ida_nalt
        import ida_segment
        import ida_hexrays
        import idaapi

        local_results = []
        seen_values = set()

        def log(msg, level="info"):
            if log_fn: log_fn(msg, level)

        # Heuristics for "Interesting" strings
        url_re = re.compile(r'https?://[^\s"\'<>]{4,}', re.I)
        file_re = re.compile(r'[A-Za-z]:\\[\\\w\.\-\s]{5,}')
        reg_re = re.compile(r'(?:HKEY_|HKLM|HKCU|HKCR|HKU|Software\\(?:Microsoft|Wow6432Node|Classes|Policies))[\\\w\.\-\s]{5,}', re.I)
        cmd_re = re.compile(r'\b(?:cmd\.exe|powershell(?:\.exe)?|powershell_ise|bash|sh|cscript|wscript|mshta|regsvr32|rundll32|net\.exe|net1\.exe|schtasks|sc\.exe|bitsadmin)\b.*', re.I)
        ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        mutex_re = re.compile(r'(?:\{[A-F0-9-]{32,}\})|(?:\b[A-Za-z0-9_]{8,}\bMutex)', re.I)
        exe_re = re.compile(r'\b[\w\-\.]+\.(?:exe|dll|sys|bat|vbs|ps1|com|scr|pif|vbe)\b', re.I)
        # Runtime/Library strings (to avoid miscategorization as obfuscation)
        library_re = re.compile(r'\b(?:runtime error|assertion failed|invalid argument|out of memory|permission denied|no such file|not a directory|executable file format|math argument|math result|Mingw-w64 runtime|image-section|Partial loss of significance|Total loss of significance|UNDERFLOW|OVERFLOW|PLOSS|TLOSS|SIGN|Matherr|___report_error)\b', re.I)
        # Patterns for encoded/obfuscated data (Not junk)
        base64_re = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        hex_re = re.compile(r'^[0-9a-fA-F]{16,}$')

        def get_entropy(s):
            if not s: return 0
            import math
            counts = collections.Counter(s)
            entropy = 0
            for count in counts.values():
                freq = count / len(s)
                entropy -= freq * math.log2(freq)
            return entropy

        def is_junk(s):
            if not s: return True
            s_stripped = s.strip()
            length = len(s_stripped)
            if length < 5:
                if cmd_re.search(s_stripped): return False
                return True
            
            # Repetitive sequences (e.g., gffff, UUUUw)
            if length >= 5 and any(s_stripped.count(c) / length > 0.7 for c in set(s_stripped)):
                return True

            # Instruction fragment check (e.g., D$&f, |$81, L[^_])
            # High symbol density + short length often indicates binary noise
            symbols = sum(1 for c in s_stripped if not c.isalnum() and not c.isspace())
            if length < 10 and symbols / length > 0.5:
                # But keep if it looks like a known command part
                if not cmd_re.search(s_stripped): return True

            printable_ratio = sum(1 for c in s if 32 <= ord(c) <= 126) / len(s)
            if printable_ratio < 0.6: return True
            
            # Common compiler/instruction junk (e.g., ?. , ?? , __ , etc.)
            if s.startswith('__') or s.startswith('?.') or s.startswith('??'):
                # Keep if it looks like a real runtime error
                if not library_re.search(s): return True
            
            # Specific instruction patterns found in strings (Stack refs)
            if re.search(r'[\$\[\]\^]{3,}', s_stripped): return True

            return False

        def _add_string(val, ea_for_xref=None, stype="ASCII"):
            if not val: return
            val_strip = val.strip()
            
            # Determine Category first to see if it's "Interesting" enough to bypass junk filter
            cat = "String"
            if url_re.search(val_strip): cat = "URL"
            elif file_re.search(val_strip): cat = "File Path"
            elif reg_re.search(val_strip): cat = "Registry Key"
            elif ip_re.search(val_strip): cat = "IP Address"
            elif mutex_re.search(val_strip): cat = "Mutex"
            elif cmd_re.search(val_strip): cat = "Command"
            elif library_re.search(val_strip): cat = "Library/Runtime String"
            elif exe_re.search(val_strip): cat = "Filename"
            elif len(val_strip) >= 16 and (base64_re.match(val_strip) or hex_re.match(val_strip)):
                cat = "Encoded Data"
            elif len(val_strip) >= 12 and get_entropy(val_strip) > 3.8 and ' ' not in val_strip:
                cat = "Potential Encryption/Obfuscation"

            # Filter Junk unless it's specifically categorized as something interesting
            if cat in ["String", "Library/Runtime String"] and is_junk(val): return
            
            if val in seen_values: return
            seen_values.add(val)
            
            funcs = set()
            if ea_for_xref is not None:
                try:
                    for ref in idautils.DataRefsTo(ea_for_xref):
                        f = ida_funcs.get_func(ref)
                        if f:
                            fname = ida_funcs.get_func_name(f.start_ea)
                            if fname: funcs.add(fname)
                except: pass
            
            local_results.append({
                "value": val,
                "type": stype,
                "category": cat,
                "funcs": sorted(list(funcs))[:3]
            })

        log("Starting string extraction (synchronized)...", "info")

        # 1. Standard IDA Strings scan (Baseline)
        try:
            s_obj = idautils.Strings()
            # Setup with all types if possible
            s_obj.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
            for s in s_obj:
                stype = "ASCII"
                if hasattr(s, 'type') and s.type in (ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_P_16, ida_nalt.STRTYPE_LEN2_16):
                    stype = "Unicode"
                _add_string(str(s), s.ea, stype)
        except Exception as e:
            log(f"Baseline string scan error: {e}", "err")
        
        # 2. Strategic Supplement: Scan analyzed functions specifically
        if graph:
            try:
                for node in graph.values():
                    if node.is_library: continue
                    for item_ea in idautils.FuncItems(node.ea):
                        for xref in idautils.DataRefsFrom(item_ea):
                            s_content = idc.get_strlit_contents(xref)
                            if s_content:
                                try:
                                    val = s_content.decode('utf-8')
                                    stype = "ASCII"
                                except UnicodeDecodeError:
                                    try:
                                        val = s_content.decode('utf-16le')
                                        stype = "Unicode"
                                    except: continue
                                _add_string(val, xref, stype)
            except Exception as e:
                log(f"Function supplement scan error: {e}", "err")

        # 3. Decompiled Source Scan
        if graph:
            try:
                for node in graph.values():
                    if node.is_library: continue
                    try:
                        cfunc = ida_hexrays.decompile(node.ea)
                        if cfunc:
                            decompiled = str(cfunc)
                            found_literals = re.findall(r'"((?:[^"\\]|\\.)*)"', decompiled)
                            for val in found_literals:
                                _add_string(val, node.ea, "ASCII")
                    except: continue
            except Exception as e:
                log(f"Decompiled scan error: {e}", "err")

        # 4. Deterministic Segment Scanning (The "No matter what" scan)
        try:
            log("Performing deterministic segment-level scan...", "info")
            for i in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(i)
                if not seg: continue
                ea = seg.start_ea
                end_ea = seg.end_ea
                
                # Use chunks to avoid massive memory overhead
                chunk_size = 0x10000
                while ea < end_ea:
                    curr_chunk = min(chunk_size, end_ea - ea)
                    data = ida_bytes.get_bytes(ea, curr_chunk)
                    if data:
                        # ASCII Scan
                        for match in re.finditer(b'[ -~]{4,}', data):
                            try:
                                val = match.group().decode('ascii')
                                _add_string(val, ea + match.start(), "ASCII")
                            except: pass
                        # UTF-16LE Scan
                        for match in re.finditer(b'(?:[ -~]\x00){4,}', data):
                            try:
                                val = match.group().decode('utf-16le')
                                _add_string(val, ea + match.start(), "Unicode")
                            except: pass
                    ea += curr_chunk
        except Exception as e:
            log(f"Deterministic segment scan error: {e}", "err")
            
        results_container.extend(local_results)
        return idaapi.MFF_READ

    # Execute all IDA API calls on the main thread and collect result
    # We use MFF_WRITE for maximizing access permission on worker threads
    # We return results_container (list) regardless of execute_sync's return value
    idaapi.execute_sync(_sync_worker, idaapi.MFF_WRITE)
    
    if log_fn:
        log_fn(f"Extracted {len(results_container)} categorized strings.", "info")
    return results_container

def extract_deterministic_iocs(strings):
    """Fallback/Supplement for AI: extract high-confidence IOCs from strings."""
    iocs = []
    seen = set()
    for s_info in strings:
        val = s_info["value"]
        cat = s_info.get("category", "String")
        if val in seen: continue
        
        ioc_type = None
        if cat == "IP Address": ioc_type = "IP"
        elif cat == "URL": ioc_type = "Network Domain"
        elif cat == "Registry Key" and any(x in val.lower() for x in ["\\run", "currentversion", "software\\microsoft"]): 
            ioc_type = "Registry Key"
        elif cat == "Mutex": ioc_type = "Mutex"
        elif cat == "Command" and any(x in val.lower() for x in ["cmd.exe", "powershell", "-enc", "-w hidden"]):
            ioc_type = "Command Execution"
            
        if ioc_type:
            iocs.append({
                "type": ioc_type,
                "value": val,
                "context": f"Deterministic Detection: Identified as {cat} in binary strings.",
                "associated_functions": s_info.get("funcs", [])
            })
            seen.add(val)
    return iocs
    return iocs

def get_graph_ascii(graph, entry_ea):
    """Generate ASCII tree view for call graph."""
    if not entry_ea: return ""
    visited = set()
    lines = []
    def _recurse(ea, prefix="", is_last=True):
        node = graph.get(ea)
        if not node: return
        marker = "└── " if is_last else "├── "
        if ea in visited:
            lines.append(f"{prefix}{marker}{node.name} [0x{ea:X}] (recursive)")
            return
        visited.add(ea)
        lines.append(f"{prefix}{marker}{node.name} [0x{ea:X}]")
        new_prefix = prefix + ("    " if is_last else "│   ")
        callees = [c for c in sorted(node.callees) if c in graph and not graph[c].is_library]
        if len(lines) > 2500:
            if len(lines) == 2501: lines.append(f"{new_prefix}... (Truncated)")
            return
        for i, c_ea in enumerate(callees):
            _recurse(c_ea, new_prefix, i == len(callees) - 1)
    
    node = graph.get(entry_ea)
    if node:
        lines.append(f"{node.name} [0x{entry_ea:X}] (Entry)")
        callees = [c for c in sorted(node.callees) if c in graph and not graph[c].is_library]
        for i, c_ea in enumerate(callees):
            _recurse(c_ea, "", i == len(callees) - 1)
    return "\n".join(lines)


# ===========================================================================
# HTML REPORT GENERATION - CORE ENTRY
# ===========================================================================

def generate_html_report(graph, entry_ea, output_dir, sections, log_fn=None):
    """
    Generate the ONLY premium interactive HTML malware analysis report.
    This replaces all old markdown and PDF generation.
    """
    def _log(msg, level="info"): 
        if log_fn: log_fn(msg, level)

    _log("Synthesizing comprehensive HTML report...")

    # Load function JSON files from IDB/Disk and aggregate data
    functions_data = []
    suspicious_apis = {}  # Map for table format

    for node in graph.values():
        # --- API scanning pass #1: always run for call-tree attribution ---
        hits = get_api_tags_for_function(node.ea, getattr(node, "callees", []))
        for cat, apis in hits.items():
            sev = get_category_severity(cat)
            for api in apis:
                if api not in suspicious_apis:
                    suspicious_apis[api] = {"category": cat, "severity": sev, "funcs": []}
                if node.name not in suspicious_apis[api]["funcs"]:
                    suspicious_apis[api]["funcs"].append(node.name)

        # Skip library / compiler-generated functions from the decomposition report
        if node.is_library:
            continue

        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', node.name)[:60]
        json_path = os.path.join(output_dir, "analysis", "%s_0x%X.json" % (safe_name, node.ea))

        fd = {
            "name": node.name,
            "ea": node.ea,
            "risk_tag": getattr(node, "risk_tag", "benign"),
            "depth": getattr(node, "depth", 0),
            "confidence": getattr(node, "confidence", 0)
        }

        # Load analysis JSON if it exists
        try:
            if os.path.isfile(json_path):
                with open(json_path, "r", encoding="utf-8") as jf:
                    d = json.load(jf)
                fd.update({k: d.get(k, fd.get(k)) for k in [
                    "one_liner", "summary", "bullets", "suspicious", "risk_tag",
                    "return_value", "contextual_purpose", "risk_logic",
                    "capabilities", "semantic_tags", "confidence"
                ]})
        except: pass

        # Load generated readable code and raw decompiled code for the UI tabs
        rd = load_readable_from_disk(node.ea, node.name, output_dir)
        raw_decomp = load_decompiled_from_disk(node.ea, node.name, output_dir)
        fd["code"] = rd if rd else (cleanup_decompiled_code(raw_decomp) if raw_decomp else "")
        fd["raw_code"] = raw_decomp if raw_decomp else ""

        # --- API scanning pass #2: lexical scan of raw decompiled code ---
        # Catches dynamic/indirect calls missed by the static call-tree.
        scan_source = raw_decomp if raw_decomp else rd
        if scan_source:
            tokens = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]{3,})\b', scan_source))
            for token in tokens:
                token_l = token.lower()
                if token_l in _API_MAP:
                    entry = _API_MAP[token_l]
                    already_caught = False
                    for existing_api in suspicious_apis.keys():
                        if existing_api.lower() == token_l:
                            if node.name not in suspicious_apis[existing_api]["funcs"]:
                                suspicious_apis[existing_api]["funcs"].append(node.name)
                            already_caught = True
                            break
                    if not already_caught:
                        suspicious_apis[token] = {
                            "category": entry["category"],
                            "severity": entry["severity"],
                            "funcs": [node.name]
                        }

        functions_data.append(fd)
        
    # Global stats
    mal_count = sum(1 for f in functions_data if f.get("risk_tag") == "malicious")
    sus_count = sum(1 for f in functions_data if f.get("risk_tag") == "suspicious")
    overall_risk = "MALICIOUS" if mal_count else ("SUSPICIOUS" if sus_count else "BENIGN")
    risk_color = {"MALICIOUS": "#dc2626", "SUSPICIOUS": "#f59e0b", "BENIGN": "#16a34a"}[overall_risk]

    def _parse_ai_json(key):
        val = sections.get(key)
        if isinstance(val, dict):
            return val
        if not val or not isinstance(val, str):
            return {}
            
        raw = val.strip()

        def _pluck_best_effort(raw_str):
            """Aggressively extract meaningful content from a broken JSON/Markdown string."""
            pluck_keys = ["detailed_technical_overview", "detailed_narrative", "assessment", "summary", "verdict", "mechanisms", "findings", "steps", "capabilities"]
            extracted = {}
            for pk in pluck_keys:
                # Look for "key": "value... OR "key": [ ...
                pattern = f'"{pk}"\\s*:\\s*([\\"\\[])(.*)'
                m = re.search(pattern, raw_str, re.DOTALL)
                if m:
                    starter = m.group(1)
                    content_raw = m.group(2).strip()
                    
                    if starter == '"':
                        # Handle String: Capture until next key or structural break
                        # We try to find the next key pattern: ", "something":
                        next_key = re.search(r'",\s*"[^"]+"\s*:', content_raw)
                        if next_key: content_raw = content_raw[:next_key.start()]
                        # Conservative Cleanup: Only remove trailing JSON structural noise
                        # Match a quote followed by optional whitespace and structural markers (comma/brace/bracket),
                        # but only if it's the LAST such sequence in the string (no more quotes after it).
                        content_raw = re.sub(r'"\s*[,\}\]]\s*[^"]*$', '', content_raw, flags=re.DOTALL).strip()
                        if content_raw.endswith('"'): content_raw = content_raw[:-1]
                        extracted[pk] = content_raw.strip()
                    else:
                        # Handle List: Attempt to parse as many items as possible
                        # Aggressive Repair: Handle unclosed strings inside the list
                        # This looks for the last " and tries to close it if it's dangling
                        if content_raw.count('"') % 2 != 0:
                            content_raw += '"'
                        
                        list_str = "[" + content_raw
                        for tail in ["]", "}]", "}]}", "}}]}"]:
                            try:
                                res = json.loads(list_str + tail)
                                if res: 
                                    extracted[pk] = res
                                    break
                            except: pass
            return extracted
        
        # Helper to try parsing and fixing truncated JSON
        def _try_json(s):
            try:
                res = json.loads(s)
                if res is not None: return res
            except:
                # Truncation repair: try adding closing characters
                # Try simple tails first
                for tail in ["}", "]", "}]", "}}", "}]}", "}}]}"]:
                    try:
                        res = json.loads(s + tail)
                        if res is not None: return res
                    except: pass
                # Aggressive repair: handle unclosed strings (common in truncation)
                for tail in ["\"}", "\"]", "\"}]", "\"}}", "\"}]}", "\"}}]}"]:
                    try:
                        res = json.loads(s + tail)
                        if res is not None: return res
                    except: pass
            return None

        # 1. Direct attempt
        res = _try_json(raw)
        if res: return res
        
        # 2. Markdown cleaning attempt
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw)
        cleaned = re.sub(r"```\s*$", "", cleaned).strip()
        res = _try_json(cleaned)
        if res: return res
        
        # 3. Aggressive Pluck
        res = _pluck_best_effort(raw)
        if res: return res

        return {}

    # --- 0. Prepare Forensic Data (Strings & Deterministic IOCs)
    s_data = extract_ida_strings(graph, _log)
    det_iocs = extract_deterministic_iocs(s_data)
    _log(f"Extracted {len(s_data)} strings and {len(det_iocs)} deterministic IOCs.")

    # --- 1. Executive Summary
    exec_json = _parse_ai_json("assessment")
    narrative = ""
    if isinstance(exec_json, dict):
        narrative = exec_json.get("assessment") or exec_json.get("detailed_narrative") or ""
    
    if narrative:
        exec_summary_html = f'<div class="ai-block" style="border-left-color:var(--accent); white-space: pre-wrap; padding: 25px; line-height: 1.6;">{_escape_html(narrative)}</div>'
    elif isinstance(exec_json, dict) and any(k in exec_json for k in ["verdict", "reasoning", "core_operation", "function_tree_analysis"]):
        # Fallback for old data or specific keys
        v = exec_json.get("verdict", "")
        r = exec_json.get("reasoning", "")
        c = exec_json.get("core_operation", "")
        f = exec_json.get("function_tree_analysis", "")
        exec_summary_html = f'<div class="ai-block" style="padding: 25px; line-height: 1.6;"><b>Verdict:</b> {v}<br/><br/><b>Reasoning:</b> {r}<br/><br/><b>Core Operation:</b> {c}<br/><br/><b>Analysis:</b> {f}</div>'
    else:
        # Final fallback from raw sections
        summ = sections.get("assessment") or "Assessment data absent or AI synthesis failed."
        if isinstance(summ, dict):
            summ = summ.get("assessment") or summ.get("detailed_narrative") or str(summ)
        # Scrub JSON leftovers if present in raw string
        if isinstance(summ, str) and ("assessment" in summ or "detailed_narrative" in summ):
            m = re.search(r'"(?:assessment|detailed_narrative)"\s*:\s*"(.*)', summ, re.DOTALL)
            if m:
                summ = re.sub(r'"\s*[,\}\]]\s*[^"]*$', '', m.group(1), flags=re.DOTALL).strip()
                if summ.endswith('"'): summ = summ[:-1]
        
        exec_summary_html = f'<div class="ai-block" style="padding: 25px; line-height: 1.6;">{_escape_html(str(summ))}</div>'

    # --- 2. Technical Code Analysis Overview
    overview_json = _parse_ai_json("overview")
    tech_narrative = ""
    if isinstance(overview_json, dict):
        tech_narrative = overview_json.get("detailed_technical_overview", "")
    
    def _format_ai_text(raw: str) -> str:
        """Convert AI text with literal \n and \" sequences into proper HTML paragraphs."""
        # Decode literal backslash-n and backslash-quote from the JSON string value
        text = raw.replace('\\n', '\n').replace('\\"', '"').replace('\\t', ' ')
        # Split on double-newlines → paragraph blocks
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
        if not paragraphs:
            return _escape_html(raw)
        parts = []
        for para in paragraphs:
            # Numbered heading like "1. Title: rest" → bold label + rest
            m = re.match(r'^(\d+\.\s*[^:]+:)(.*)$', para, re.DOTALL)
            if m:
                heading = _escape_html(m.group(1).strip())
                body = _escape_html(m.group(2).strip()).replace('\n', '<br>')
                parts.append(f'<p style="margin:0 0 10px 0;"><strong style="color:#1e293b;">{heading}</strong> {body}</p>')
            else:
                body = _escape_html(para).replace('\n', '<br>')
                parts.append(f'<p style="margin:0 0 10px 0;">{body}</p>')
        return ''.join(parts)

    if tech_narrative:
        tech_overview_html = f'<div class="ai-block" style="border-left-color:#3b82f6; padding: 25px; line-height: 1.7;">{_format_ai_text(tech_narrative)}</div>'
    else:
        # Fallback Narrative Plucking from raw text
        ov_text = sections.get("overview") or ""
        # If it's a dict from legacy processing
        if isinstance(ov_text, dict):
            ol = ov_text.get("operational_logic", "")
            df = ov_text.get("data_flow", "")
            ch = ov_text.get("choreography", "")
            ov_text = "\n\n".join([x for x in [ol, df, ch] if x])
        
        # Clean up raw string if it contains the JSON wrapper but failed parsing
        if isinstance(ov_text, str) and ("detailed_technical_overview" in ov_text):
            m = re.search(r'"detailed_technical_overview"\s*:\s*"(.*)', ov_text, re.DOTALL)
            if m:
                ov_text = m.group(1).strip()
                ov_text = re.sub(r'"\s*[,\}\]]\s*[^"]*$', '', ov_text, flags=re.DOTALL).strip()
                if ov_text.endswith('"'): ov_text = ov_text[:-1]

        ov_text = ov_text or "Technical analysis data absent or AI synthesis failed."
        tech_overview_html = f'<div class="ai-block" style="border-left-color:#3b82f6; padding: 25px; line-height: 1.7;">{_format_ai_text(str(ov_text))}</div>'

    # --- 3. Execution Flow Overview (NEW)
    exec_flow_json = _parse_ai_json("execution_flow")
    if exec_flow_json and isinstance(exec_flow_json, dict) and "steps" in exec_flow_json:
        steps_rows = ""
        for s in exec_flow_json.get("steps", []):
            if isinstance(s, dict):
                phase = _escape_html(s.get("phase", ""))
                desc = _escape_html(s.get("description", ""))
                steps_rows += f'<tr><td style="font-weight:bold; width:180px;">{phase}</td><td class="muted">{desc}</td></tr>'
        execution_flow_html = f'<table class="data-table"><thead><tr><th>Phase</th><th>Execution Description</th></tr></thead><tbody>{steps_rows}</tbody></table>' if steps_rows else f'<p class="muted">No execution flow steps identified.</p>'
    else:
        execution_flow_html = f'<div class="ai-block">{_escape_html(sections.get("execution_flow", "Execution flow analysis pending..."))}</div>'

    # --- 4. General Capability or Malware Features
    caps_json = _parse_ai_json("capabilities")
    cap_rows = ""
    if caps_json and isinstance(caps_json, dict) and "capabilities" in caps_json:
        for c in caps_json.get("capabilities", []):
            if isinstance(c, dict):
                name = _escape_html(c.get("name", ""))
                desc = _escape_html(c.get("description", ""))
                funcs = c.get("associated_functions") or c.get("functions") or []
                if isinstance(funcs, str): funcs = [funcs]
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                cap_rows += f'<tr><td style="font-weight:bold; color:#1e293b; width:220px;">{name}</td><td class="muted">{desc}</td><td style="width:250px;">{f_html}</td></tr>'
        capabilities_html = f'<table class="data-table"><thead><tr><th>Capability</th><th>Description</th><th>Associated Functions</th></tr></thead><tbody>{cap_rows}</tbody></table>' if cap_rows else f'<p class="muted">No general capabilities identified.</p>'
    else:
        capabilities_html = f'<div class="ai-block">{_escape_html(sections.get("capabilities", "Capabilities pending..."))}</div>'

    # --- 5. C2/Backdoor Analysis
    c2_json = _parse_ai_json("c2_analysis")
    c2_rows = ""
    _summ = ""
    
    # --- 5. C2/Backdoor Analysis
    c2_json = _parse_ai_json("c2_analysis")
    c2_rows = ""
    _summ = ""
    
    # Normalize: Handle both {"mechanisms": [...]} and raw list [...]
    c2_mechanisms = []
    if isinstance(c2_json, dict):
        _summ = c2_json.get("summary", "")
        c2_mechanisms = c2_json.get("mechanisms", [])
    elif isinstance(c2_json, list):
        c2_mechanisms = c2_json

    if c2_mechanisms:
        for m in c2_mechanisms:
            if isinstance(m, dict):
                feat = _escape_html(m.get("feature", ""))
                evid = _escape_html(m.get("evidence", ""))
                funcs = m.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                c2_rows += f'<tr><td style="font-weight:bold; width:180px;">{feat}</td><td>{evid}</td><td class="muted">{f_html}</td></tr>'
        
    c2_accent = "#dc2626"
    c2_summary_html = f'<div class="ai-block" style="border-left-color:{c2_accent}; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_escape_html(_summ)}</div>' if _summ else ""
    
    if c2_rows:
        c2_analysis_html = c2_summary_html + f'<table class="data-table"><thead><tr><th>Mechanism</th><th>Technical Evidence</th><th>Source Functions</th></tr></thead><tbody>{c2_rows}</tbody></table>'
    elif _summ:
        c2_analysis_html = c2_summary_html + f'<p class="muted">Summary synthesized; no granular mechanisms extracted in table format.</p>'
    else:
        # Final fallback: display raw text but clean it up
        raw_c2 = sections.get("c2_analysis", "")
        if not raw_c2 or (isinstance(raw_c2, dict) and not any(raw_c2.values())):
            c2_analysis_html = '<p class="muted">C2 analysis pending or result empty.</p>'
        else:
            # Strict Cleanup: Strip whitespace and check for boilerplate empty JSON
            # This handles cases where AI returns formatted JSON like:
            # { "mechanisms": [] }
            clean_c2 = re.sub(r'```(?:json)?|```', '', str(raw_c2)).strip()
            # Normalize whitespace for comparison
            normalized = re.sub(r'\s+', '', clean_c2)
            if normalized in ["{}", "{\"mechanisms\":[]}", "[]"]:
                c2_analysis_html = '<p class="muted">No explicit C2/Backdoor communication logic detected.</p>'
            else:
                c2_analysis_html = f'<div class="ai-block" style="border-left-color:{c2_accent}; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_c2)}</div>'

    # --- 6. Persistence Mechanisms
    pers_json = _parse_ai_json("persistence")
    pers_rows = ""
    _psumm = ""
    
    pers_mechanisms = []
    if isinstance(pers_json, dict):
        _psumm = pers_json.get("summary", "")
        pers_mechanisms = pers_json.get("mechanisms", [])
    elif isinstance(pers_json, list):
        pers_mechanisms = pers_json

    if pers_mechanisms:
        for m in pers_mechanisms:
            if isinstance(m, dict):
                meth = _escape_html(m.get("method", ""))
                det = _escape_html(m.get("details", ""))
                funcs = m.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                pers_rows += f'<tr><td style="font-weight:bold; width:180px;">{meth}</td><td>{det}</td><td class="muted">{f_html}</td></tr>'
        
    pers_accent = "#f97316"
    pers_summary_html = f'<div class="ai-block" style="border-left-color:{pers_accent}; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_escape_html(_psumm)}</div>' if _psumm else ""
    
    if pers_rows:
        persistence_html = pers_summary_html + f'<table class="data-table"><thead><tr><th>Persistence Method</th><th>Technical Details</th><th>Source Functions</th></tr></thead><tbody>{pers_rows}</tbody></table>'
    elif _psumm:
        persistence_html = pers_summary_html + f'<p class="muted">Summary synthesized; no granular mechanisms extracted in table format.</p>'
    else:
        raw_pers = sections.get("persistence", "")
        if not raw_pers or (isinstance(raw_pers, dict) and not any(raw_pers.values())):
            persistence_html = '<p class="muted">No specific persistence mechanisms detected.</p>'
        else:
            clean_pers = re.sub(r'```(?:json)?|```', '', str(raw_pers)).strip()
            normalized = re.sub(r'\s+', '', clean_pers)
            if normalized in ["{}", "{\"mechanisms\":[]}", "[]"]:
                persistence_html = '<p class="muted">No explicit persistence mechanisms identified.</p>'
            else:
                persistence_html = f'<div class="ai-block" style="border-left-color:{pers_accent}; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_pers)}</div>'

    # --- 7. Reconnaissance or Info Stealer
    recon_json = _parse_ai_json("recon_infostealer")
    recon_rows = ""
    _rsumm = ""
    
    recon_findings = []
    if isinstance(recon_json, dict):
        _rsumm = recon_json.get("summary", "")
        recon_findings = recon_json.get("findings", [])
    elif isinstance(recon_json, list):
        recon_findings = recon_json

    if recon_findings:
        for f in recon_findings:
            if isinstance(f, dict):
                cat = _escape_html(f.get("category", ""))
                desc = _escape_html(f.get("description", ""))
                funcs = f.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                recon_rows += f'<tr><td style="font-weight:bold; width:180px;">{cat}</td><td>{desc}</td><td class="muted">{f_html}</td></tr>'
        
    recon_accent = "#8b5cf6"
    recon_summary_html = f'<div class="ai-block" style="border-left-color:{recon_accent}; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_escape_html(_rsumm)}</div>' if _rsumm else ""
    
    if recon_rows:
        recon_infostealer_html = recon_summary_html + f'<table class="data-table"><thead><tr><th>Category</th><th>Forensic Discovery</th><th>Source Functions</th></tr></thead><tbody>{recon_rows}</tbody></table>'
    elif _rsumm:
        recon_infostealer_html = recon_summary_html + f'<p class="muted">Summary synthesized; no specific info-stealing artifacts extracted in table format.</p>'
    else:
        raw_recon = sections.get("recon_infostealer", "")
        if not raw_recon or (isinstance(raw_recon, dict) and not any(raw_recon.values())):
            recon_infostealer_html = '<p class="muted">No explicit reconnaissance or info-stealing patterns identified.</p>'
        else:
            clean_recon = re.sub(r'```(?:json)?|```', '', str(raw_recon)).strip()
            normalized = re.sub(r'\s+', '', clean_recon)
            if normalized in ["{}", "{\"findings\":[]}", "[]"]:
                recon_infostealer_html = '<p class="muted">No relevant reconnaissance routines detected.</p>'
            else:
                recon_infostealer_html = f'<div class="ai-block" style="border-left-color:{recon_accent}; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_recon)}</div>'

    # --- 8. File / Registry / Process Interaction
    inter_json = _parse_ai_json("file_registry_interaction")
    inter_rows = ""
    
    inter_list = []
    if isinstance(inter_json, dict):
        inter_list = inter_json.get("interactions", [])
    elif isinstance(inter_json, list):
        inter_list = inter_json

    if inter_list:
        for i in inter_list:
            if isinstance(i, dict):
                itype = _escape_html(i.get("type", ""))
                iact = _escape_html(i.get("action", ""))
                itarg = _escape_html(i.get("target", ""))
                idesc = _escape_html(i.get("description", ""))
                funcs = i.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                inter_rows += f'<tr><td style="font-weight:bold; width:120px;">{itype}</td><td style="width:100px;">{iact}</td><td><code>{itarg}</code><br/><small class="muted">{idesc}</small></td><td class="muted">{f_html}</td></tr>'
        
        interaction_html = f'<table class="data-table"><thead><tr><th>Type</th><th>Action</th><th>Target & Significance</th><th>Source Functions</th></tr></thead><tbody>{inter_rows}</tbody></table>'
    else:
        raw_inter = sections.get("file_registry_interaction", "")
        if not raw_inter or (isinstance(raw_inter, dict) and not any(raw_inter.values())):
            interaction_html = '<p class="muted">No significant OS interactions recorded.</p>'
        else:
            clean_inter = re.sub(r'```(?:json)?|```', '', str(raw_inter)).strip()
            normalized = re.sub(r'\s+', '', clean_inter)
            if normalized in ["{}", "{\"interactions\":[]}", "[]"]:
                interaction_html = '<p class="muted">No direct OS object manipulation identified.</p>'
            else:
                interaction_html = f'<div class="ai-block" style="border-left-color:#64748b; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_inter)}</div>'

    # --- 9. API Hashing / Resolving / PEB Walk
    resolv_json = _parse_ai_json("api_resolving")
    res_rows = ""
    
    resolv_list = []
    if isinstance(resolv_json, dict):
        resolv_list = resolv_json.get("techniques", [])
    elif isinstance(resolv_json, list):
        resolv_list = resolv_json

    if resolv_list:
        for t in resolv_list:
            if isinstance(t, dict):
                rname = _escape_html(t.get("name", ""))
                rdesc = _escape_html(t.get("description", ""))
                funcs = t.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                res_rows += f'<tr><td style="font-weight:bold; width:200px;">{rname}</td><td>{rdesc}</td><td class="muted">{f_html}</td></tr>'
        
        api_resolving_html = f'<table class="data-table"><thead><tr><th>Resolution Technique</th><th>Technical Details</th><th>Source Functions</th></tr></thead><tbody>{res_rows}</tbody></table>'
    else:
        raw_res = sections.get("api_resolving", "")
        if not raw_res or (isinstance(raw_res, dict) and not any(raw_res.values())):
            api_resolving_html = '<p class="muted">No dynamic API resolution techniques identified.</p>'
        else:
            clean_res = re.sub(r'```(?:json)?|```', '', str(raw_res)).strip()
            normalized = re.sub(r'\s+', '', clean_res)
            if normalized in ["{}", "{\"techniques\":[]}", "[]"]:
                api_resolving_html = '<p class="muted">No indirect API resolving found.</p>'
            else:
                api_resolving_html = f'<div class="ai-block" style="border-left-color:#64748b; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_res)}</div>'

    # --- 10. Packer/Obfuscation or Anti-Analysis
    anti_json = _parse_ai_json("anti_analysis")
    anti_rows = ""
    
    anti_list = []
    if isinstance(anti_json, dict):
        anti_list = anti_json.get("techniques", [])
    elif isinstance(anti_json, list):
        anti_list = anti_json

    if anti_list:
        for t in anti_list:
            if isinstance(t, dict):
                aname = _escape_html(t.get("name", ""))
                adesc = _escape_html(t.get("description", ""))
                funcs = t.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                anti_rows += f'<tr><td style="font-weight:bold; width:200px;">{aname}</td><td>{adesc}</td><td class="muted">{f_html}</td></tr>'
        
        anti_analysis_html = f'<table class="data-table"><thead><tr><th>Anti-Analysis Technique</th><th>Technical Reasoning</th><th>Source Functions</th></tr></thead><tbody>{anti_rows}</tbody></table>'
    else:
        raw_anti = sections.get("anti_analysis", "")
        if not raw_anti or (isinstance(raw_anti, dict) and not any(raw_anti.values())):
            anti_analysis_html = '<p class="muted">No packers or anti-analysis techniques identified.</p>'
        else:
            clean_anti = re.sub(r'```(?:json)?|```', '', str(raw_anti)).strip()
            normalized = re.sub(r'\s+', '', clean_anti)
            if normalized in ["{}", "{\"techniques\":[]}", "[]"]:
                anti_analysis_html = '<p class="muted">No anti-debugging or anti-VM logic found.</p>'
            else:
                anti_analysis_html = f'<div class="ai-block" style="border-left-color:#64748b; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_anti)}</div>'

    # --- 11. Cryptographic Artifacts
    crypto_json = _parse_ai_json("crypto_artifacts")
    cry_rows = ""
    
    crypto_list = []
    if isinstance(crypto_json, dict):
        crypto_list = crypto_json.get("artifacts", [])
    elif isinstance(crypto_json, list):
        crypto_list = crypto_json

    if crypto_list:
        for c in crypto_list:
            if isinstance(c, dict):
                cname = _escape_html(c.get("algorithm", c.get("name", "")))
                cdesc = _escape_html(c.get("purpose", c.get("description", "")))
                funcs = c.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                cry_rows += f'<tr><td style="font-weight:bold; width:200px;">{cname}</td><td>{cdesc}</td><td class="muted">{f_html}</td></tr>'
        
        crypto_artifacts_html = f'<table class="data-table"><thead><tr><th>Cryptographic Algorithm</th><th>Forensic Purpose</th><th>Source Functions</th></tr></thead><tbody>{cry_rows}</tbody></table>'
    else:
        raw_cry = sections.get("crypto_artifacts", "")
        if not raw_cry or (isinstance(raw_cry, dict) and not any(raw_cry.values())):
            crypto_artifacts_html = '<p class="muted">No cryptographic artifacts identified.</p>'
        else:
            clean_cry = re.sub(r'```(?:json)?|```', '', str(raw_cry)).strip()
            normalized = re.sub(r'\s+', '', clean_cry)
            if normalized in ["{}", "{\"artifacts\":[]}", "[]"]:
                crypto_artifacts_html = '<p class="muted">No cryptographic constants or algorithms detected.</p>'
            else:
                crypto_artifacts_html = f'<div class="ai-block" style="border-left-color:#64748b; white-space: pre-wrap; padding: 25px;">{_escape_html(clean_cry)}</div>'

    # --- 12. Suspicious Imports
    api_rows = ""
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for api, info in sorted(suspicious_apis.items(), key=lambda x: sev_order.get(x[1]["severity"],"LOW")):
        sev = info["severity"]
        scolor = {"HIGH":"#dc2626","MEDIUM":"#f59e0b","LOW":"#16a34a"}.get(sev,"#6b7280")
        fnames = ", ".join(info["funcs"][:10]) + ("..." if len(info["funcs"])>10 else "")
        api_rows += f'<tr><td><code>{_escape_html(api)}</code></td><td>{_escape_html(info["category"])}</td><td><span class="sev-badge" style="background:{scolor};">{sev}</span></td><td class="muted">{_escape_html(fnames)}</td></tr>'
    
    suspicious_imports_html = f'<table class="data-table"><thead><tr><th>API Name</th><th>Category</th><th>Severity</th><th>Associated Functions</th></tr></thead><tbody>{api_rows}</tbody></table>' if api_rows else '<p class="muted">No explicit high-risk imports detected.</p>'

    # --- 9. TTP Mapping (MITRE ATTACK)
    mitre_techs = _mitre_from_data(functions_data)
    mitre_rows = ""
    for tid, tname, funcs in mitre_techs:
        u = tid.replace(".","/")+("/" if "." not in tid else "")
        mitre_rows += f'<tr><td><a href="https://attack.mitre.org/techniques/{u}" target="_blank"><b>{_escape_html(tid)}</b></a></td><td>{_escape_html(tname)}</td><td class="muted">{_escape_html(funcs)}</td></tr>'
    ttp_html = f'<table class="data-table"><thead><tr><th>Technique ID</th><th>Technique Name</th><th>Associated Functions</th></tr></thead><tbody>{mitre_rows}</tbody></table>' if mitre_rows else '<p class="muted">No distinct capabilities matched exact MITRE techniques.</p>'

    # --- 10. Indicator of Compromise (IOC)
    ioc_json = _parse_ai_json("behavioral")
    if not ioc_json or not isinstance(ioc_json, dict): ioc_json = {"iocs": []}
    if "iocs" not in ioc_json: ioc_json["iocs"] = []
    
    # Merge deterministic IOCs
    existing_vals = {str(i.get("value", "")).lower() for i in ioc_json["iocs"] if isinstance(i, dict)}
    for di in det_iocs:
        if str(di.get("value", "")).lower() not in existing_vals:
            ioc_json["iocs"].append(di)

    if ioc_json and isinstance(ioc_json, dict) and "iocs" in ioc_json:
        ioc_rows = ""
        for ioc in ioc_json.get("iocs", []):
            if isinstance(ioc, dict):
                _type = _escape_html(ioc.get("type", ""))
                _val = _escape_html(ioc.get("value", ""))
                _ctx = _escape_html(ioc.get("context", ""))
                
                # Associated functions handle
                funcs = ioc.get("associated_functions") or ioc.get("functions") or []
                if isinstance(funcs, str): funcs = [funcs]
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                
                ioc_rows += f'<tr><td style="font-weight:600;">{_type}</td><td><code style="color:#dc2626; background:#fef2f2; padding:2px 4px; border-radius:4px;">{_val}</code></td><td class="muted">{_ctx}</td><td class="muted" style="width:250px;">{f_html}</td></tr>'
        if ioc_rows:
            ioc_html = f'<table class="data-table"><thead><tr><th>Type</th><th>Value</th><th>Context</th><th>Associated Functions</th></tr></thead><tbody>{ioc_rows}</tbody></table>'
        else:
            ioc_html = f'<p class="muted">No specific indicator signatures extracted.</p>'
    else:
        ioc_html = f'<div class="ai-block">{_escape_html(sections.get("behavioral", "IOC discovery pending..."))}</div>'

    # --- 11. Strings analysis
    ranked_json = _parse_ai_json("ranked_strings")
    s_rows = ""
    # s_data already extracted at start
    
    # Merge LLM ranking/importance if available
    llm_importance = {}
    
    # Pre-populate with Deterministic findings (inherently High)
    for di in det_iocs:
        llm_importance[di["value"]] = "High"

    if ranked_json and isinstance(ranked_json, dict) and "ranked_strings" in ranked_json:
        for item in ranked_json["ranked_strings"]:
            # Only overwrite if not already marked High by deterministic scan
            val = item.get("value", "")
            if val not in llm_importance or llm_importance[val] != "High":
                llm_importance[val] = item.get("importance", "Medium")

    # 🛑 CRITICAL FIX: Ensure 1:1 consistency between IOC section and String section
    # Use the ioc_json we already built/merged above instead of re-parsing
    if ioc_json and isinstance(ioc_json, dict) and "iocs" in ioc_json:
        for ioc in ioc_json.get("iocs", []):
            if isinstance(ioc, dict):
                val = str(ioc.get("value", ""))
                if val:
                    # Mark as High if it's an IOC
                    llm_importance[val] = "High"
                    
                    if val not in [s["value"] for s in s_data]:
                        # Inject manually identified IOC string into s_data if missing
                        s_data.append({
                            "value": val,
                            "type": "AI Extracted",
                            "category": str(ioc.get("type", "Indicator")),
                            "funcs": ioc.get("associated_functions") or []
                        })

    for s in s_data:
        val = _escape_html(s["value"])
        stype = _escape_html(s.get("type", "ASCII"))
        scat = _escape_html(s.get("category", "String"))
        importance = llm_importance.get(s["value"], "Low")
        imp_color = {"High": "#dc2626", "Medium": "#f59e0b", "Low": "#64748b"}.get(importance, "#64748b")
        
        f_html = ", ".join([f'<code>{_escape_html(f)}</code>' for f in s["funcs"]])
        s_rows += f'''
        <tr>
            <td><span style="color:{imp_color}; font-weight:bold;">{importance}</span></td>
            <td>{scat} ({stype})</td>
            <td style="word-break:break-all; font-family:'Fira Code', 'Cascadia Code', monospace; font-size:12px;">{val}</td>
            <td class="muted" style="width:250px;">{f_html}</td>
        </tr>'''
    
    if s_rows:
        strings_html = f'''
        <details class="fn-card" style="margin-top:0; border:1px solid #e2e8f0; box-shadow:none;">
            <summary style="padding:15px; cursor:pointer; font-weight:600; color:#1e293b; background:#f8fafc; border-radius:8px;">
                View Extracted Strings ({len(s_data)} artifacts found)
            </summary>
            <div style="padding:15px;">
                <table class="data-table" style="box-shadow:none; border:none; margin-top:0;">
                    <thead><tr><th style="width:80px;">Rank</th><th style="width:150px;">Category</th><th>String Value</th><th>Associated Functions</th></tr></thead>
                    <tbody>{s_rows}</tbody>
                </table>
            </div>
        </details>'''
    else:
        strings_html = '<p class="muted">No significant strings discovered.</p>'

    # --- 8. Function Analysis
    # 8.1 Call Chain Analysis
    call_chain_nodes = [f for f in functions_data if f.get("depth", 99) <= 2][:10]
    chain_html = ""
    for f in call_chain_nodes:
        cl = {"malicious":"#dc2626","suspicious":"#f59e0b","benign":"#16a34a"}.get(f.get("risk_tag"),"#94a3b8")
        chain_html += f'<div class="chain-box" style="border-left-color:{cl};"><b>{f["name"]}</b> <span class="muted">(Depth {f["depth"]})</span><br/><small>{_escape_html(f.get("one_liner") or "Entry execution path")}</small></div>'
    
    # 8.2 Call Graph (Tree View)
    tree_ascii = get_graph_ascii(graph, entry_ea)
    tree_view_html = f'<pre><code class="language-plaintext">{_escape_html(tree_ascii)}</code></pre>'

    # 8.3 Mermaid Visual Call Flow
    mermaid_svg = sections.get("mermaid", "")
    mermaid_html = ""
    if mermaid_svg:
        mermaid_html = f'''
        <div id="mermaid-container" style="margin-bottom:15px;">
          <div id="zoom-controls">
            <button onclick="zoomMermaid(1.2)"><b>+</b> Zoom In</button>
            <button onclick="zoomMermaid(0.8)"><b>-</b> Zoom Out</button>
            <button onclick="resetMermaidZoom()">Reset</button>
          </div>
          <div id="mermaid-diagram" class="mermaid">{mermaid_svg}</div>
        </div>
        
        <details class="code-details" style="border:1px solid #cbd5e1; box-shadow:none; margin-bottom:20px;">
          <summary style="padding:10px 15px; background:#f8fafc; cursor:pointer; font-weight:600; display:flex; justify-content:space-between; align-items:center;">
            <span style="display:flex; align-items:center; gap:8px;">
              <svg style="width:16px; height:16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
              Raw Mermaid Source Code (Export to mermaid.live)
            </span>
            <button onclick="copyMermaidCode(event)" style="background:#4f46e5; color:white; border:none; padding:5px 15px; border-radius:6px; font-size:12px; cursor:pointer; font-weight:600; transition:0.2s;">Copy Code</button>
          </summary>
          <pre id="raw-mermaid-code" style="margin:0; border-radius:0; background:#0f172a; color:#cbd5e1; font-size:11px; border-top:1px solid #e2e8f0; white-space: pre-wrap;">{_escape_html(mermaid_svg)}</pre>
        </details>
        '''
    else:
        mermaid_html = '<p class="muted">No meaningful custom flowchart available.</p>'

    # --- 9 & 10. Malicious / Suspicious functions
    def _create_ai_func_html(ai_key, filter_tag):
        ai_json = _parse_ai_json(ai_key)
        
        # Build normalized mapping for more robust lookup (ignore case/parens)
        def _norm(n): return str(n).lower().strip().rstrip("()").strip()
        name_to_ea = {_norm(f["name"]): f["ea"] for f in functions_data}
        
        ai_rows = ""
        if ai_json and isinstance(ai_json, dict) and "functions" in ai_json:
            for f in ai_json.get("functions", []):
                if isinstance(f, dict):
                    name = f.get("name", "Unknown")
                    addr = str(f.get("address", ""))
                    reason = _escape_html(f.get("reasoning", "No detail provided."))
                    
                    # Robust address resolving: search name_to_ea OR try to parse raw hex from AI 'addr'
                    real_ea = name_to_ea.get(_norm(name))
                    
                    if real_ea is not None:
                        display_addr = f"0x{real_ea:X}"
                        link_id = f"fn_{real_ea:X}"
                    else:
                        # Search for a hex address in the 'addr' field or 'name' string if name is like sub_401000
                        hex_match = re.search(r'(?:0x)?([0-9a-fA-F]{4,16})', str(addr) + " " + str(name))
                        if hex_match:
                            try:
                                parsed_ea = int(hex_match.group(1), 16)
                                display_addr = f"0x{parsed_ea:X}"
                                link_id = f"fn_{parsed_ea:X}"
                            except:
                                display_addr = "N/A"
                                link_id = "sec-1"
                        else:
                            display_addr = "N/A"
                            link_id = "sec-1"
                        
                    ai_rows += f'''
                    <tr>
                        <td style="width:100px; font-family:monospace;">
                            <a href="#{link_id}" style="color:#2563eb; text-decoration:none; font-weight:600;">{display_addr}</a>
                        </td>
                        <td style="font-weight:600; color:#1e293b;">{_escape_html(name)}</td>
                        <td class="muted" style="font-size:12.5px;">{reason}</td>
                    </tr>'''
        
        # Build Verified Taxonomy table
        rows = ""
        for f in functions_data:
            if str(f.get("risk_tag", "")).lower() == filter_tag:
                one = f.get("one_liner") or f.get("summary") or "Awaiting granular analysis..."
                rows += f'<tr><td style="width:100px; font-family:monospace;"><a href="#fn_{f["ea"]:X}">0x{f["ea"]:X}</a></td><td><a href="#fn_{f["ea"]:X}"><b>{_escape_html(f["name"])}</b></a></td><td>{_risk_badge(filter_tag)}</td><td>{_escape_html(one)}</td><td>{f["confidence"]}%</td></tr>'
        
        local_tbl = f'<table class="data-table sortable"><thead><tr><th>Address</th><th>Function Name</th><th>Risk Tag</th><th>One-liner</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table>' if rows else f'<p class="muted">No verified {filter_tag} functions in taxonomy.</p>'
        
        ai_html = f'''
        <div style="margin-bottom:25px;">
            <div style="font-weight:bold; color:#64748b; margin-bottom:10px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">AI Behavioral Synthesis:</div>
            <table class="data-table" style="border: 1px solid #f1f5f9; box-shadow:none;">
                <thead><tr><th>Target Address</th><th>Function Identifier</th><th>Forensic Reasoning & Pattern Discovery</th></tr></thead>
                <tbody>{ai_rows}</tbody>
            </table>
        </div>''' if ai_rows else ''
        
        taxonomy_html = f'''
        <div>
            <div style="font-weight:bold; color:#64748b; margin-bottom:10px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Verified Forensic Taxonomy:</div>
            {local_tbl}
        </div>'''
        return ai_html + taxonomy_html

    mal_tbl = _create_ai_func_html("malicious", "malicious")
    sus_tbl = _create_ai_func_html("suspicious", "suspicious")
    benign_tbl = _create_ai_func_html("benign", "benign")

    # --- 11. Function Decomposition
    _order = {"malicious": 0, "suspicious": 1, "benign": 2}
    functions_data.sort(key=lambda x: (int(x.get("depth", 999)), _order.get(x.get("risk_tag", "benign"), 2)))
    
    decomp_html = ""
    for f in functions_data:
        ea = f["ea"]
        risk = f.get("risk_tag", "benign")
        bullets = "".join([f'<li>{_escape_html(b)}</li>' for b in f.get("bullets", [])])
        
        c = f.get("code", "")
        code_block = f'<pre><code class="language-c">{_escape_html(c)}</code></pre>' if c else '<div class="muted">No readable code source found. LLM output missing.</div>'
        
        suggested_html = ""
        snames = f.get("suggested_names", [])
        if not snames and f.get("suggested_func_name"):
            snames = [f["suggested_func_name"]]
        
        if snames:
            links = []
            for sn in snames[:3]:
                links.append(f'<span class="status-badge" style="background:#f1f5f9; color:#475569; border:1px solid #cbd5e1; cursor:default;">{_escape_html(str(sn))}</span>')
            suggested_html = f'<div class="fn-info-row"><b>Suggested Names:</b> {" ".join(links)}</div>'

        decomp_html += f'''
        <div class="fn-card" id="fn_{ea:X}" data-name="{f["name"].lower()}" data-tag="{risk}">
            <h4 class="fn-card-title">{_escape_html(f["name"])} @ 0x{ea:X}</h4>
            <div style="margin-bottom:12px;">{_risk_badge(risk)} <span class="muted" style="margin-left:8px;">Conf: {f["confidence"]}% | Depth: {f["depth"]}</span></div>
            {suggested_html}
            <div class="fn-info-row"><b>Purpose:</b> {_escape_html(f.get("one_liner") or "—")}</div>
            <div class="fn-info-row"><b>Summary:</b> {_escape_html(f.get("summary") or "—")}</div>
            <div class="fn-info-row"><b>Contextual Purpose:</b> {_escape_html(f.get("contextual_purpose") or "—")}</div>
            <div class="fn-info-row"><b>Return Value:</b> {_escape_html(f.get("return_value") or "—")}</div>
            <div class="fn-info-row"><b>Risk Logic:</b> {_escape_html(f.get("risk_logic") or "—")}</div>
            {f'<div class="fn-info-row" style="margin-top:10px;"><b>Details:</b><ul style="margin:5px 0 0 20px;">{bullets}</ul></div>' if bullets else ''}
            <details class="code-section" style="margin-top:12px;">
                <summary class="code-section-header">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    <span>Original Decompiled (Hex-Rays)</span>
                </summary>
                <div class="code-section-body">
                    <pre><code class="language-c">{_escape_html(f.get("raw_code", ""))}</code></pre>
                </div>
            </details>
            <details class="code-section" style="margin-top:6px;">
                <summary class="code-section-header">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    <span>Readable Code (AI Generated)</span>
                </summary>
                <div class="code-section-body">
                    <pre><code class="language-c">{_escape_html(f.get("code", ""))}</code></pre>
                </div>
            </details>
        </div>'''

    # --- 12. Risk Assessment
    risk_json = _parse_ai_json("risk_assessment")
    if risk_json and isinstance(risk_json, dict) and "risk_score" in risk_json:
        rs = risk_json.get("risk_score", "0")
        summ = risk_json.get("summary", "")
        recs = "".join([f'<li>{_escape_html(r)}</li>' for r in risk_json.get("recommendations", [])])
        
        risk_assessment_html = f'''
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; padding:20px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px;">
            <div style="flex:1;">
                <h3 style="margin:0 0 10px 0; color:#1e293b;">Final Synthesis</h3>
                <div style="color:#475569; font-size:14px; line-height:1.6;">{_escape_html(summ)}</div>
            </div>
            <div style="margin-left:20px; text-align:center;">
                <div style="font-size:36px; font-weight:900; color:{risk_color};">{_escape_html(rs)}<span style="font-size:20px; color:#cbd5e1;">/100</span></div>
                <div style="font-size:12px; font-weight:bold; color:#64748b; text-transform:uppercase; margin-top:4px;">Risk Score</div>
            </div>
        </div>
        <div class="ai-block" style="border-left-color:#10b981; margin-top:15px;">
            <h4 style="margin-top:0; color:#1e293b;">Security Recommendations</h4>
            <ul style="margin-bottom:0; padding-left:20px; color:#334155;">{recs}</ul>
        </div>
        '''
    else:
        overall_risk_assessment = sections.get("risk_assessment")
        if not overall_risk_assessment:
            overall_risk_assessment = f"""Based on aggregated static reverse engineering context, the binary exhibits an overall risk of **{overall_risk}**.
    The analysis reviewed {len(functions_data)} custom functions, uncovering {mal_count} explicitly malicious routines and {sus_count} suspicious blocks.
    *Ensure to cross-reference identified IOC signatures with dynamic executions.*"""
        risk_assessment_html = f'<div class="ai-block" style="border-color:{risk_color};">{_escape_html(overall_risk_assessment)}</div>'

    # Master HTML Assembly
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Malware Analysis Report: 0x{entry_ea:X}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
:root {{ --bg: #f8fafc; --text: #0f172a; --card: #ffffff; --accent: #4f46e5; --border: #e2e8f0; --muted: #64748b; }}
html {{ scroll-behavior: smooth; }}
body {{ font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; font-size: 14px; padding-bottom:100px; }}
.header {{ background: linear-gradient(135deg, #1e293b, #0f172a); color: white; padding: 20px 40px; position: sticky; top: 0; z-index: 1000; box-shadow: 0 4px 15px rgba(0,0,0,0.1); display: flex; align-items:center; justify-content: space-between; }}
.header h1 {{ font-size: 20px; font-weight: 700; margin-bottom:4px; }}
.content {{ max-width: 1250px; margin: 30px auto; padding: 0 20px; }}
.section {{ background: var(--card); border-radius: 12px; padding: 30px; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.03); border: 1px solid var(--border); }}
.section-title {{ font-size: 20px; font-weight: 700; color: #1e293b; border-bottom: 2px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 20px; }}
.ai-block {{ white-space: pre-wrap; color: #334155; line-height: 1.7; background:#fbfcfe; padding: 20px; border-left: 4px solid var(--accent); border-radius: 4px 8px 8px 4px; }}
.ai-block.code-like {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; background:#0f172a; color:#e2e8f0; border-left-color:#60a5fa; }}
.data-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
.data-table th {{ position: sticky; top: 80px; text-align: left; padding: 12px 15px; background: #f1f5f9; color: #475569; font-weight: 600; }}
.data-table td {{ padding: 12px 15px; border-bottom: 1px solid #e2e8f0; vertical-align:top; }}
.data-table tr:hover {{ background-color: #f8fafc; }}
.sev-badge {{ padding:3px 10px; border-radius:12px; color:white; font-size:10px; font-weight:bold; }}
.muted {{ color: var(--muted); }}
.chain-box {{ padding:10px 15px; background:#f9fafb; border-left:4px solid; margin-bottom:8px; border-radius:4px; }}
pre {{ background:#1e1e1e; color:#d4d4d4; padding:15px; border-radius:8px; overflow-x:auto; font-size:12px; font-family:'Fira Code', 'JetBrains Mono', 'Cascadia Code', 'Courier New', monospace; }}
.str-details {{ background:#f1f5f9; margin-bottom:8px; border-radius:8px; overflow:hidden; }}
.str-details summary {{ padding:12px 15px; font-weight:600; cursor:pointer; background:#e2e8f0; }}
.str-content {{ padding:15px; max-height:300px; overflow-y:auto; font-family:'Fira Code', 'JetBrains Mono', monospace; font-size:12px; }}
.fn-card {{ background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:20px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }}
.fn-card-title {{ font-family:'Fira Code', 'Cascadia Code', 'JetBrains Mono', monospace; font-size:16px; font-weight:600; color:#1e293b; margin-bottom:8px; border-bottom: 1px dotted #cbd5e1; padding-bottom:5px; }}
.fn-info-row {{ margin-top:8px; color:#334155; line-height:1.5; font-size:14px; }}
.fn-info-row b {{ color:#1e293b; font-weight:600; margin-right:5px; }}
.code-details {{ margin-top: 15px; background: #f8fafc; border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
.code-details summary {{ padding: 10px 15px; cursor:pointer; font-weight:600; background:#f1f5f9; border-bottom:1px solid var(--border); }}
.code-details pre {{ margin:0; border-radius:0; max-height:800px; overflow:auto; }}
#mermaid-container {{ position: relative; border: 1px solid var(--border); background: #fdfdfd; border-radius: 8px; overflow: hidden; height:600px; }}
#zoom-controls {{ position: absolute; top: 15px; right: 15px; z-index: 1000; display:flex; gap:8px; background:rgba(255,255,255,0.9); padding:5px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1); }}
#zoom-controls button {{ background:white; border:1px solid #cbd5e1; padding:6px 12px; border-radius:5px; cursor:pointer; font-weight:600; font-size:12px; transition:0.2s; }}
#zoom-controls button:hover {{ background:#f1f5f9; }}
#mermaid-diagram {{ width: 100%; height: 100%; transform-origin: top left; transition: transform 0.2s ease; cursor: grab; }}
#mermaid-diagram:active {{ cursor: grabbing; }}
.mermaid .node {{ cursor: pointer !important; }}
.filter-input {{ width:100%; padding:12px 15px; font-size:14px; border:1px solid #cbd5e1; border-radius:8px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }}
.ai-block.code-like {{ font-family: 'Fira Code', 'JetBrains Mono', monospace; font-size: 13px; background:#0f172a; color:#e2e8f0; border-left-color:#60a5fa; }}
/* Collapsible Code Sections (native details/summary) */
.code-section {{ margin-top: 0; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
.code-section-header {{ display: flex; align-items: center; gap: 8px; background: #f8fafc; padding: 7px 14px; cursor: pointer; font-weight: 700; font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.4px; user-select: none; list-style: none; transition: background 0.15s; }}
.code-section-header::-webkit-details-marker {{ display: none; }}
.code-section-header::marker {{ display: none; content: ''; }}
.code-section-header:hover {{ background: #f1f5f9; color: var(--accent); }}
.code-section-header svg {{ transition: transform 0.25s ease; flex-shrink: 0; }}
details.code-section[open] > .code-section-header svg {{ transform: rotate(0deg); }}
details.code-section:not([open]) > .code-section-header svg {{ transform: rotate(-90deg); }}
.code-section-body pre {{ margin: 0; border-radius: 0; max-height: 600px; border: none; }}
@keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>PseudoNote (Deep Analyzer): Static Code Analysis Report</h1>
    <span style="font-size:12px; opacity:0.8; font-family:'JetBrains Mono',monospace;">Target Entry: 0x{entry_ea:X}</span>
  </div>
  <div style="background:{risk_color}; color:white; padding:8px 25px; border-radius:25px; font-weight:800; font-size:16px;">
    {overall_risk}
  </div>
</div>

<div class="content">

  <!-- Executive summary -->
  <div class="section" id="sec-1">
    <h2 class="section-title">Executive summary</h2>
    {exec_summary_html}
  </div>

  <!-- Technical Code analysis overview -->
  <div class="section" id="sec-2">
    <h2 class="section-title">Technical Code analysis overview</h2>
    {tech_overview_html}
  </div>

  <!-- Execution Flow Overview -->
  <div class="section" id="sec-3">
    <h2 class="section-title">Execution Flow Overview</h2>
    {execution_flow_html}
  </div>

  <!-- Capability or Malware Features (Aggregated) -->
  <div class="section" id="sec-4">
    <h2 class="section-title">Capability or Malware Features</h2>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#1e293b' if cap_rows else '#94a3b8'}; border-left:4px solid {'#1e293b' if cap_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">1. General Identified Capabilities</h3>
        {capabilities_html}
    </div>
    
    <div style="margin-bottom:30px;">
        <h3 style="color:{'#dc2626' if c2_rows else '#94a3b8'}; border-left:4px solid {'#dc2626' if c2_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">2. C2 / Backdoor / RAT Analysis</h3>
        {c2_analysis_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#f97316' if pers_rows else '#94a3b8'}; border-left:4px solid {'#f97316' if pers_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">3. Persistence Mechanisms</h3>
        {persistence_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#8b5cf6' if recon_rows else '#94a3b8'}; border-left:4px solid {'#8b5cf6' if recon_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">4. Reconnaissance or Info Stealer</h3>
        {recon_infostealer_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#1e293b' if inter_rows else '#94a3b8'}; border-left:4px solid {'#64748b' if inter_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">5. File / Registry / Process Interaction</h3>
        {interaction_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#1e293b' if res_rows else '#94a3b8'}; border-left:4px solid {'#64748b' if res_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">6. API Hashing / Resolving / PEB Walk</h3>
        {api_resolving_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#1e293b' if anti_rows else '#94a3b8'}; border-left:4px solid {'#64748b' if anti_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">7. Packer/Obfuscation or Anti-Analysis</h3>
        {anti_analysis_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:{'#1e293b' if cry_rows else '#94a3b8'}; border-left:4px solid {'#64748b' if cry_rows else '#cbd5e1'}; padding-left:10px; margin-bottom:15px;">8. Cryptographic Artifacts</h3>
        {crypto_artifacts_html}
    </div>
  </div>

  <!-- Suspicious Imports -->
  <div class="section" id="sec-8">
    <h2 class="section-title">Suspicious Imports</h2>
    {suspicious_imports_html}
  </div>

  <!-- TTP Mapping (MITRE ATTACK) -->
  <div class="section" id="sec-9">
    <h2 class="section-title">TTP Mapping (MITRE ATTACK)</h2>
    {ttp_html}
  </div>

  <!-- Indicator of Compromise -->
  <div class="section" id="sec-10">
    <h2 class="section-title">Indicator of Compromise</h2>
    {ioc_html}
  </div>

  <!-- Strings analysis -->
  <div class="section" id="sec-11">
    <h2 class="section-title">Strings analysis</h2>
    {strings_html}
  </div>

  <!-- Function Analysis -->
  <div class="section" id="sec-12">
    <h2 class="section-title">Function Analysis</h2>
    
    <h3 style="margin:20px 0 10px; color:#1e293b;">Call chain analysis</h3>
    {chain_html if chain_html else '<p class="muted">No execution chain mapping established.</p>'}
    
    <h3 style="margin:30px 0 10px; color:#1e293b;">Call Graph (Tree View)</h3>
    {tree_view_html}

    <h3 style="margin:30px 0 10px; color:#1e293b;">Mermaid Visual Call Flow - HTML</h3>
    {mermaid_html}

    <h3 style="margin:40px 0 10px; color:#1e293b; border-top:1px solid #e2e8f0; padding-top:20px;">Malicious functions</h3>
    {mal_tbl}

    <h3 style="margin:40px 0 10px; color:#1e293b; border-top:1px solid #e2e8f0; padding-top:20px;">Suspicious functions</h3>
    {sus_tbl}

    <h3 style="margin:40px 0 10px; color:#1e293b; border-top:1px solid #e2e8f0; padding-top:20px;">Benign functions</h3>
    {benign_tbl}

    <h3 style="margin:40px 0 10px; color:#1e293b; border-top:1px solid #e2e8f0; padding-top:20px;">Function Decomposition</h3>
    <input type="text" id="fnSearch" class="filter-input" placeholder="Search function name or risk tag (e.g., malicious)..." onkeyup="filterFunctions()">
    <div id="func-grid">
        {decomp_html}
    </div>
  </div>

  <!-- Risk Assessment -->
  <div class="section" id="sec-13">
    <h2 class="section-title">Risk Assessment</h2>
    {risk_assessment_html}
  </div>

</div>

<script>
    mermaid.initialize({{ startOnLoad: true, theme: 'default', securityLevel: 'loose' }});
    document.addEventListener('DOMContentLoaded', () => {{
        document.querySelectorAll('pre code.language-c').forEach((el) => {{ hljs.highlightElement(el); }});
    }});

    // Function Search Filter
    function filterFunctions() {{
        var q = document.getElementById('fnSearch').value.toLowerCase();
        var cards = document.querySelectorAll('.fn-card');
        cards.forEach(c => {{
            var txt = c.innerText.toLowerCase() + " " + c.getAttribute('data-tag');
            c.style.display = txt.includes(q) ? '' : 'none';
        }});
    }}

    // Mermaid Pan/Zoom Logic
    let currentScale = 1;
    let isDragging = false;
    let startX, startY, translateX = 0, translateY = 0;
    
    const container = document.getElementById('mermaid-container');
    const diagram = document.getElementById('mermaid-diagram');
    
    if (diagram) {{
        function applyTransform() {{
            diagram.style.transform = `translate(${{translateX}}px, ${{translateY}}px) scale(${{currentScale}})`;
        }}

        window.zoomMermaid = function(factor) {{
            currentScale *= factor;
            applyTransform();
        }};
        
        window.resetMermaidZoom = function() {{
            currentScale = 1;
            translateX = 0;
            translateY = 0;
            applyTransform();
        }};

        diagram.addEventListener('mousedown', (e) => {{
            isDragging = true;
            startX = e.clientX - translateX;
            startY = e.clientY - translateY;
        }});
        
        window.addEventListener('mouseup', () => isDragging = false);
        window.addEventListener('mousemove', (e) => {{
            if (!isDragging) return;
            e.preventDefault();
            translateX = e.clientX - startX;
            translateY = e.clientY - startY;
            applyTransform();
        }});
    }}

    window.copyMermaidCode = function(e) {{
        e.stopPropagation();
        const code = document.getElementById('raw-mermaid-code').innerText;
        navigator.clipboard.writeText(code).then(() => {{
            const btn = e.target;
            const originalText = btn.innerText;
            btn.innerText = 'Copied!';
            btn.style.background = '#16a34a';
            setTimeout(() => {{
                btn.innerText = originalText;
                btn.style.background = '#4f46e5';
            }}, 2000);
        }});
    }}

</script>
</body>
</html>'''

    html_path = os.path.join(output_dir, "report.html")
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        _log(f"Final interactive HTML report written to: {html_path}", "ok")
        return html_path
    except Exception as e:
        _log(f"Critical: Failed to write HTML report: {e}", "err")
        return None


# ===========================================================================
# STUBBED LEGACY MARKDOWN & PDF EXPORTS 
# (Kept purely for deep_analyzer.py compatibility)
# ===========================================================================

def write_markdown_header(output_dir, name, entry_ea, total_count=0, ts=""):
    return f"# Malware Analysis Report: {name} (0x{entry_ea:X})\n**Date:** {ts}\n**Total Functions:** {total_count}\n\n"

def append_function_to_markdown(*args, **kwargs): pass

def finalize_markdown(output_dir, graph, summary_msg, entry_ea):
    # Backward compatibility stub
    pass

def build_function_markdown_piece(ea, node, res_data, graph, code=None):
    """Fallback markdown builder for intermediate worker updates."""
    risk = (res_data.get("risk_tag") or "benign").upper()
    summ = res_data.get("one_liner") or res_data.get("summary") or "No detail available."
    return f"### {node.name} (0x{ea:X}) [{risk}]\n**Summary:** {summ}\n\n"

def assemble_malware_source(graph, entry_ea, output_dir):
    """Concatenate all custom function code into a single forensic library."""
    all_code = []
    for node in sorted(graph.values(), key=lambda x: x.depth):
        if node.is_library: continue
        rd = load_readable_from_disk(node.ea, node.name, output_dir)
        if not rd: rd = load_decompiled_from_disk(node.ea, node.name, output_dir)
        if rd:
            all_code.append(f"// --- Function: {node.name} (0x{node.ea:X}) ---\n{rd}\n")
    return "\n".join(all_code) if all_code else "// No source code available."


# ===========================================================================
# AI REPORT GENERATION HELPERS
# ===========================================================================

def _validated_ai_request(cfg, prompt, sys_prompt=None, **kwargs):
    from pseudonote.renamer import ai_request
    required = ['api_url', 'api_key', 'model']
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        err = f"AI config missing required fields: {missing}."
        if kwargs.get('logger'): kwargs['logger'](err, 'err')
        raise ValueError(err)
    if sys_prompt is None:
        sys_prompt = "You are a senior reverse engineer and malware analyst. Provide technical assessments of binary code. Return format as clean technical text. Do NOT use markdown codeblock wrappers for standard text output."
    return ai_request(cfg, prompt, sys_prompt, **kwargs)

def generate_program_overview(digest, entry_name, entry_children_count, ai_cfg, log_fn):
    prompt = f"""Target: {entry_name}
Sub-calls: {entry_children_count}
Context: {digest}

Analyze execution flow and provide a high-level technical code analysis overview of what the program is doing.
Focus on operational logic, data flow, structure, and stage-by-stage choreography.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "operational_logic": "Brief high-level overview of the program's logic.",
  "data_flow": "Brief overview of data movement.",
  "choreography": "Brief overview of execution flow."
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_technical_overview(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}

You are a senior malware reverse engineer writing a Technical Code Analysis Overview section for a professional malware analysis report. Your goal is to provide a deep-dive technical narrative that explains the inner workings of the binary with forensic precision.

STRICT RULES:
- Do NOT write generic or high-level descriptions.
- Produce a cohesive technical narrative. Cross-reference sections where logical (e.g., how architecture supports evasion).
- Base everything ONLY on analyzed functions and confirmed behaviors.
- Ensure the explanation naturally covers:
  - The technique being implemented.
  - Its technical purpose.
  - How it is implemented (specific APIs, structures, transformations).
  - The exact function(s) or memory region(s) where it resides.
  - Its position within the execution lifecycle.

OUTPUT STRUCTURE:
1. Program Architecture: Describe the overall design (modular, dispatcher-based, etc.). Explain the entry point logic.
2. Initialization & Execution Chain: Detail the startup sequence and key transition functions.
3. Payload Handling & Data transformation: Forensic analysis of decryption, unpacking, or memory mapping.
4. Control Flow & Dispatcher Logic: Implementation of command dispatchers and handler routing.
5. System Interaction Layer: Detailed analysis of File, Registry, Network, and Process manipulation.
6. Evasion & Obfuscation: API hashing, anti-analysis, and code shielding techniques.

WRITING STYLE:
- Technical, Dense, and Authoritative. No filler.
- Answer WHY and HOW for every behavior.

Respond STRICTLY with a valid JSON object:
{{
  "detailed_technical_overview": "Comprehensive 6-zone forensic narrative."
}}"""
    sys_p = "You are a senior malware reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096)

def generate_malware_analysis_assessment(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}

You are a senior malware reverse engineer and head of forensic reporting, writing a professional Executive Summary section for a high-stakes malware analysis report.

STRICT REQUIREMENTS:
- Base every statement ONLY on analyzed functions and confirmed observed behavior.
- Do NOT repeat the same capability multiple times.
- For EVERY major observation, you MUST answer the following questions within the narrative:
  1. WHAT: What is the specific behavior or capability?
  2. WHY: What is the technical objective or intent behind this behavior?
  3. HOW: How is the behavior implemented (Registry keys, specific APIs, logic flows)?
  4. WHERE: Identify specific function names (e.g., fn_function) or memory locations where the logic resides.
  5. WHEN: Where in the execution chain (initialization, payload deployment, C2 phase) does this occur?

Respond STRICTLY with a valid JSON object matching this structure:
{{
  "detailed_narrative": "The full 4-paragraph technical executive summary text providing deep malware analysis and code reverse engineering context."
}}"""
    sys_p = "You are a senior malware reverse engineer and head of forensic reporting. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096)

def generate_key_capabilities(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Identify key technical capabilities matching malware features. For each capability, list which specific function(s) from the context perform or contribute to it.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "capabilities": [
    {{
      "name": "Capability Name (e.g. Network C2)", 
      "description": "Brief technical description",
      "associated_functions": ["func_name1", "func_name2"]
    }},
    {{"name": "...", "description": "...", "associated_functions": []}}
  ]
}}
Ensure you list 5-8 capabilities. Use function names provided in 'Context'."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_suspicious_functions(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Identify functions performing highly suspicious operations.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "functions": [
    {{"address": "0x123456", "name": "func_name", "reasoning": "why it's suspicious"}}
  ]
}}
IMPORTANT: Replace 0x123456 with the actual hex address from the Context."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_malicious_functions(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Identify definitive malicious functions and patterns.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "functions": [
    {{"address": "0x123456", "name": "func_name", "reasoning": "pattern description"}}
  ]
}}
IMPORTANT: Replace 0x123456 with the actual hex address from the Context."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_behavioral_indicators(digest, ai_cfg, log_fn, all_strings=None):
    if not all_strings:
        all_strings = []
        
    chunk_size = 150
    aggregated_iocs = []
    
    if len(all_strings) == 0:
        chunks = [[]]
    else:
        chunks = [all_strings[i:i + chunk_size] for i in range(0, len(all_strings), chunk_size)]
        
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    for idx, chunk in enumerate(chunks):
        if len(chunks) > 1:
            log_fn(f"Processing chunk {idx+1}/{len(chunks)} of strings for IOC extraction...", "info")
            batch_ctx = "\n".join(chunk)
            prompt = f"""Context: {digest}
Additional Strings Batch ({idx+1}/{len(chunks)}):
{batch_ctx}

TASK:
1. Examine all Strategic Strings and API Behaviors in the Context and the Additional Strings Batch.
2. Extract REAL, EXACT literal strings as indicators (C2 domains, IP addresses, specific malware file paths, registry keys for persistence, exact mutexes).
3. DO NOT abstract values, DO NOT use placeholders like [random_folder], and DO NOT write descriptive behavior as an indicator. The "value" must be a true literal string that was found in the context.
4. IGNORE junk strings, compiler artifacts, or generic library paths (e.g., C:\\Windows\\System32).
5. For each IOC, explain its forensic significance.

Respond STRICTLY with a valid JSON object matching this structure:
{{
  "iocs": [
    {{
      "type": "File Path|Registry Key|Network Domain|IP|Mutex|User-Agent", 
      "value": "EXACT LITERAL STRING ONLY", 
      "context": "Forensic significance / why it's an IOC",
      "associated_functions": ["func_name1"]
    }}
  ]
}}"""
        else:
            prompt = f"""Context: {digest}
Provide Indicators of Compromise (IOCs). 

TASK:
1. Examine all Strategic Strings and API Behaviors in the Context.
2. Extract REAL, EXACT literal strings as indicators (C2 domains, IP addresses, specific malware file paths, registry keys for persistence, exact mutexes).
3. DO NOT abstract values, DO NOT use placeholders like [random_folder], and DO NOT write descriptive behavior as an indicator. The "value" must be a true literal string that was found in the context.
4. IGNORE junk strings, compiler artifacts, or generic library paths (e.g., C:\\Windows\\System32).
5. For each IOC, explain its forensic significance.

Respond STRICTLY with a valid JSON object matching this structure:
{{
  "iocs": [
    {{
      "type": "File Path|Registry Key|Network Domain|IP|Mutex|User-Agent", 
      "value": "EXACT LITERAL STRING ONLY", 
      "context": "Forensic significance / why it's an IOC",
      "associated_functions": ["func_name1"]
    }}
  ]
}}"""

        res = _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)
        if isinstance(res, dict) and "iocs" in res and isinstance(res["iocs"], list):
            aggregated_iocs.extend(res["iocs"])
            
    return {"iocs": aggregated_iocs}

def generate_ranked_strings(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Review the Extracted Strings in the context. Rank them by forensic importance.

Rank categories: High (C2, persistence, exploit artifacts), Medium (Configuration, specific internal logic), Low (UI strings, logging).

Respond STRICTLY with a valid JSON object:
{{
  "ranked_strings": [
    {{"value": "the string", "importance": "High|Medium|Low"}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_risk_assessment(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Provide a definitive overall Risk Assessment based on all aggregated static analysis data.
Synthesize findings from all segments, provide an overall risk score, and conclude with security recommendations.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "risk_score": 85,
  "summary": "1-2 paragraphs of synthesis",
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_execution_flow_overview(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}

Analyze the program's complete execution lifecycle from start to finish. 
Trace the operational flow by synthesizing the 'Primary Execution Dispatch' (entry logic) and the 'Deep Forensic Findings' (sub-routine capabilities).

Your goal is to identify a logical chronological sequence of stages (e.g., Initialization -> Environment Discovery -> Persistence/Infection -> Core Malicious Logic -> Network/C2 Communication -> Cleanup/Termination).

STRICT FORENSIC RULES:
1. Identify at least 3 distinct logical phases unless the program is extremely trivial.
2. Synthesize the description by explaining HOW routines relate to each other (e.g., "The initialization routine sets up X, which is later used by Y for Z").
3. Standard compiler/CRT stubs (__chkstk, mainCRTStartup, etc.) are BENIGN boilerplate. NEVER report them as malicious stages.
4. Use the provided context to build a technical narrative of the program's lifecycle.

Respond STRICTLY with a valid JSON object matching this structure:
{{
  "steps": [
    {{"phase": "Phase Name (e.g., Initialization)", "description": "Deep technical narrative of what occurs during this phase based on the context."}},
    {{"phase": "Phase Name", "description": "..."}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_crypto_artifacts(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Identify cryptographic operations.
Look for: XOR loops with constant keys, bitwise substitution, S-box implementations, or WinAPI calls to BCrypt/CryptProtect/CryptEncrypt.

ANTI-HALLUCINATION RULES:
1. DO NOT list things you did NOT find. If no crypto is present, return an empty artifacts list.
2. Do NOT interpret bitwise XOR as "Encryption" unless you see a clear key-schedule or algorithm pattern.
3. Standard pointer encoding (_encode_pointer, _decode_pointer) is NOT cryptography.

Respond STRICTLY with a valid JSON object:
{{
  "artifacts": [
    {{"algorithm": "Algorithm Name", "usage": "Reasoning for classification", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_anti_analysis_logic(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Identify Anti-VM, Anti-Debug, or Evasion techniques.
Check for: Timing checks (RDTSC), process enumeration (Toolhelp32), debugger detection (IsDebuggerPresent, CheckRemoteDebuggerPresent), or specific VM-related strings/files.

ANTI-HALLUCINATION RULES:
1. BOILERPLATE IGNORE LIST: The following are BENIGN and MUST NOT be reported: 
   - _set_invalid_parameter_handler, _invalid_parameter
   - __mingw_invalidParameterHandler
   - _pei386_runtime_relocator
   - IsProcessorFeaturePresent
   - mainCRTStartup
2. If only the above functions are present, return an empty techniques list.
3. DO NOT interpret generic error handling as "Anti-Sandbox".

Respond STRICTLY with a valid JSON object:
{{
  "techniques": [
    {{"name": "...", "description": "Technical reasoning", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_c2_analysis(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}

Analyze technical evidence of Command & Control (C2), Backdoor communication, or RAT (Remote Access Trojan) capabilities.
FORENSIC FOCUS:
- Socket/Network APIs: WSAStartup, socket, connect, send, recv, HttpOpenRequest, WinHttpOpen.
- Shell/Command Channels: Creating pipes for cmd.exe, reverse shells, remote command execution.
- Command Handler: Identify command menus or handlers (e.g., switch/case or if/else chain dispatching specific commands like download, execute, terminate, etc.).
- Active Remote Control: Look for RAT-specific features like screen capture (GDI/BitBlt), keylogging (GetAsyncKeyState/SetWindowsHookEx), or direct remote execution logic.
- Network Artifacts: Hardcoded IPs, domains, or User-Agents.

STRICT FORENSIC RULES:
1. If the context shows 'opening shell connections' or 'creating pipes for command execution', this IS a Backdoor/C2 mechanism.
2. If the malware parses incoming data to dispatch commands (e.g., '1' for shell, '2' for upload), this is a C2 command menu.
3. If it has screenshot or keylogging logic combined with network send() calls, categorize it as active RAT capability within C2.
4. Cite specific functions from the 'DEEP FORENSIC FINDINGS' or 'CATEGORIZED WINAPI BEHAVIORS' as evidence.

Respond STRICTLY with a valid JSON object:
{{
  "summary": "Technical synthesis of identified C2, Backdoor, or RAT logic, including any identified command menus.",
  "mechanisms": [
     {{
       "feature": "Mechanism Type (e.g., Reverse Shell, Command Menu Handler, RAT/Remote Control)", 
       "evidence": "Specific technical proof from the context (APIs used, strings found, command list if found)", 
       "associated_functions": ["Name of functions responsible"]
     }}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_call_flow_mermaid(graph, entry_ea, analyzed_results, log_fn=None):
    # Existing generation logic
    analyzed_eas = set(ea for ea, res in analyzed_results.items() if res)
    def _mml(text): return re.sub(r'[^A-Za-z0-9_]', '_', str(text))
    def _mml_label(text): return str(text).replace('"', "'")

    risk_colors = {
        "malicious":  "fill:#fee2e2,stroke:#ef4444,color:#7f1d1d",
        "suspicious": "fill:#fef3c7,stroke:#f59e0b,color:#92400e",
        "benign":     "fill:#dcfce7,stroke:#22c55e,color:#14532d",
        "pending":    "fill:#f1f5f9,stroke:#94a3b8,color:#334155",
        "unknown":    "fill:#f8fafc,stroke:#e2e8f0,color:#64748b",
    }
    
    lines = ["flowchart TD"]
    classdefs = []
    seen_classdefs = set()
    edges = set()
    nodes_declared = set()
    click_commands = []

    def _declare_node(ea, node, risk, summary=None):
        safe_id = f"fn_{ea:X}"
        if safe_id in nodes_declared: return safe_id
        nodes_declared.add(safe_id)
        
        name_label = _mml_label(node.name)
        if summary:
            # Show full summary if it exists (removed truncation to prevent '...' in labels)
            label = f"<b>{name_label}</b><br/>{_mml_label(summary)}"
        else: label = name_label
            
        lines.append(f'    {safe_id}(["{label}"])')
        cls = f"cls_{risk}"
        if cls not in seen_classdefs:
            seen_classdefs.add(cls)
            classdefs.append(f"    classDef {cls} {risk_colors.get(risk, risk_colors['unknown'])}")
        lines.append(f"    class {safe_id} {cls}")
        
        # Add interactive click command to jump to decompose section
        click_commands.append(f'    click {safe_id} "#fn_{ea:X}" "Click to view full analysis of {name_label}"')
        return safe_id

    for ea, node in graph.items():
        if node.is_library: continue
        res = analyzed_results.get(ea, {})
        result_risk = (res.get("risk_tag") or "").lower().strip()
        node_risk = (getattr(node, "risk_tag", "") or "").lower().strip()
        risk = result_risk if result_risk and result_risk not in ("pending", "unknown", "") else node_risk or "pending"
        
        src_id = _declare_node(ea, node, risk, summary=res.get("one_liner", ""))
        
        for callee_ea in node.callees:
            callee = graph.get(callee_ea)
            if not callee or callee.is_library: continue
            c_res = analyzed_results.get(callee_ea, {})
            c_risk = (c_res.get("risk_tag") or "unknown").lower()
            dst_id = _declare_node(callee_ea, callee, c_risk, summary=c_res.get("one_liner", ""))
            
            edge = (src_id, dst_id)
            if edge not in edges:
                edges.add(edge)
                lines.append(f"    {src_id} --> {dst_id}")

    lines.extend(classdefs)
    return "\n".join(lines) if nodes_declared else None

def build_analysis_digest(graph, entry_ea, analysis_cache=None, interest_calc_fn=None, log_fn=None):
    PLACEHOLDER_SUMMARIES = {"batch parsed function.", "trivial or wrapper function.", "", "(no summary available)"}
    MIN_CONFIDENCE = 40

    all_nodes = sorted([n for n in graph.values() if not n.is_library], key=lambda x: (x.depth, x.name))
    
    # 1. Aggregate categorized APIs (not just high-sev)
    categorized_apis = collections.defaultdict(set)
    for node in graph.values():
        if node.is_library: continue
        hits = get_api_tags_for_function(node.ea, getattr(node, 'callees', []))
        for cat, apis in hits.items():
            for api in apis:
                # Add function context to the API hit for better AI attribution
                categorized_apis[cat].add(f"{api} (in {node.name})")
    
    api_digest = []
    for cat, apis in sorted(categorized_apis.items()):
        api_list = sorted(list(apis))
        api_digest.append(f"[{cat}]: {', '.join(api_list[:12])}{'...' if len(api_list) > 12 else ''}")
    
    api_summary_text = "\n".join(api_digest) if api_digest else "None explicitly categorized."

    # 2. Extract Strategic Strings
    s_data = extract_ida_strings(graph)
    str_digest = []
    
    # Priority sorting: Interesting categories first so they survive the [:60] limit for AI context
    def string_priority(s):
        cat = s.get('category', 'String')
        priority_map = {"URL": 0, "IP Address": 1, "Command": 2, "Registry Key": 3, "File Path": 4, "Mutex": 5, "String": 99}
        return priority_map.get(cat, 99)

    s_data_sorted = sorted(s_data, key=string_priority)

    for s in s_data_sorted:
        # Use Category (URL, IP, etc.) instead of Type (ASCII) for better AI context
        str_digest.append(f"[{s.get('category', 'String')}]: {s['value']} (refs: {', '.join(s['funcs'])})")
    
    str_summary_text = "\n".join(str_digest[:100]) if str_digest else "No strategic strings detected."
    if len(str_digest) > 100:
        str_summary_text += f"\n[... TRUNCATED. {len(str_digest)-100} MORE STRINGS PRESERVED FOR BATCH ANALYSIS ...]"

    entry_node = graph.get(entry_ea)
    entry_children_blocks = []
    entry_child_eas = set()

    if entry_node:
        children = [graph[c] for c in sorted(entry_node.callees) if c in graph and not graph[c].is_library]
        entry_child_eas = {ch.ea for ch in children}
        for ch in children:
            # Fallback to node attribute if cache is missing
            one_liner = (analysis_cache.get(ch.ea, "") if analysis_cache else "") or getattr(ch, "one_liner", "") or "(not yet analyzed)"
            entry_children_blocks.append(f"  [{ch.name}] depth={ch.depth} conf={ch.confidence}% [Risk: {getattr(ch, 'risk_tag', 'benign')}]\n    Purpose: {one_liner.strip()}\n")

    quality_nodes = []
    for node in all_nodes:
        if node.ea in entry_child_eas: continue
        if node.status not in ("analyzed", "preliminary", "contextual"): continue
        
        # Fallback to node attribute if cache is missing
        one_liner = (analysis_cache.get(node.ea, "") if analysis_cache else "") or getattr(node, "one_liner", "") or ""
        full_summary = getattr(node, "summary", "") or ""
        
        if (one_liner.lower() in PLACEHOLDER_SUMMARIES and not getattr(node, 'suspicious', [])) or node.confidence < MIN_CONFIDENCE: 
             continue
        
        quality_nodes.append({
            "node": node,
            "one_liner": one_liner,
            "summary": full_summary,
            "interest": interest_calc_fn(node) if interest_calc_fn else 0,
            "risk_tag": getattr(node, "risk_tag", "benign")
        })

    quality_nodes.sort(key=lambda x: (_RISK_ORDER.get(x["risk_tag"], 0), x["interest"]), reverse=True)
    digest_lines = ["DETAILED FINDINGS:"]
    for q in quality_nodes[:80]:
        n = q["node"]
        # Extract indicators from preliminary_analysis if available
        indicators = []
        if hasattr(n, 'preliminary_analysis') and isinstance(n.preliminary_analysis, dict):
            indicators = n.preliminary_analysis.get('suspicious', [])
        elif hasattr(n, 'suspicious') and isinstance(n.suspicious, list):
            indicators = n.suspicious
            
        ind_str = ", ".join(indicators[:5]) if indicators else "None"
        risk_label = q['risk_tag'].upper()
        # For high-risk functions, include the full summary for maximum context
        summary_to_show = q['summary'] if (risk_label in ("MALICIOUS", "SUSPICIOUS") and q['summary']) else q['one_liner']
        
        digest_lines.append(f"Function: {n.name} (0x{n.ea:X}) [Risk: {risk_label}]\n  Summary: {summary_to_show}\n  Indicators: {ind_str}")

    full_digest = f"""PRIMARY EXECUTION DISPATCH (Layer 1):
{' '.join(entry_children_blocks)}

DEEP FORENSIC FINDINGS (Sub-Routines):
{chr(10).join(digest_lines)}

CATEGORIZED WINAPI BEHAVIORS:
{api_summary_text}

STRATEGIC STRING ARTIFACTS:
{str_summary_text}"""

    return full_digest, len(entry_children_blocks), str_digest


def generate_persistence_mechanisms(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Analyze potential persistence mechanisms identified in the code.
Look for: Registry run keys (Run, RunOnce), Service creation (CreateService), Task scheduling (SchTasks), Startup folder manipulation, or DLL hijacking/side-loading logic.

Respond STRICTLY with a valid JSON object:
{{
  "summary": "Technical summary of how the malware ensures it survives reboots.",
  "mechanisms": [
    {{"method": "Method Name (e.g., Registry Run Key)", "details": "Detailed forensic explanation including keys or file paths used", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_file_registry_interaction(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Analyze how the program interacts with the File System, Registry, and Processes.
Focus on: Creating, deleting, accessing, or injecting into these entities.
Cite specific forensic details: e.g., which registry keys are created, which files are deleted, or target process names for injection (OpenProcess/CreateRemoteThread).

Respond STRICTLY with a valid JSON object:
{{
  "interactions": [
    {{"type": "File|Registry|Process", "action": "Create|Delete|Access|Inject", "target": "EXACT Path or Name", "description": "Forensic significance of this interaction", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_api_resolving_logic(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Analyze if the program uses advanced API resolving techniques like API Hashing, PEB Walking, or manual export table parsing (GetProcAddress/GetModuleHandle/LdrGetProcedureAddress).
Explain the implementation (e.g., CRC32 hashing, custom rotation, etc.).

Respond STRICTLY with a valid JSON object:
{{
  "techniques": [
    {{"name": "Technique Name (e.g., ROR13 API Hashing)", "description": "Technical description of the implementation", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)

def generate_recon_infostealer_analysis(digest, ai_cfg, log_fn):
    prompt = f"""Context: {digest}
Analyze Reconnaissance or Information Stealing capabilities (LOCAL Discovery).
Look for: Enumerating local files (.txt, .docx, wallets), stealing browser cookies/passwords, clipboard monitoring, or gathering environment info (ComputerName, UserName, OSVersion, Disk size, CPU info).

Identify what specific forensic data is being harvested from the host. Do NOT include active C2/Remote control logic here; focus on data theft/collection methods.

Respond STRICTLY with a valid JSON object:
{{
  "summary": "Detailed summary of what local information is being targeted or gathered.",
  "findings": [
    {{"category": "Category (e.g., Browser Data, File Enumeration, System Info)", "description": "Forensic details of what is stolen or captured and how", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn)
