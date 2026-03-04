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

def save_exec_flow_to_disk(ea, name, flow_text, output_dir):
    """Save high-level execution flow for a function to exec_flow/ subfolder."""
    path, _ = get_function_artifact_path(output_dir, "exec_flow", ea, name, "md")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if flow_text:
            flow_str = flow_text.strip()
            # Strip markdown block wrapper if present
            flow_str = re.sub(r'^```[\w]*\s*', '', flow_str)
            flow_str = re.sub(r'\s*```$', '', flow_str).strip()
        else:
            flow_str = "No execution flow generated."
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(flow_str)
        return path
    except Exception as e:
        print("[PseudoNote] Error saving execution flow file: %s" % e)
        return None

def load_exec_flow_from_disk(ea, name, output_dir):
    """Load high-level execution flow from exec_flow/ subfolder."""
    safe_name = sanitize_function_name(name)
    path = os.path.join(output_dir, "exec_flow", "%s_0x%X.md" % (safe_name, ea))
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except: pass
    hits = glob.glob(os.path.join(output_dir, "exec_flow", "*_0x%X.md" % ea))
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
        # Strict IPv4 — exactly 4 octets (0-255), not followed by another dot+digit (OID guard),
        # not preceded by a digit-dot (to avoid matching tail of longer dotted sequence),
        # and not a version string prefix like "v1." or "2.0.".
        # EXCLUDES: loopback (127.x), link-local (169.254.x), multicast (224-239.x),
        #           broadcast (255.x), unspecified (0.0.0.0), and private RFC1918 ranges
        #           ONLY when the full string is ONLY an IP (to avoid false negatives in URLs).
        _octet = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        ip_re = re.compile(
            r'(?<!\d\.)(?<!\d)'               # not preceded by digit or "digit."
            r'\b'
            r'(' + _octet + r'\.)' + r'{3}'   # exactly 3 "octet." groups
            r'(' + _octet + r')'              # final octet — no trailing dot
            r'\b'
            r'(?!\.\d)'                       # not followed by ".digit" (OID / version guard)
        )

        def is_valid_public_ip(ip_str):
            """Validate that an IP is a real, non-trivial internet address worth flagging."""
            try:
                parts = [int(p) for p in ip_str.split('.')]
                if len(parts) != 4: return False
                a, b = parts[0], parts[1]
                # Reject loopback
                if a == 127: return False
                # Reject unspecified
                if ip_str == '0.0.0.0': return False
                # Reject link-local
                if a == 169 and b == 254: return False
                # Reject multicast
                if 224 <= a <= 239: return False
                # Reject broadcast / reserved
                if a == 255: return False
                # Reject private RFC1918 — these are usually noise in static analysis
                if a == 10: return False
                if a == 172 and 16 <= b <= 31: return False
                if a == 192 and b == 168: return False
                # Reject trivial "all zeros" per octet (e.g. version-like 1.0.0.0)
                if parts[1] == 0 and parts[2] == 0 and parts[3] == 0: return False
                return True
            except Exception:
                return False

        mutex_re = re.compile(r'(?:\{[A-F0-9-]{32,}\})|(?:\b[A-Za-z0-9_]{8,}\bMutex)', re.I)
        exe_re = re.compile(r'\b[\w\-\.]+\.(?:exe|dll|sys|bat|vbs|ps1|com|scr|pif|vbe)\b', re.I)
        # Library/Framework/Common boilerplate strings
        library_re = re.compile(
            r'\b(?:runtime error|assertion failed|invalid argument|out of memory|permission denied|'
            r'no such file|not a directory|executable file format|math argument|math result|'
            r'Mingw-w64 runtime|image-section|Partial loss of significance|Total loss of significance|'
            r'UNDERFLOW|OVERFLOW|PLOSS|TLOSS|SIGN|Matherr|___report_error|'
            r'Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|'
            r'January|February|March|April|May|June|July|August|September|October|November|December|'
            r'MM/dd/yy|dddd, MMMM dd, yyyy|'
            r'AreFileApisANSI|LCMapStringEx|LocaleNameToLCID|AppPolicyGetProcessTerminationMethod)\b', re.I)
        # Patterns for encoded/obfuscated data (Not junk) - Require at least one non-alphanumeric base64 char to reduce false positives
        base64_re = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        hex_re = re.compile(r'^[0-9a-fA-F]{16,}$')
        camel_concat_re = re.compile(r'^([A-Z][a-z0-9]{1,}){3,}$') # e.g. NtDelayExecutionGetNamed

        # Comprehensive noise filter for C++ metadata, Windows boilerplate, and RTTI
        noise_re = re.compile(
            r'^[ `\'].*[\'\(]$|'  # MSVC backtick/quote metadata patterns (e.g. `vftable', `vcall')
            r'^\b(?:restrict\(|delete|operator|new\[\]|delete\[\]|mscoree\.dll|CONOUT\$|CONIN\$|'
            r'AreFileApisANSI|LCMapStringEx|LocaleNameToLCID|AppPolicyGetProcessTerminationMethod|'
            r'FlsAlloc|FlsFree|FlsGetValue|FlsSetValue|InitializeCriticalSectionEx|CorExitProcess|'
            r'GetCurrentProcess|MiniDumpWriteDump|LoadLibraryA|CloseHandle|GetProcAddress|LocalFree|'
            r'GetModuleHandleW|TerminateProcess|IsProcessorFeaturePresent|QueryPerformanceCounter|'
            r'GetCurrentProcessId|GetCurrentThreadId|GetSystemTimeAsFileTime|InitializeSListHead|'
            r'UnhandledExceptionFilter|SetUnhandledExceptionFilter|RtlCaptureContext|'
            r'RtlLookupFunctionEntry|RtlVirtualUnwind|__scrt_|__dcrt_|'
            r'Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|'
            r'January|February|March|April|May|June|July|August|September|October|November|December|'
            r'MM/dd/yy|dddd, MMMM dd, yyyy|'
            r'Type Descriptor|Base Class Descriptor|Base Class Array|Class Hierarchy Descriptor|Complete Object Locator'
            r')|'                 # Keywords and RTTI phrases
            r'^(?:api-ms-|ext-ms-|kernel32|user32|advapi32|ntdll|shell32|gdi32)', # System prefix
            re.I
        )

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
            
            # Explicit Noise Block: Return early if string is a known system/metadata artifact
            if noise_re.search(val_strip):
                return
            
            # Determine Category first to see if it's "Interesting" enough to bypass junk filter
            cat = "String"
            if url_re.search(val_strip): cat = "URL"
            elif file_re.search(val_strip): cat = "File Path"
            elif reg_re.search(val_strip): cat = "Registry Key"
            elif (m := ip_re.search(val_strip)) and is_valid_public_ip(m.group()): cat = "IP Address"
            elif mutex_re.search(val_strip): cat = "Mutex"
            elif cmd_re.search(val_strip): cat = "Command"
            elif library_re.search(val_strip): cat = "Library/Runtime String"
            elif exe_re.search(val_strip): cat = "Filename"
            elif val_strip.lower().startswith(('api-ms-win-', 'ext-ms-win-')) or val_strip.lower() in ["kernel32", "user32", "advapi32", "ntdll", "shell32", "gdi32"]:
                cat = "System Component"
            elif len(val_strip) >= 16 and (hex_re.match(val_strip) or (base64_re.match(val_strip) and (not val_strip.isalnum() or get_entropy(val_strip) > 4.5))):
                # Extra check: if it looks like CamelCase concatenation, it's probably not Base64
                if not camel_concat_re.match(val_strip):
                    cat = "Encoded Data"
            elif len(val_strip) >= 12 and get_entropy(val_strip) > 3.8 and ' ' not in val_strip:
                if not camel_concat_re.match(val_strip):
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
    
    # Pre-compile some secondary regex checks for robustness
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    # Common system patterns to filter out from IOCs
    system_patterns = re.compile(r'^(?:api-ms-win-|ext-ms-win-|kernel32|user32|advapi32|ntdll|shell32|gdi32|comctl32|comdlg32|msvcrt|vcruntime|mscoree|ucrtbase|AreFileApisANSI|LCMapStringEx|LocaleNameToLCID|AppPolicyGetProcessTerminationMethod)', re.I)
    system_dlls = {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
        "ws2_32.dll", "winmm.dll", "wtsapi32.dll", "iphlpapi.dll", "secur32.dll",
        "cryptdll.dll", "ntdll.dll", "msvcrt.dll", "wsock32.dll", "wininet.dll",
        "shell32.dll", "shlwapi.dll", "crypt32.dll", "rpcrt4.dll", "mpr.dll",
        "netapi32.dll", "normaliz.dll", "version.dll", "psapi.dll", "gdi32.dll", "WINHTTP.dll", "DNSAPI.dll", "urlmon.dll", "msimg32.dll", "msi.dll", "winhttp.dll", "comctl32.dll", "comdlg32.dll", "setupapi.dll", "imagehlp.dll", "dbghelp.dll"
    }
    
    for s_info in strings:
        val = str(s_info.get("value", "")).strip()
        cat = s_info.get("category", "String")
        if not val or val in seen: continue
        
        # Suppress obvious system strings
        if cat in ["System Component", "Library/Runtime String"] or system_patterns.match(val):
            continue
        
        ioc_type = None
        
        # 1. Trust the scanner's categorization if available
        if cat == "IP Address": ioc_type = "IP"
        elif cat == "URL": ioc_type = "Network Domain"
        elif cat == "Registry Key" and any(x in val.lower() for x in ["\\run", "currentversion", "software\\microsoft", "hklm", "hkcu"]): 
            ioc_type = "Registry Key"
        elif cat == "Mutex": ioc_type = "Mutex"
        elif cat == "Command" and any(x in val.lower() for x in ["cmd.exe", "powershell", "-enc", "-w hidden", "sc.exe", "net.exe"]):
            ioc_type = "Command Execution"
        elif cat == "Filename" and val.lower().endswith((".exe", ".dll", ".pif", ".scr", ".sys")):
            if val.lower() in system_dlls:
                continue
            ioc_type = "Filename"
        elif cat == "Encoded Data" and len(val) > 32:
            ioc_type = "Encoded Blob"
            
        # 2. Secondary Regex Fallback (in case category was lost or missed)
        if not ioc_type:
            if ipv4_pattern.match(val):
                ioc_type = "IP"
            elif val.lower().startswith(("http://", "https://", "ftp://")):
                ioc_type = "URL"
            elif val.lower().startswith(("hklm\\", "hkcu\\", "software\\")):
                ioc_type = "Registry Key"
            
        if ioc_type:
            iocs.append({
                "type": ioc_type,
                "value": val,
                "context": f"Deterministic Detection: Identified as {cat if cat != 'String' else ioc_type} in binary strings.",
                "associated_functions": s_info.get("funcs", [])
            })
            seen.add(val)
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
                # Define list-type keys that need [] as default to avoid iteration errors
                list_keys = ["bullets", "suspicious", "arguments", "variables", "suggested_names", "capabilities", "semantic_tags"]
                for k in list_keys:
                    val = d.get(k)
                    if not isinstance(val, list): val = []
                    fd[k] = val
                
                # Update remaining scalar fields
                fd.update({k: d.get(k, fd.get(k)) for k in [
                    "one_liner", "summary", "risk_tag", "return_value", 
                    "contextual_purpose", "risk_logic", "suggested_func_name", "confidence"
                ]})
        except: pass

        # Load generated readable code and raw decompiled code for the UI tabs
        rd = load_readable_from_disk(node.ea, node.name, output_dir)
        raw_decomp = load_decompiled_from_disk(node.ea, node.name, output_dir)
        fd["code"] = rd if rd else (cleanup_decompiled_code(raw_decomp) if raw_decomp else "")
        fd["raw_code"] = raw_decomp if raw_decomp else ""
        
        # Load high-level execution flow
        ef = load_exec_flow_from_disk(node.ea, node.name, output_dir)
        fd["exec_flow"] = ef if ef else ""

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

        def _try_json(s):
            try:
                res = json.loads(s)
                if res is not None: return res
            except:
                # Truncation repair: try adding closing characters
                for tail in ["}", "]", "}]", "}}", "}]}", "}}]}"]:
                    try:
                        res = json.loads(s + tail)
                        if res is not None: return res
                    except: pass
                # Aggressive repair: handle unclosed strings
                for tail in ["\"}", "\"]", "\"}]", "\"}}", "\"}]}", "\"}}]}"]:
                    try:
                        res = json.loads(s + tail)
                        if res is not None: return res
                    except: pass
            return None

        # 1. Primary Attempt: Extract any JSON-like block bounded by {} or []
        # We try to find the longest block that looks like JSON
        json_blocks = re.findall(r'(\{.*\}|\[.*\])', raw, re.DOTALL)
        if json_blocks:
            for block in sorted(json_blocks, key=lambda x: len(x), reverse=True):
                res = _try_json(block)
                if res: return res

        # 1.2. Secondary Attempt: If valid JSON block not found with DOTALL greediness, 
        # try a more targeted approach for Markdown code blocks
        md_blocks = re.findall(r'```(?:json)?\s*(.*?)\s*```', raw, re.DOTALL)
        for block in md_blocks:
            res = _try_json(block.strip())
            if res: return res

        # 1.5. Truncation Recovery: If no closed block found, try extracting from the first { or [ to end
        first_curly = raw.find('{')
        first_bracket = raw.find('[')
        start_idx = -1
        if first_curly != -1 and (first_bracket == -1 or first_curly < first_bracket):
            start_idx = first_curly
        elif first_bracket != -1:
            start_idx = first_bracket
            
        if start_idx != -1:
            block = raw[start_idx:]
            res = _try_json(block)
            if res: return res

        # 2. Fallback: Detailed plucker for split or severely malformed JSON
        def _pluck_best_effort(raw_str):
            pluck_keys = [
                "detailed_technical_overview", "detailed_narrative", "assessment", 
                "summary", "verdict", "mechanisms", "findings", "steps", 
                "capabilities", "functions", "techniques", "interactions", 
                "iocs", "artifacts"
            ]
            extracted = {}
            for pk in pluck_keys:
                pattern = f'"{pk}"\\s*:\\s*([\\"\\[])(.*)'
                m = re.search(pattern, raw_str, re.DOTALL | re.IGNORECASE)
                if m:
                    starter = m.group(1)
                    content_raw = m.group(2).strip()
                    
                    if starter == '"':
                        next_key = re.search(r'",\s*"[^"]+"\s*:', content_raw)
                        if next_key: content_raw = content_raw[:next_key.start()]
                        content_raw = re.sub(r'"\s*[,\}\]]\s*[^"]*$', '', content_raw, flags=re.DOTALL).strip()
                        if content_raw.endswith('"'): content_raw = content_raw[:-1]
                        extracted[pk] = content_raw.strip()
                    else:
                        if content_raw.count('"') % 2 != 0:
                            content_raw += '"'
                        
                        # Try parsing from the start of the list
                        # We try to find the closing bracket
                        bracket_depth = 1
                        list_end = len(content_raw)
                        for idx, char in enumerate(content_raw):
                            if char == '[': bracket_depth += 1
                            elif char == ']': bracket_depth -= 1
                            if bracket_depth == 0:
                                list_end = idx + 1
                                break
                        
                        list_str = "[" + content_raw[:list_end]
                        # Fix up if we stopped early
                        if not list_str.endswith(']'): list_str += ']'
                        
                        try:
                            res = json.loads(list_str)
                            if res: extracted[pk] = res
                        except:
                            # Final fallback tail search including unclosed quotes
                            for tail in ["", "]", "}]", "}]}", "}}]}", "\"]", "\"}]", "\"}]}", "\"}}]}"]:
                                try:
                                    res = json.loads(list_str + tail)
                                    if res: 
                                        extracted[pk] = res
                                        break
                                except: pass
            return extracted

        res = _pluck_best_effort(raw)
        return res if res else {}

    # --- 0. Prepare Analysis Data (Strings & Deterministic IOCs)
    s_data = extract_ida_strings(graph, _log)
    det_iocs = extract_deterministic_iocs(s_data)
    _log(f"Extracted {len(s_data)} strings and {len(det_iocs)} deterministic IOCs.")

    # Highlighting Helpers
    def _apply_forensic_highlighting(text):
        if not text or not isinstance(text, str): return text
        
        # We only keep the function name redirection as requested by the user.
        # Highlighting for APIs, IOCs, Paths, and Commands has been removed.

        # Function Names (Cross-reference analyzed functions)
        # Sort by length descending to match longest possible function name first
        sorted_fnames = sorted([f["name"] for f in functions_data if len(f["name"]) > 4], key=len, reverse=True)
        for fname in sorted_fnames[:100]: # Cap to avoid over-processing
            safe_fname = re.escape(fname)
            # Find the first ea for this name
            target_ea = next((f["ea"] for f in functions_data if f["name"] == fname), None)
            if target_ea:
                 # Standard link style, no extra highlighting span
                 text = re.sub(fr'\b{safe_fname}\b', f'<a href="#fn_{target_ea:X}" style="color:var(--accent); text-decoration:underline dotted;" title="View function details">\g<0></a>', text)

        return text

    def _format_ai_text(raw: str) -> str:
        """Convert AI text with literal \n and \" sequences into proper HTML paragraphs."""
        if not raw or not isinstance(raw, str): return ""
        # Decode literal backslash-n and backslash-quote form the JSON string value
        text = raw.replace('\\n', '\n').replace('\\"', '"').replace('\\t', ' ')
        # Split on double-newlines → paragraph blocks
        # 🛑 CRITICAL: Also strip surrounding quotes from each paragraph to fix AI formatting artifacts
        paragraphs = [p.strip().strip('"') for p in text.split('\n\n') if p.strip()]
        if not paragraphs:
            return _apply_forensic_highlighting(_escape_html(raw))
        parts = []
        for para in paragraphs:
            # Numbered heading like "1. Title: rest" → bold label + rest
            m = re.match(r'^(\d+\.\s*[^:]+:)(.*)$', para, re.DOTALL)
            if m:
                heading = _escape_html(m.group(1).strip())
                body = _apply_forensic_highlighting(_escape_html(m.group(2).strip())).replace('\n', '<br>')
                parts.append(f'<p style="margin:0 0 10px 0;"><strong style="color:#1e293b;">{heading}</strong> {body}</p>')
            else:
                body = _apply_forensic_highlighting(_escape_html(para)).replace('\n', '<br>')
                parts.append(f'<p style="margin:0 0 10px 0;">{body}</p>')
        return ''.join(parts)

    # --- 1. Executive Summary
    exec_json = _parse_ai_json("assessment")
    narrative = ""
    if isinstance(exec_json, dict):
        narrative = exec_json.get("assessment") or exec_json.get("detailed_narrative") or ""
    
    if narrative:
        exec_summary_html = f'<div class="ai-block" style="border-left-color:var(--accent); padding: 25px; line-height: 1.6;">{_format_ai_text(narrative)}</div>'
    elif isinstance(exec_json, dict) and any(k in exec_json for k in ["verdict", "reasoning", "core_operation", "function_tree_analysis"]):
        # Fallback for old data or specific keys
        v = exec_json.get("verdict", "")
        r = exec_json.get("reasoning", "")
        c = exec_json.get("core_operation", "")
        f = exec_json.get("function_tree_analysis", "")
        exec_summary_html = f'<div class="ai-block" style="padding: 25px; line-height: 1.6;"><b>Verdict:</b> {v}<br/><br/><b>Reasoning:</b> {r}<br/><br/><b>Core Operation:</b> {c}<br/><br/><b>Analysis:</b> {f}</div>'
        exec_summary_html = _apply_forensic_highlighting(exec_summary_html)
    else:
        # Final fallback from raw sections
        summ = sections.get("assessment") or "Assessment data absent or AI synthesis failed."
        if isinstance(summ, dict):
            summ = summ.get("assessment") or summ.get("detailed_narrative") or str(summ)
        # Scrub JSON leftovers if present in raw string
        if isinstance(summ, str) and ("assessment" in summ or "detailed_narrative" in summ):
            m = re.search(r'"(?:assessment|detailed_narrative)"\s* : \s*"(.*)', summ, re.DOTALL)
            if m:
                summ = re.sub(r'"\s*[,\}\]]\s*[^"]*$', '', m.group(1), flags=re.DOTALL).strip()
                if summ.endswith('"'): summ = summ[:-1]
        
        exec_summary_html = f'<div class="ai-block" style="padding: 25px; line-height: 1.6;">{_format_ai_text(str(summ))}</div>'

    # --- 2. Technical Code Analysis Overview
    overview_json = _parse_ai_json("overview")
    tech_narrative = ""
    if isinstance(overview_json, dict):
        tech_narrative = overview_json.get("detailed_technical_overview", "")
    

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
                desc = _apply_forensic_highlighting(_escape_html(s.get("description", "")))
                steps_rows += f'<tr><td style="font-weight:bold; width:180px;">{phase}</td><td class="muted">{desc}</td></tr>'
        execution_flow_html = f'<table class="data-table"><thead><tr><th>Phase</th><th>Execution Description</th></tr></thead><tbody>{steps_rows}</tbody></table>' if steps_rows else f'<p class="muted">No execution flow steps identified.</p>'
    else:
        execution_flow_html = f'<div class="ai-block">{_escape_html(sections.get("execution_flow", "Execution flow analysis pending..."))}</div>'

    # --- 4. General Capability or Malware Features
    caps_json = _parse_ai_json("capabilities")
    cap_rows = ""
    
    # Normalize: Handle both {"capabilities": [...]} and raw list [...]
    actual_caps = []
    if isinstance(caps_json, dict):
        actual_caps = caps_json.get("capabilities", [])
    elif isinstance(caps_json, list):
        actual_caps = caps_json

    if actual_caps:
        for c in actual_caps:
            if isinstance(c, dict):
                name = _escape_html(c.get("name", ""))
                desc = _apply_forensic_highlighting(_escape_html(c.get("description", "")))
                funcs = c.get("associated_functions") or c.get("functions") or []
                if isinstance(funcs, str): funcs = [funcs]
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                cap_rows += f'<tr><td style="font-weight:bold; color:#1e293b; width:220px;">{name}</td><td class="muted">{desc}</td><td style="width:250px;">{f_html}</td></tr>'
        
        capabilities_html = f'<table class="data-table"><thead><tr><th>Capability</th><th>Description</th><th>Associated Functions</th></tr></thead><tbody>{cap_rows}</tbody></table>' if cap_rows else f'<p class="muted">No general capabilities identified.</p>'
    else:
        # Check if the raw string is just empty or boilerplate
        raw_cap = sections.get("capabilities", "")
        if not raw_cap or (isinstance(raw_cap, dict) and not any(raw_cap.values())):
            capabilities_html = '<p class="muted">No general capabilities identified.</p>'
        else:
            capabilities_html = f'<div class="ai-block" style="border-left-color: #cbd5e1;">{_escape_html(str(raw_cap))}</div>'

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
                evid = _apply_forensic_highlighting(_escape_html(m.get("evidence", "")))
                funcs = m.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                c2_rows += f'<tr><td style="font-weight:bold; width:180px;">{feat}</td><td>{evid}</td><td class="muted">{f_html}</td></tr>'
        
    c2_summary_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_apply_forensic_highlighting(_escape_html(_summ))}</div>' if _summ else ""
    
    if c2_rows:
        c2_analysis_html = c2_summary_html + f'<table class="data-table"><thead><tr><th>Mechanism</th><th>Technical Evidence</th><th>Source Functions</th></tr></thead><tbody>{c2_rows}</tbody></table>'
    elif _summ:
        c2_analysis_html = '<p class="muted">No explicit C2/Backdoor mechanisms extracted.</p>'
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
                c2_analysis_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_c2))}</div>'

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
                det = _apply_forensic_highlighting(_escape_html(m.get("details", "")))
                funcs = m.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                pers_rows += f'<tr><td style="font-weight:bold; width:180px;">{meth}</td><td>{det}</td><td class="muted">{f_html}</td></tr>'
        
    pers_summary_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_apply_forensic_highlighting(_escape_html(_psumm))}</div>' if _psumm else ""
    
    if pers_rows:
        persistence_html = pers_summary_html + f'<table class="data-table"><thead><tr><th>Persistence Method</th><th>Technical Details</th><th>Source Functions</th></tr></thead><tbody>{pers_rows}</tbody></table>'
    elif _psumm:
        persistence_html = '<p class="muted">No specific persistence mechanisms detected.</p>'
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
                persistence_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_pers))}</div>'

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
                desc = _apply_forensic_highlighting(_escape_html(f.get("description", "")))
                funcs = f.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                recon_rows += f'<tr><td style="font-weight:bold; width:180px;">{cat}</td><td>{desc}</td><td class="muted">{f_html}</td></tr>'
        
    recon_summary_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; margin-bottom:15px; padding:25px; line-height:1.6;"><b>Summary:</b> {_apply_forensic_highlighting(_escape_html(_rsumm))}</div>' if _rsumm else ""
    
    if recon_rows:
        recon_infostealer_html = recon_summary_html + f'<table class="data-table"><thead><tr><th>Category</th><th>Analysis Discovery</th><th>Source Functions</th></tr></thead><tbody>{recon_rows}</tbody></table>'
    elif _rsumm:
        recon_infostealer_html = '<p class="muted">No specific info-stealing artifacts identified.</p>'
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
                recon_infostealer_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_recon))}</div>'

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
                interaction_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_inter))}</div>'

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
                rdesc = _apply_forensic_highlighting(_escape_html(t.get("description", "")))
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
                api_resolving_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_res))}</div>'

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
                adesc = _apply_forensic_highlighting(_escape_html(t.get("description", "")))
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
                anti_analysis_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_anti))}</div>'

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
                cdesc = _apply_forensic_highlighting(_escape_html(c.get("usage", c.get("purpose", c.get("description", "")))))
                funcs = c.get("associated_functions") or []
                f_html = ", ".join([f'<code>{_escape_html(str(func))}</code>' for func in funcs])
                cry_rows += f'<tr><td style="font-weight:bold; width:200px;">{cname}</td><td>{cdesc}</td><td class="muted">{f_html}</td></tr>'
        
        crypto_artifacts_html = f'<table class="data-table"><thead><tr><th>Cryptographic Algorithm</th><th>Analysis Purpose</th><th>Source Functions</th></tr></thead><tbody>{cry_rows}</tbody></table>'
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
                crypto_artifacts_html = f'<div class="ai-block" style="border-left-color: #cbd5e1; white-space: pre-wrap; padding: 25px;">{_apply_forensic_highlighting(_escape_html(clean_cry))}</div>'

    # --- 12. Suspicious Imports
    api_rows = ""
    for api, info in sorted(suspicious_apis.items(), key=lambda x: x[0]):
        fnames = ", ".join(info["funcs"][:10]) + ("..." if len(info["funcs"]) > 10 else "")
        api_rows += f'<tr><td><code>{_escape_html(api)}</code></td><td>{_escape_html(info["category"])}</td><td class="muted">{_escape_html(fnames)}</td></tr>'

    suspicious_imports_html = f'<table class="data-table"><thead><tr><th>API Name</th><th>Category</th><th>Associated Functions</th></tr></thead><tbody>{api_rows}</tbody></table>' if api_rows else '<p class="muted">No explicit high-risk imports detected.</p>'


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

    system_dlls = {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
        "ws2_32.dll", "winmm.dll", "wtsapi32.dll", "iphlpapi.dll", "secur32.dll",
        "cryptdll.dll", "ntdll.dll", "msvcrt.dll", "wsock32.dll", "wininet.dll",
        "shell32.dll", "shlwapi.dll", "crypt32.dll", "rpcrt4.dll", "mpr.dll",
        "netapi32.dll", "normaliz.dll", "version.dll", "psapi.dll", "gdi32.dll",
        "comctl32.dll", "comdlg32.dll", "setupapi.dll", "imagehlp.dll", "dbghelp.dll"
    }

    if ioc_json and isinstance(ioc_json, dict) and "iocs" in ioc_json:
        ioc_rows = ""
        for ioc in ioc_json.get("iocs", []):
            if isinstance(ioc, dict):
                _type = _escape_html(ioc.get("type", ""))
                _val = _escape_html(ioc.get("value", ""))
                
                if str(ioc.get("value", "")).strip().lower() in system_dlls and str(ioc.get("type", "")).strip().lower() == "filename":
                    continue
                _ctx = _apply_forensic_highlighting(_escape_html(ioc.get("context", "")))
                
                # Associated functions handle
                funcs = ioc.get("associated_functions") or ioc.get("functions") or []
                if isinstance(funcs, str): funcs = [funcs]
                f_html = ", ".join([f'<code>{_escape_html(str(f))}</code>' for f in funcs])
                
                ioc_rows += f'<tr><td style="font-weight:600;">{_type}</td><td><code>{_val}</code></td><td class="muted">{_ctx}</td><td class="muted" style="width:250px;">{f_html}</td></tr>'
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

        funcs = s.get("funcs", [])
        if len(funcs) > 1:
            f_html = '<ul style="margin:0; padding-left:16px; list-style:disc;">' + \
                     ''.join(f'<li><code>{_escape_html(f)}</code></li>' for f in funcs) + \
                     '</ul>'
        elif funcs:
            f_html = f'<code>{_escape_html(funcs[0])}</code>'
        else:
            f_html = ''

        s_rows += f'''
        <tr>
            <td style="word-break:break-all; font-family:'Fira Code', 'Cascadia Code', monospace; font-size:12px;">{val}</td>
            <td class="muted" style="width:260px;">{f_html}</td>
        </tr>'''
    
    if s_rows:
        strings_html = f'''
        <details class="fn-card" style="margin-top:0; border:1px solid #e2e8f0; box-shadow:none;">
            <summary style="padding:15px; cursor:pointer; font-weight:600; color:#1e293b; background:#f8fafc; border-radius:8px; display:flex; align-items:center; gap:10px;">
                <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
                View Extracted Strings ({len(s_data)} artifacts found)
            </summary>
            <div style="padding:15px;">
                <table class="data-table" style="box-shadow:none; border:none; margin-top:0;">
                    <thead><tr><th>String Value</th><th style="width:260px;">Associated Functions</th></tr></thead>
                    <tbody id="strings-tbody">{s_rows}</tbody>
                </table>
                <div id="strings-pagination" style="margin-top:15px; display:flex; gap:10px; justify-content:center; align-items:center; font-size:13px; font-weight:600; color:#475569;">
                    <button onclick="changeStringPage(-1)" style="padding:6px 14px; border-radius:6px; border:1px solid #cbd5e1; background:white; cursor:pointer; font-weight:600; color:#334155;">&lt; Prev</button>
                    <span id="strings-page-info">Page 1</span>
                    <button onclick="changeStringPage(1)" style="padding:6px 14px; border-radius:6px; border:1px solid #cbd5e1; background:white; cursor:pointer; font-weight:600; color:#334155;">Next &gt;</button>
                </div>
                <script>
                    var currentStringPage = 1;
                    var stringsPerPage = 20;
                    function renderStringPage() {{
                        var tbody = document.getElementById('strings-tbody');
                        if(!tbody) return;
                        var rows = tbody.getElementsByTagName('tr');
                        var totalPages = Math.ceil(rows.length / stringsPerPage) || 1;
                        
                        if(currentStringPage < 1) currentStringPage = 1;
                        if(currentStringPage > totalPages) currentStringPage = totalPages;
                        
                        var start = (currentStringPage - 1) * stringsPerPage;
                        var end = start + stringsPerPage;
                        
                        for(var i=0; i<rows.length; i++) {{
                            rows[i].style.display = (i >= start && i < end) ? '' : 'none';
                        }}
                        document.getElementById('strings-page-info').innerText = 'Page ' + currentStringPage + ' of ' + totalPages;
                    }}
                    function changeStringPage(dir) {{
                        currentStringPage += dir;
                        renderStringPage();
                    }}
                    // Run immediately to format on load
                    renderStringPage();
                </script>
            </div>
        </details>'''
    else:
        strings_html = '<p class="muted">No significant strings discovered.</p>'

    # --- 8. Function Analysis
    # 8.1 Call Chain Analysis
    # Expanded visibility: Depth up to 5, and force-include all malicious/suspicious functions
    # Priority: High-risk nodes first, then by depth to maintain tree-like flow
    candidates = [f for f in functions_data if (f.get("depth", 99) <= 5 or f.get("risk_tag") in ("malicious", "suspicious"))]
    # Sort primarily by depth to keep the tree look, but we'll cap the total
    candidates.sort(key=lambda x: x.get("depth", 99))
    
    # Take more nodes to show the full attack path (up to 60)
    call_chain_nodes = candidates[:60]
    chain_html = ""
    for f in call_chain_nodes:
        cl = {"malicious":"#dc2626","suspicious":"#f59e0b","benign":"#16a34a"}.get(f.get("risk_tag"),"#94a3b8")
        depth = f.get("depth", 0)
        # Apply visual tree indentation
        indent = depth * 25
        tree_prefix = ""
        if depth > 0:
            tree_prefix = '<span style="color:#cbd5e1; margin-right:5px; font-family:monospace;">└─</span>'
            
        chain_html += f'''
        <div class="chain-box" style="border-left-color:{cl}; margin-left:{indent}px; position:relative;">
            {tree_prefix}<b>{_escape_html(f["name"])}</b> 
            <span class="muted" style="font-size:11px; margin-left:5px;">(Depth {depth})</span>
            <div style="margin-top:4px; padding-left:{15 if depth > 0 else 0}px;">
                <small style="color:#475569; line-height:1.4;">{_escape_html(f.get("one_liner") or "Entry execution path")}</small>
            </div>
        </div>'''
    
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
              Raw Mermaid Source Code (Export to www.mermaidonline.live)
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
                <thead><tr><th>Target Address</th><th>Function Identifier</th><th>Analysis Reasoning & Pattern Discovery</th></tr></thead>
                <tbody>{ai_rows}</tbody>
            </table>
        </div>''' if ai_rows else ''
        
        taxonomy_html = f'''
        <div>
            <div style="font-weight:bold; color:#64748b; margin-bottom:10px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Verified Analysis Taxonomy:</div>
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
            <div class="fn-info-row"><b>Purpose:</b> {_apply_forensic_highlighting(_escape_html(f.get("one_liner") or "—"))}</div>
            <div class="fn-info-row"><b>Summary:</b> {_apply_forensic_highlighting(_escape_html(f.get("summary") or "—"))}</div>
            <div class="fn-info-row"><b>Contextual Purpose:</b> {_apply_forensic_highlighting(_escape_html(f.get("contextual_purpose") or "—"))}</div>
            <div class="fn-info-row"><b>Return Value:</b> {_apply_forensic_highlighting(_escape_html(f.get("return_value") or "—"))}</div>
            <div class="fn-info-row"><b>Risk Logic:</b> {_apply_forensic_highlighting(_escape_html(f.get("risk_logic") or "—"))}</div>
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
            <details class="code-section" style="margin-top:6px;">
                <summary class="code-section-header">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    <span>High-level execution flow</span>
                </summary>
                <div class="code-section-body">
                    <pre><code class="language-markdown">{_escape_html(f.get("exec_flow", ""))}</code></pre>
                </div>
            </details>
        </div>'''

    # --- 12. Risk Assessment
    risk_json = _parse_ai_json("risk_assessment")
    
    verdict_header_html = ""
    if risk_json and isinstance(risk_json, dict) and ("risk_score" in risk_json or "malware_category" in risk_json):
        rs = str(risk_json.get("risk_score", "0"))
        reason = risk_json.get("risk_reason", "Analysis of core routines and API behaviors indicates significant operational risk.")
        category = risk_json.get("malware_category", "Malware / Potentially Unwanted Tool")
        
        verdict_header_html = f'''
        <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:25px; margin-bottom:25px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06); border-top: 5px solid {risk_color};">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                <div style="flex:1;">
                    <div style="font-size:11px; font-weight:800; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">Verdict & Risk Assessment</div>
                    <h2 style="margin:0; color:#1e293b; font-size:26px; font-weight:800; letter-spacing:-0.5px;">{_escape_html(category)}</h2>
                    <div style="margin-top:12px; color:#334155; font-size:15px; line-height:1.6;">
                        <b style="color:#475569;">Risk Factor:</b> {_escape_html(reason)}
                    </div>
                </div>
                <div style="background:#f8fafc; border:1px solid #e2e8f0; padding:15px 25px; border-radius:12px; text-align:center; min-width:130px; margin-left:30px; box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.05);">
                    <div style="font-size:32px; font-weight:900; color:{risk_color}; line-height:1;">{_escape_html(rs)}<span style="font-size:18px; color:#cbd5e1; font-weight:700;">/100</span></div>
                    <div style="font-size:10px; font-weight:800; color:#64748b; text-transform:uppercase; margin-top:8px; letter-spacing:0.5px;">Security Risk</div>
                </div>
            </div>
        </div>'''

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
.toggle-icon {{ transition: transform 0.2s ease; display: block; fill: currentColor; }}
details[open] .toggle-icon {{ transform: rotate(90deg); }}
.icon-box {{ width: 16px; height: 16px; background: transparent; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }}

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

  {verdict_header_html}

  <div style="background-color: #fffbeb; color: #b45309; padding: 15px 20px; border-left: 4px solid #f59e0b; border-radius: 6px; margin-bottom: 25px; font-size: 14px; line-height: 1.5; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
    <strong style="font-size: 15px;">⚠️ Analysis Warning</strong><br/>
    This report may contain hallucinated LLM-generated content, especially in the <b>Executive Summary</b> and <b>Technical Overview</b> sections. Proceed to the detailed function analysis below to assist your reverse engineering activities and independently verify these findings.
  </div>

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
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">1. General Identified Capabilities</h3>
        {capabilities_html}
    </div>
    
    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">2. C2, Backdoor or RAT Analysis</h3>
        {c2_analysis_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">3. Persistence Mechanisms</h3>
        {persistence_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">4. Reconnaissance or Info Stealer</h3>
        {recon_infostealer_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">5. File, Registry or Process Interaction</h3>
        {interaction_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">6. API Hashing, API Resolving or PEB Walk</h3>
        {api_resolving_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">7. Packer, Obfuscation or Anti-Analysis</h3>
        {anti_analysis_html}
    </div>

    <div style="margin-bottom:30px;">
        <h3 style="color:#1e293b; border-left:4px solid #cbd5e1; padding-left:10px; margin-bottom:15px;">8. Cryptographic, Hashing, Encoding or Compression Artifacts</h3>
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
    
    <details class="fn-card" style="margin-bottom:12px; border:1px solid #e2e8f0; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#1e293b; background:#f8fafc; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Call Chain Analysis
      </summary>
      <div style="padding:16px;">
        {chain_html if chain_html else '<p class="muted">No execution chain mapping established.</p>'}
      </div>
    </details>

    <details class="fn-card" style="margin-bottom:12px; border:1px solid #e2e8f0; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#1e293b; background:#f8fafc; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Call Graph (Tree View)
      </summary>
      <div style="padding:16px;">
        {tree_view_html}
      </div>
    </details>

    <details class="fn-card" style="margin-bottom:12px; border:1px solid #e2e8f0; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#1e293b; background:#f8fafc; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Mermaid Visual Call Flow
      </summary>
      <div style="padding:16px;">
        {mermaid_html}
      </div>
    </details>

    <details class="fn-card" open style="margin-bottom:12px; border:1px solid #fecaca; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#dc2626; background:#fff5f5; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Malicious Functions
      </summary>
      <div style="padding:16px;">
        {mal_tbl}
      </div>
    </details>

    <details class="fn-card" open style="margin-bottom:12px; border:1px solid #fed7aa; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#c2410c; background:#fff7ed; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Suspicious Functions
      </summary>
      <div style="padding:16px;">
        {sus_tbl}
      </div>
    </details>

    <details class="fn-card" style="margin-bottom:12px; border:1px solid #bbf7d0; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#15803d; background:#f0fdf4; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Benign Functions
      </summary>
      <div style="padding:16px;">
        {benign_tbl}
      </div>
    </details>

    <details class="fn-card" open style="margin-bottom:12px; border:1px solid #e2e8f0; box-shadow:none;">
      <summary style="padding:14px 18px; cursor:pointer; font-weight:700; font-size:15px; color:#1e293b; background:#f8fafc; border-radius:8px; display:flex; align-items:center; gap:10px;">
        <div class="icon-box"><svg class="toggle-icon" style="width:10px; height:10px;" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></div>
        Function Decomposition
      </summary>
      <div style="padding:16px;">

    <div id="func-grid">
        <input type="text" id="fnSearch" class="filter-input" placeholder="Search function name or risk tag (e.g., malicious)..." onkeyup="filterFunctions()" style="margin-bottom:12px;">
        {decomp_html}
    </div>
      </div>
    </details>

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
# LEGACY MARKDOWN COMPATIBILITY SHIMS
# The report pipeline is HTML-only (report.html). These stubs exist solely
# so deep_analyzer.py call-sites continue to work without modification.
# summary.md is no longer written or consumed by any part of the pipeline.
# ===========================================================================

def write_markdown_header(output_dir, name, entry_ea, total_count=0, ts=""):
    """Returns a header string used as a markdown_updated_signal payload."""
    return f"# Malware Analysis Report: {name} (0x{entry_ea:X})\n**Date:** {ts}\n**Total Functions:** {total_count}\n\n"

def append_function_to_markdown(*args, **kwargs): pass

def finalize_markdown(output_dir, graph, summary_msg, entry_ea): pass

def build_function_markdown_piece(ea, node, res_data, graph, code=None):
    """Returns a minimal markdown snippet used as a markdown_updated_signal payload."""
    risk = (res_data.get("risk_tag") or "benign").upper()
    summ = res_data.get("one_liner") or res_data.get("summary") or "No detail available."
    return f"### {node.name} (0x{ea:X}) [{risk}]\n**Summary:** {summ}\n\n"

def assemble_malware_source(graph, entry_ea, output_dir):
    """Concatenate all custom function code into a single Analysis library."""
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

def generate_program_overview(digest, entry_name, entry_children_count, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

Target Entry: {entry_name}
Sub-calls: {entry_children_count}

Analyze the Analyst Notebook and provide a high-level technical code analysis overview of what the program is doing.
Focus on operational logic, data flow, structure, and stage-by-stage choreography explicitly found in the notes.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "operational_logic": "Brief high-level overview of the program's logic.",
  "data_flow": "Brief overview of data movement.",
  "choreography": "Brief overview of execution flow."
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=2048, **kwargs)

def generate_technical_overview(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

You are a senior malware reverse engineer writing a Technical Code Analysis Overview section for a professional malware analysis report. Your goal is to provide a deep-dive technical narrative that explains the inner workings of the binary by relying STRICTLY on the curated notes provided in the "Analyst Notebook" above.

STRICT RULES:
- The Analyst Notebook is categorically split into Executable Dispatch, Malicious Payloads, and Suspicious Infrastructure. You MUST build your narrative around the "CRITICAL MALICIOUS PAYLOADS" section.
- Produce a cohesive technical narrative linking the malicious payload functions together (e.g. how data collected in one function is encrypted or exfiltrated in another).
- Do not talk about compiler or linker findings.
- Do not talk about any system DLLs or runtime error strings.
- Base everything ONLY on the functions explicitly listed in the Analyst Notebook.
- Explain:
  - The malicious techniques being implemented.
  - Their technical purpose within the attack.
  - How they are implemented (specific APIs, structures).
  - The exact function names (e.g., fn_function).
You are prohibited from describing findings unless explicit logic is present in the Analyst Notes.

OUTPUT STRUCTURE:
The technical code analysis must focus on the core malicious payload capabilities. Describe the overall design. Explain the entry point logic briefly, but spend the majority of the text analyzing the command dispatchers, file/network manipulation, cryptography, or active stealth techniques listed in the Notebook. 

WRITING STYLE:
- Technical, Dense, and Authoritative. No filler.
- Answer WHY and HOW for every major malicious function.
- Split to several paragraph.

Respond STRICTLY with a valid JSON object:
{{
  "detailed_technical_overview": "Comprehensive 6-zone Analysis narrative."
}}"""
    sys_p = "You are a senior malware reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_malware_analysis_assessment(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

You are a senior malware reverse engineer and head of Analysis reporting. Your analysts have prepared the "Analyst Notebook" above containing the highest-risk functions found in the binary. You must write a professional Executive Summary section for a high-stakes malware analysis report based ONLY on these notes.

You must:
- Determine the threat category (e.g. Spyware, Ransomware, Dropper, Benign) based on the "CRITICAL MALICIOUS PAYLOADS" (dont mention this word in report) and "STRATEGIC INDICATORS" (dont mention this word in report) sections in the notebook.
- Do NOT infer lifecycle stages beyond what the notes explicitly state.
- Do not talk about generic functions or compiler operations.
- If no Malicious payloads exist, explicitly state the program appears to be Safe or Adware.

STRICT REQUIREMENTS:
- STRONGLY PRIORITIZE the "CRITICAL MALICIOUS PAYLOADS" (dont mention this word in report) section of the notebook. Do NOT constrain your summary to just the Layer 1 dispatch.
- You MUST explicitly document and emphasize the highest-risk sub-routines (e.g. data collection, C2, evasion, injection).
- Base every statement ONLY on the functions provided in the notebook.
- Do NOT speculate, infer intent beyond technical evidence, or attribute capabilities that are not explicitly implemented in code.
- Avoid qualitative adjectives.
- For EVERY major observation, you MUST answer the following questions within the narrative:
  1. What is the specific malicious capability?
  2. What is the technical objective behind it?
  3. Identify specific malicious function names (e.g., fn_function) where the logic resides.
  4. Explain how these disjointed functions fit into the overall attack narrative.
5. Do NOT wrap individual paragraphs in additional double quotes.

Respond STRICTLY with a valid JSON object matching this structure:
{{
  "detailed_narrative": "The full 4-paragraph technical executive summary text providing deep malware analysis and code reverse engineering context."
}}"""
    sys_p = "You are a senior malware reverse engineer and head of Analysis reporting. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_key_capabilities(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

Identify key technical capabilities matching malware features based solely on the Analyst Notebook. For each capability, list which specific function(s) perform or contribute to it.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "capabilities": [
    {{
      "name": "Capability Name (e.g. Network C2)", 
      "description": "Brief technical description",
      "associated_functions": ["func_name1", "func_name2"]
    }}
  ]
}}
CRITICAL: Do NOT list generic CRT wrappers, error handling, pointer encryption, thread-local storage, or memory allocation as capabilities. If no actual malicious or significant capabilities exist, it is perfectly acceptable to return a very small list.
Use ONLY function names explicitly listed in the Analyst Notebook."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_suspicious_functions(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

Extract functions performing highly suspicious operations directly from the notebook. Do not hallucinate external routines.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "functions": [
    {{"address": "0x123456", "name": "func_name", "reasoning": "why it's suspicious"}}
  ]
}}
IMPORTANT: Replace 0x123456 with the actual hex address from the Analyst Notebook."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_malicious_functions(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Analyst Notebook: 
{digest}

Extract definitive malicious functions and patterns directly from the notebook. Do not hallucinate external routines.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "functions": [
    {{"address": "0x123456", "name": "func_name", "reasoning": "pattern description"}}
  ]
}}
IMPORTANT: Replace 0x123456 with the actual hex address from the Analyst Notebook."""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_behavioral_indicators(digest, ai_cfg, log_fn, all_strings=None, **kwargs):
    if not all_strings:
        all_strings = []
        
    chunk_size = 150
    aggregated_iocs = []
    
    # Ensure strings are handled in chunks to prevent context overflow, but always include them
    chunks = [all_strings[i:i + chunk_size] for i in range(0, len(all_strings), chunk_size)]
    if not chunks: chunks = [[]]
        
    sys_p = "You are a senior reverse engineer experts in malware analysis. Respond ONLY with valid JSON."
    
    for idx, chunk in enumerate(chunks):
        if len(chunks) > 1:
            log_fn(f"Processing chunk {idx+1}/{len(chunks)} of strings for IOC extraction...", "info")
        
        batch_ctx = "\n".join(chunk) if chunk else "No additional strings."
        
        prompt = f"""Context: {digest}

Additional Strategic Strings for analysis:
{batch_ctx}

TASK:
1. Examine all Strategic Strings and API Behaviors in the Context and the Additional Strings.
2. Extract REAL, EXACT literal strings as forensic indicators (IOCs).
3. Focus on these specific types (Extract ANY that find):
   - hash: MD5, SHA1, or SHA256 literals.
   - IP: IPv4 or IPv6 addresses.
   - domain: Fully qualified domain names.
   - url: Complete URLs or target endpoints.
   - email: Email addresses found in strings.
   - port: Connection ports (if explicitly defined as such).
   - registry key: Full HKLM/HKCU paths.
   - registry value: Specific value names being modified or queried.
   - registry name: Friendly names associated with registry objects.
   - filename: Standalone filenames (e.g. 'malware.exe', 'temp.dat').
   - file path: Full or partial directory paths (e.g. 'C:\\Windows\\Temp\\').
   - folder name: Specific directory names of interest.
   - file extension: Suspicious or targeted extensions.
   - commands: Shell commands or command-line arguments.
   - OS Artifacts: Mutex names, User-Agents, or specific system markers.

CRITICAL RULES:
- DO NOT use placeholders or abstract values like [random_folder]. 
- The "value" MUST be a true literal string that was found in the input.
- Extract partial strings if they represent a clear IOC (e.g., a registry key fragment).
- IGNORE obvious system libraries (kernel32.dll, ntdll.dll, api-ms-win-*) unless they are involved in hijacking.
- DO NOT list standard Windows API names (e.g. GetCurrentProcess, CloseHandle, LoadLibraryA, GetProcAddress, TerminateProcess, etc.) as IOCs. These are standard system behaviors, not unique forensic indicators.
- DO NOT classify Windows DLLs or Windows API names as "domain" or "url". DLL names like advapi32, ntdll, or api-ms-win-* are NOT domains.
- STANDALONE strings that represent days of the week (Sunday, Monday, etc.), months (January, etc.), or common date formats (MM/dd/yy) are NOT IOCs and should be ignored.
- For each IOC, explain its Analysis significance.
- associated_functions MUST be a list of function names from the context that reference this indicator.

Respond STRICTLY with a valid JSON object:
{{
  "iocs": [
    {{
      "type": "Hash|IP|Domain|URL|Registry Key|Registry Value|Registry Name|Filename|File Path|Folder Name|File Extension|Email|Command|Port|Mutex|User-Agent", 
      "value": "EXACT LITERAL STRING FOUND", 
      "context": "Analysis significance / why it's a malware or forensic indicator",
      "associated_functions": ["func_name1", "sub_401000"]
    }}
  ]
}}"""

        res = _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)
        
        # Parse result: LLM returns string, we need dict
        parsed = {}
        if isinstance(res, str):
            # Strip markdown code blocks if present
            cleaned = re.sub(r'```(?:json)?|```', '', res).strip()
            try:
                parsed = json.loads(cleaned)
            except:
                # Best-effort regex extraction if JSON is broken
                matches = re.findall(r'\{.*\}', cleaned, re.DOTALL)
                if matches:
                    try: parsed = json.loads(matches[0])
                    except: pass
        elif isinstance(res, dict):
            parsed = res

        if isinstance(parsed, dict) and "iocs" in parsed and isinstance(parsed["iocs"], list):
            aggregated_iocs.extend(parsed["iocs"])
            
    # Final Deduplication: remove duplicates with case-insensitive check and clean up
    final_iocs = []
    seen_values = set()
    for item in aggregated_iocs:
        if not isinstance(item, dict): continue
        val = str(item.get("value", "")).strip()
        if not val: continue
        val_lower = val.lower()
        if val_lower not in seen_values:
            # Ensure type is one of the preferred ones
            final_iocs.append(item)
            seen_values.add(val_lower)
            
    return {"iocs": final_iocs}

def generate_ranked_strings(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Review the Extracted Strings in the context. Rank them by Analysis importance.

Rank categories: High (C2, persistence, exploit artifacts), Medium (Configuration, specific internal logic), Low (UI strings, logging).

Respond STRICTLY with a valid JSON object:
{{
  "ranked_strings": [
    {{"value": "the string", "importance": "High|Medium|Low"}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=2048, **kwargs)

def generate_risk_assessment(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Provide a definitive overall Risk Assessment based on all aggregated static analysis data.
Synthesize findings from all segments, provide an overall risk score, and conclude with security recommendations.
Respond STRICTLY with a valid JSON object matching this structure:
{{
  "risk_score": 85,
  "risk_reason": "Concise 1-sentence reason why this score was given.",
  "malware_category": "Spyware|Ransomware|Dropper|Infostealer|Lsass Dumper|Worm|Trojan|Backdoor|Safe|Adware|Tool",
  "summary": "1-2 paragraphs of synthesis",
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=2048, **kwargs)

def generate_execution_flow_overview(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}

Analyze the program's complete execution lifecycle from start to finish. 
Trace the operational flow by synthesizing the 'Primary Execution Dispatch' (entry logic) and the 'Deep Analysis Findings' (sub-routine capabilities).

Your goal is to identify a logical chronological sequence of stages (e.g., Initialization -> Environment Discovery -> Persistence/Infection -> Core Malicious Logic -> Network/C2 Communication -> Cleanup/Termination).

STRICT Analysis RULES:
1. Break the execution into a granular set of 5 to 7 distinct logical phases representing the full chronological lifecycle. Do NOT consolidate multiple stages unless the program is extremely trivial.
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
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_crypto_artifacts(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Identify Cryptographic, Hashing, Encoding, or Compression artifacts.

Look for:
1. Hashing: MD5, SHA-1/256/512, CRC32, custom rolling hashes (e.g., API name hashes).
2. Encryption: XOR loops with constant keys, bitwise substitution, S-box implementations (AES/DES), or WinAPI calls (BCrypt, CryptProtectData, CryptEncrypt).
3. Encoding: Base64/32/58, Hex-to-Bin conversion, custom alphabet substitution.
4. Compression: Zlib, LZMA, Huffman tables, or custom RLE (Run-Length Encoding).

ANTI-HALLUCINATION RULES:
1. DO NOT list things you did NOT find. If no artifacts are present, return an empty artifacts list.
2. Do NOT interpret simple bitwise XOR as "Encryption" unless you see a clear key-schedule or persistent algorithm pattern.
3. Standard pointer encoding (_encode_pointer, _decode_pointer) is NOT cryptography.

Respond STRICTLY with a valid JSON object:
{{
  "artifacts": [
    {{"algorithm": "Algorithm/Technique Name", "usage": "Specific technical details and purpose (e.g., C2 payload encryption, API name hashing)", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_anti_analysis_logic(digest, ai_cfg, log_fn, **kwargs):
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
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_c2_analysis(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}

Analyze technical evidence of Command & Control (C2), Backdoor communication, or RAT (Remote Access Trojan) capabilities.
Analysis FOCUS:
- Socket/Network APIs: WSAStartup, socket, connect, send, recv, HttpOpenRequest, WinHttpOpen.
- Shell/Command Channels: Creating pipes for cmd.exe, reverse shells, remote command execution.
- Command Handler: Identify command menus or handlers (e.g., switch/case or if/else chain dispatching specific commands like download, execute, terminate, etc.).
- Active Remote Control: Look for RAT-specific features like screen capture (GDI/BitBlt), keylogging (GetAsyncKeyState/SetWindowsHookEx), or direct remote execution logic.
- Network Artifacts: Hardcoded IPs, domains, or User-Agents.

STRICT Analysis RULES:
1. If the context shows 'opening shell connections' or 'creating pipes for command execution', this IS a Backdoor/C2 mechanism.
2. If the malware parses incoming data to dispatch commands (e.g., '1' for shell, '2' for upload), this is a C2 command menu.
3. If it has screenshot or keylogging logic combined with network send() calls, categorize it as active RAT capability within C2.
4. Cite specific functions from the 'DEEP Analysis FINDINGS' or 'CATEGORIZED WINAPI BEHAVIORS' as evidence.

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
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

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

def build_analysis_digest(graph, entry_ea, analysis_cache=None, interest_calc_fn=None, log_fn=None, output_dir=None):
    PLACEHOLDER_SUMMARIES = {"batch parsed function.", "trivial or wrapper function.", "", "(no summary available)"}
    MIN_CONFIDENCE = 40

    all_nodes = sorted([n for n in graph.values() if not n.is_library], key=lambda x: (x.depth, x.name))
    
    # 1. Aggregate categorized APIs (not just high-sev)
    try:
        from pseudonote.api_taxonomy import get_api_tags_for_function as _real_get_api_tags
        from pseudonote.api_taxonomy import get_category_severity as _real_get_category_severity
    except ImportError:
        _real_get_api_tags = get_api_tags_for_function
        _real_get_category_severity = lambda c: "LOW"
        
    names_map = {n.ea: n.name for n in graph.values()}
    categorized_apis = collections.defaultdict(list)
    
    for node in graph.values():
        if node.is_library: continue
        hits = _real_get_api_tags(node.ea, getattr(node, 'callees', []), names_map=names_map)
        for cat, apis in hits.items():
            for api in apis:
                categorized_apis[cat].append((api, node.name))
    
    api_digest = []
    
    def _cat_sort_key(cat):
        sev = _real_get_category_severity(cat).upper()
        if sev == "CRITICAL": return 0
        if sev == "HIGH": return 1
        if sev == "MEDIUM": return 2
        return 3
        
    sorted_cats = sorted(categorized_apis.keys(), key=lambda c: (_cat_sort_key(c), c))
    
    for cat in sorted_cats:
        cat_apis = categorized_apis[cat]
        api_usage = collections.defaultdict(set)
        for api, caller in cat_apis:
            api_usage[api].add(caller)
            
        formatted_apis = []
        for api in sorted(api_usage.keys(), key=lambda a: (-len(api_usage[a]), a)):
            callers = sorted(list(api_usage[api]))
            caller_str = ", ".join(callers[:3])
            if len(callers) > 3:
                caller_str += f", +{len(callers)-3} more"
            formatted_apis.append(f"{api} (in {caller_str})")
            
        api_digest.append(f"[{cat}]: {', '.join(formatted_apis[:15])}{'...' if len(formatted_apis) > 15 else ''}")
    
    api_summary_text = "\n".join(api_digest) if api_digest else "None explicitly categorized."

    # 2. Extract Strategic Strings
    s_data = extract_ida_strings(graph)
    # Filter out noise: Don't waste notebook context on system DLLs or common library boilerplate
    s_data = [s for s in s_data if s.get('category') not in ("System Component", "Library/Runtime String")]
    
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
    # Absolute drop list for Notebook (do not waste Analyst Notebook tokens on CRT/compiler wrappers unless malicious)
    ignore_stubs = ['__chkstk', '_fpreset', 'mainCRTStartup', '_start', '__main', 'TlsGetValue', '__mingw', 
                    '_init_', '_fini_', 'bad_alloc', 'bad_cast', 'exception', '_acmdln', 'get_osfhandle', 
                    '_isatty', '_setmode', '_cinit', '_invalid_parameter', '_pei386', '_encode_pointer', 
                    '_decode_pointer', 'IsProcessorFeaturePresent', 'atexit', '__security_init_cookie', 
                    '__CxxFrameHandler', '_purecall', '__acrt_', 'wcrtomb', 'mbrtowc', 'memset', 'memcpy', 
                    'memmove', 'memcmp', 'strlen', 'strcpy', 'strcmp', 'FlsAlloc', 'FlsGetValue', 'FlsSetValue', 
                    'FlsFree', '_NMSG_WRITE', 'GetProcessWindowStation', 'GetUserObjectInformation',
                    '__matherr', '_fpclass', '_statusfp', '_clearfp', '_controlfp', '_clear87', '_control87', '_status87',
                    'std::', 'std::allocator', 'std::vector', 'std::string', 'std::map', 'std::set', 'std::list',
                    'operator new', 'operator delete', '`new[]', '`delete[]', '`vector constructor iterator', '`vector destructor iterator',
                    'dynamic initializer for', 'dynamic atexit destructor for', '`vbase destructor', '`eh vector constructor',
                    '__RTC_CheckEsp', '__RTC_InitBase', '__RTC_Shutdown', 'GetActiveWindow', 'GetLastActivePopup',
                    '__tmainCRTStartup', 'wmainCRTStartup', '__scrt_common_main', '__scrt_common_main_seh',
                    '__scrt_initialize_crt', '__scrt_initialize_onexit_tables', '__scrt_acquire_startup_lock',
                    '__scrt_release_startup_lock', '__scrt_get_dyn_tls_init_callback', '__scrt_fastfail',
                    '__scrt_uninitialize_crt', '__security_check_cookie', '__security_cookie', '__GSHandlerCheck',
                    '__GSHandlerCheck_SEH', '__report_gsfailure', '__CxxThrowException', '__CxxFrameHandler3',
                    '__CxxFrameHandler4', '__std_terminate', '__std_exception_copy', '__std_exception_destroy',
                    '__RTtypeid', '__RTDynamicCast', '__RTCastToVoid', 'type_info', 'TlsAlloc', 'TlsFree',
                    'TlsSetValue', 'TlsGetValue', 'std::_Tree', 'std::_Vector', 'std::_List', 'std::_String',
                    'std::_Map', 'std::_Set', 'std::_Deque', 'std::_Hash', 'std::_Iterator', 'std::_Container',
                    '_interlockedincrement', '_interlockeddecrement', '_interlockedcompareexchange',
                    '_bit_scan_forward', '_bit_scan_reverse', 'InitializeCriticalSection', 'DeleteCriticalSection',
                    'EnterCriticalSection', 'LeaveCriticalSection', 'CreateThread', 'CreateThreadpoolWork',
                    'CloseHandle', 'WaitForSingleObject', 'HeapAlloc', 'HeapFree', 'HeapReAlloc', 'LocalAlloc',
                    'LocalFree', 'GlobalAlloc', 'GlobalFree',
                    # Golang stubs
                    'runtime.', 'type..', 'go.itab.', 'go.info.', 'go.string.', 'go.func.',
                    'fmt.', 'sync.', 'reflect.', 'strconv.', 'math.', 'internal.', 'syscall.',
                    # Rust stubs
                    'core::', 'alloc::', 'std::sys::', 'std::rt::', 'std::panicking::', 
                    'core::fmt::', 'core::panicking::', 'core::ptr::drop_in_place', 
                    'rust_panic', 'rust_begin_unwind', 'rust_eh_personality', 'compiler_builtins::']

    for node in all_nodes:
        risk_tag = getattr(node, "risk_tag", "benign")
        is_high_risk = risk_tag in ("malicious", "suspicious")
        
        # 1. Skip logic for benign stubs and Layer 1 overlaps
        if not is_high_risk:
            # Skip functions already in the Layer 1 Dispatch section to save tokens
            if node.ea in entry_child_eas: continue
            
            # Skip unanalyzed or low-confidence benign nodes
            if node.status not in ("analyzed", "preliminary", "contextual"): continue
            
            # Skip generic CRT and utility stubs
            if any(stub.lower() in node.name.lower() for stub in ignore_stubs): continue
            
            one_liner = (analysis_cache.get(node.ea, "") if analysis_cache else "") or getattr(node, "one_liner", "") or ""
            if (one_liner.lower() in PLACEHOLDER_SUMMARIES and not getattr(node, 'suspicious', [])) or node.confidence < MIN_CONFIDENCE: 
                 continue
        
        # 2. Extract detail
        one_liner = (analysis_cache.get(node.ea, "") if analysis_cache else "") or getattr(node, "one_liner", "") or ""
        full_summary = getattr(node, "summary", "") or ""
        
        quality_nodes.append({
            "node": node,
            "one_liner": one_liner,
            "summary": full_summary,
            "interest": interest_calc_fn(node) if interest_calc_fn else 0,
            "risk_tag": risk_tag
        })

    quality_nodes.sort(key=lambda x: (_RISK_ORDER.get(x["risk_tag"], 0), x["interest"]), reverse=True)
    # Convert all candidate nodes into notebook objects
    malicious_blocks = []
    suspicious_blocks = []
    benign_blocks = []
    
    for q in quality_nodes:
        n = q["node"]
        indicators = []
        if hasattr(n, 'preliminary_analysis') and isinstance(n.preliminary_analysis, dict):
            indicators = n.preliminary_analysis.get('suspicious', [])
        elif hasattr(n, 'suspicious') and isinstance(n.suspicious, list):
            indicators = n.suspicious
            
        ind_str = ", ".join(indicators[:5]) if indicators else "None"
        risk = q['risk_tag'].lower()
        
        # Determine how much detail to show
        # Malicious targets get the full extensive summary. Benign only get one-liners.
        summary_to_show = q['summary'] if (risk in ("malicious", "suspicious") and q['summary']) else q['one_liner']
        
        rich_details = ""
        if risk in ("malicious", "suspicious"):
            if hasattr(n, "pattern_matches") and n.pattern_matches:
                pat_str = ", ".join([p.get("name", "") for p in n.pattern_matches if isinstance(p, dict)])
                if pat_str: rich_details += f"\n    Patterns: {pat_str}"
            if hasattr(n, "semantic_tags") and n.semantic_tags:
                tag_str = ", ".join(n.semantic_tags)
                if tag_str: rich_details += f"\n    Tags: {tag_str}"
            # Extract high-level "Malware Capabilities" from deep analyzer markers
            if hasattr(n, 'preliminary_analysis') and isinstance(n.preliminary_analysis, dict):
                caps = n.preliminary_analysis.get('capabilities', [])
                if caps:
                    rich_details += f"\n    Capabilities: {', '.join(caps)}"

        block = f"  [{n.name}] (0x{n.ea:X})\n    Summary: {summary_to_show}\n    Indicators: {ind_str}{rich_details}"
        
        if risk == "malicious":
            malicious_blocks.append(block)
        elif risk == "suspicious":
            suspicious_blocks.append(block)
        else:
            # We only pull the top highly interesting benign functions contextually
            if len(benign_blocks) < 15:
                benign_blocks.append(block)

    # ---------------------------------------------------------
    # BUILD BINARY CONTEXT & METADATA
    # ---------------------------------------------------------
    bin_info = {"name": "unknown", "md5": "unknown", "sha256": "unknown", "arch": "unknown", "is_64": False}
    
    def _sync_metadata():
        import ida_nalt, ida_ida
        bin_info["name"] = idaapi.get_input_file_path() or "unknown"
        bin_info["arch"] = ida_ida.inf_get_procname() or "unknown"
        bin_info["is_64"] = ida_ida.inf_is_64bit()
        
        md5_b = getattr(ida_nalt, 'retrieve_input_file_md5', lambda: b'')()
        sha_b = getattr(ida_nalt, 'retrieve_input_file_sha256', lambda: b'')()
        if md5_b: bin_info["md5"] = md5_b.hex() if isinstance(md5_b, bytes) else str(md5_b)
        if sha_b: bin_info["sha256"] = sha_b.hex() if isinstance(sha_b, bytes) else str(sha_b)

    if idaapi:
        idaapi.execute_sync(_sync_metadata, idaapi.MFF_READ)

    # Calculate Global Threat Intensity
    mal_count = len(malicious_blocks)
    sus_count = len(suspicious_blocks)
    total_custom = len(all_nodes)
    avg_entropy = sum(n.entropy for n in all_nodes) / total_custom if total_custom else 0.0
    
    nb_system = (
        f"=== SYSTEM & BINARY CONTEXT ===\n"
        f"Input Binary: {os.path.basename(bin_info['name'])}\n"
        f"MD5/SHA256: {bin_info['md5']} / {bin_info['sha256']}\n"
        f"Architecture: {bin_info['arch']} ({'64-bit' if bin_info['is_64'] else '32-bit'})\n"
        f"Analysis Scope: {total_custom} custom functions identified.\n"
        f"Threat Density: {mal_count} Malicious, {sus_count} Suspicious, {len(benign_blocks)} Relevant structural markers.\n"
        f"Aggregated Entropy: {avg_entropy:.2f} ({'Potentially Packed/Encrypted' if avg_entropy > 6.5 else 'Standard Code Intensity'})\n"
    )

    # Notebook Section 1: APIs & Strings
    nb_indicators = f"=== STRATEGIC INDICATORS ===\nCATEGORIZED WINAPIS:\n{api_summary_text}\n\nSTRATEGIC STRINGS:\n{str_summary_text}\n"
    
    # Notebook Section 2: Execution Chain & Call Graph
    cg_ascii = get_graph_ascii(graph, entry_ea)
    if cg_ascii:
        cg_lines = cg_ascii.splitlines()
        if len(cg_lines) > 500:
            cg_ascii = "\n".join(cg_lines[:500]) + "\n  ... [TRUNCATED: Call Graph exceeds context limits]"
    else:
        cg_ascii = "  No call graph available."

    nb_dispatch = f"=== EXECUTION DISPATCH & CALL GRAPH ===\nLAYER 1 DISPATCH:\n{chr(10).join(entry_children_blocks) if entry_children_blocks else '  No immediate operational calls identifiable.'}\n\nCALL GRAPH HIERARCHY:\n{cg_ascii}\n"
    
    # Notebook Section 3: Critical Payloads (NEVER TRUNCATED)
    nb_malicious = f"=== CRITICAL MALICIOUS PAYLOADS ===\n{chr(10).join(malicious_blocks) if malicious_blocks else '  No explicitly malicious payload functions discovered.'}\n"
    
    # Notebook Section 4: Suspicious Infrastructure (Bounded)
    sus_list = suspicious_blocks[:55]
    if len(suspicious_blocks) > 55:
         sus_list.append(f"  [... {len(suspicious_blocks)-55} MORE SUSPICIOUS INFRASTRUCTURE FUNCTIONS OMITTED FOR BREVITY ...]")
    nb_suspicious = f"=== SUSPICIOUS INFRASTRUCTURE ===\n{chr(10).join(sus_list) if sus_list else '  No distinct suspicious capability blocks found.'}\n"
    
    # Notebook Section 5: Key Operations
    nb_benign = f"=== STRUCTURAL OPERATIONS OF INTEREST ===\n{chr(10).join(benign_blocks[:25]) if benign_blocks else '  None.'}\n"

    # Calculate MITRE TTPs for the notebook
    # Re-use the data we already built for quality_nodes to identify TTPs
    temp_fd_list = []
    for q in quality_nodes:
        n = q["node"]
        temp_fd_list.append({
            "name": n.name,
            "capabilities": n.preliminary_analysis.get('capabilities', []) if hasattr(n, 'preliminary_analysis') and isinstance(n.preliminary_analysis, dict) else [],
            "semantic_tags": n.semantic_tags if hasattr(n, 'semantic_tags') else []
        })
    
    mitre_techs = _mitre_from_data(temp_fd_list)
    mitre_summary = []
    for tid, tname, funcs in mitre_techs:
        mitre_summary.append(f"  [{tid}] {tname} (Associated Functions: {funcs})")
    
    nb_mitre = f"=== TTP MAPPING (MITRE ATT&CK) ===\n{chr(10).join(mitre_summary) if mitre_summary else '  No distinct TTP patterns identified.'}\n"

    # 6. Extract Suspicious Imports & Modules (Real Binary Fingerprint)
    import_digest = []
    suspicious_libs = {"wininet", "ws2_32", "urlmon", "winhttp", "advapi32", "psapi", "imagehlp", "wtsapi32", "crypt32", "iphlpapi", "shell32", "userenv", "shlwapi", "netapi32", "dnsapi", "mpr", "winscard"}
    
    import_data = {}
    def _collect_imports_sync():
        qty = ida_nalt.get_import_module_qty()
        for i in range(qty):
            lib_name_raw = ida_nalt.get_import_module_name(i)
            if not lib_name_raw: continue
            lib_name_low = lib_name_raw.lower().split('.')[0]
            if lib_name_low in suspicious_libs:
                funcs_found = []
                def _imp_cb(ea, name, ordinal):
                    if name: funcs_found.append(name)
                    return True
                ida_nalt.enum_import_names(i, _imp_cb)
                if funcs_found:
                    import_data[lib_name_raw] = sorted(list(set(funcs_found)))

    if idaapi:
        idaapi.execute_sync(_collect_imports_sync, idaapi.MFF_READ)
    
    for lib, funcs in sorted(import_data.items()):
        func_summary = ", ".join(funcs[:12]) + ("..." if len(funcs) > 12 else "")
        import_digest.append(f"  [{lib}]: {func_summary}")
    
    nb_imports = f"=== SUSPICIOUS IMPORTS & LIBRARIES ===\n{chr(10).join(import_digest) if import_digest else '  No highly suspicious third-party libraries identified in import table.'}\n"

    # ---------------------------------------------------------
    # FINAL NOTEBOOK AGGREGATION
    # ---------------------------------------------------------
    
    full_digest = f"{nb_system}\n{nb_indicators}\n{nb_imports}\n{nb_mitre}\n{nb_dispatch}\n{nb_malicious}\n{nb_suspicious}\n{nb_benign}"

    return full_digest, len(entry_children_blocks), str_digest


def generate_persistence_mechanisms(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Analyze potential persistence mechanisms identified in the code.
Look for: Registry run keys (Run, RunOnce), Service creation (CreateService), Task scheduling (SchTasks), Startup folder manipulation, or DLL hijacking/side-loading logic.

Respond STRICTLY with a valid JSON object:
{{
  "summary": "Technical summary of how the malware ensures it survives reboots.",
  "mechanisms": [
    {{"method": "Method Name (e.g., Registry Run Key)", "details": "Detailed Analysis explanation including keys or file paths used", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_file_registry_interaction(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Analyze how the program interacts with the File System, Registry, and Processes.
Focus on: Creating, deleting, accessing, or injecting into these entities.
Cite specific Analysis details: e.g., which registry keys are created, which files are deleted, or target process names for injection (OpenProcess/CreateRemoteThread).

Respond STRICTLY with a valid JSON object:
{{
  "interactions": [
    {{"type": "File|Registry|Process", "action": "Create|Delete|Access|Inject", "target": "EXACT Path or Name", "description": "Analysis significance of this interaction", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_api_resolving_logic(digest, ai_cfg, log_fn, **kwargs):
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
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)

def generate_recon_infostealer_analysis(digest, ai_cfg, log_fn, **kwargs):
    prompt = f"""Context: {digest}
Analyze Reconnaissance or Information Stealing capabilities (LOCAL Discovery).
Look for: Enumerating local files (.txt, .docx, wallets), stealing browser cookies/passwords, clipboard monitoring, or gathering environment info (ComputerName, UserName, OSVersion, Disk size, CPU info).

Identify what specific Analysis data is being harvested from the host. Do NOT include active C2/Remote control logic here; focus on data theft/collection methods.

Respond STRICTLY with a valid JSON object:
{{
  "summary": "Detailed summary of what local information is being targeted or gathered.",
  "findings": [
    {{"category": "Category (e.g., Browser Data, File Enumeration, System Info)", "description": "Analysis details of what is stolen or captured and how", "associated_functions": ["func_name"]}}
  ]
}}"""
    sys_p = "You are a senior reverse engineer. Respond ONLY with valid JSON."
    return _validated_ai_request(ai_cfg, prompt, sys_prompt=sys_p, logger=log_fn, max_tokens=4096, **kwargs)
