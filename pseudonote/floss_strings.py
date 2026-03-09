import os
import __main__
import builtins
import sys
import ida_kernwin
import idaapi
import idc
import subprocess
import json
import re
import threading
import ctypes
from .qt_compat import QtCore, Signal, QtWidgets, QtGui, Qt
from .config import CONFIG

# --- IDB PERSISTENCE ---
FLOSS_NETNODE_NAME = "$ pseudonote:floss_results"

def save_results_to_idb(results):
    def _do_save():
        try:
            import ida_netnode
            node = ida_netnode.netnode(FLOSS_NETNODE_NAME, 0, True)
            data = json.dumps(results)
            node.setblob(data.encode('utf-8'), 0, ord('F'))
        except Exception as e:
            print(f"FLOSS Viewer: Failed to save results to IDB: {e}")
    ida_kernwin.execute_sync(_do_save, ida_kernwin.MFF_WRITE)

def load_results_from_idb():
    res = [None]
    def _do_load():
        try:
            import ida_netnode
            node = ida_netnode.netnode(FLOSS_NETNODE_NAME, 0, False)
            if node and node != ida_netnode.BADNODE:
                data = node.getblob(0, ord('F'))
                if data:
                    res[0] = json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"FLOSS Viewer: Failed to load results from IDB: {e}")
    ida_kernwin.execute_sync(_do_load, ida_kernwin.MFF_READ)
    return res[0]

# --- ROBUST SHIBOKEN DISCOVERY FOR IDA 9.3 ---
def _find_shiboken():
    # 1. Search sys.modules (best for already-loaded IDA environment)
    for name, mod in sys.modules.items():
        if mod is None or not isinstance(name, str): continue
        if 'shiboken' in name.lower():
            if hasattr(mod, 'wrapInstance'): return mod
            if hasattr(mod, 'shiboken') and hasattr(mod.shiboken, 'wrapInstance'): return mod.shiboken
    
    # 2. Try explicit names (priority on PySide6)
    for name in ['shiboken6', 'shiboken2', 'shiboken']:
        try:
            m = __import__(name)
            if hasattr(m, 'wrapInstance'): return m
            if hasattr(m, 'shiboken') and hasattr(m.shiboken, 'wrapInstance'): return m.shiboken
        except: continue
    return None

shiboken = _find_shiboken()

# Inject into all possible namespaces to satisfy IDA's internal C++ evaluations
for mod_name in ['shiboken', 'Shiboken']:
    if shiboken:
        globals()[mod_name] = shiboken
        setattr(builtins, mod_name, shiboken)
        setattr(__main__, mod_name, shiboken)

# Ensure Qt modules are also visible to IDA's bridge
for mod_name, mod in [('QtCore', QtCore), ('QtWidgets', QtWidgets), ('QtGui', QtGui)]:
    if mod:
        setattr(builtins, mod_name, mod)
        setattr(__main__, mod_name, mod)

# Final Bridge Shim for QWidget.FromCapsule (IDA 9.3 specific)
if QtGui:
    if not hasattr(QtGui, 'QWidget') or not hasattr(getattr(QtGui, 'QWidget', object), 'FromCapsule'):
        class QWidgetShim(QtWidgets.QWidget):
            @staticmethod
            def FromCapsule(tw):
                if not shiboken or not hasattr(shiboken, 'wrapInstance'):
                    return None
                
                # IDA 9.3/PySide6 specific: convert PyCapsule to raw pointer address (int)
                ptr = tw
                if str(type(tw)).find('PyCapsule') != -1:
                    try:
                        # IDA uses b'$valid$' for its capsules
                        ctypes.pythonapi.PyCapsule_GetPointer.restype = ctypes.c_void_p
                        ctypes.pythonapi.PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
                        
                        # Try with IDA's default name first
                        ptr = ctypes.pythonapi.PyCapsule_GetPointer(tw, b'$valid$')
                        if not ptr:
                            # Fallback to None (unnamed)
                            ptr = ctypes.pythonapi.PyCapsule_GetPointer(tw, None)
                    except Exception:
                        # Final resort: if it's a capsule but we can't get pointer, let wrapInstance try it directly
                        ptr = tw
                
                try:
                    return shiboken.wrapInstance(ptr, QtWidgets.QWidget)
                except Exception as e:
                    # Final attempt: try with original 'tw' in case wrapInstance was updated
                    try:
                        return shiboken.wrapInstance(tw, QtWidgets.QWidget)
                    except Exception:
                        print(f"FLOSS Viewer: Failed to wrap widget: {e}")
                        return None
        
        # Patch QtGui with the shim if it's missing or broken
        if not hasattr(QtGui, 'QWidget'):
            QtGui.QWidget = QWidgetShim
        else:
            try:
                QtGui.QWidget.FromCapsule = QWidgetShim.FromCapsule
            except:
                # If QWidget is read-only, we swap the class out
                QtGui.QWidget = QWidgetShim

# Global reference to prevent UI garbage collection
floss_strings_chooser = None
floss_thread = None

class FlossStringsChooser(ida_kernwin.Choose):
    def __init__(self, title, items, embedded=False):
        # In newer IDA versions, these constants are global in ida_kernwin
        flags = getattr(ida_kernwin, "CH_KEEP", 0)
        if embedded:
            flags |= getattr(ida_kernwin, "CH_EMBEDDED", 0x400)
            
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 10 | getattr(ida_kernwin, "CHCOL_HEX", 0x2)],
                ["Type", 10],
                ["String", 50],
            ],
            flags=flags,
            embedded=embedded
        )
        self.items = items

    def OnGetLine(self, n):
        item = self.items[n]
        return [hex(item[0]), item[2], item[1]]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n][0])

    def OnRefresh(self, n):
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

class FlossTabbedViewer(ida_kernwin.PluginForm):
    def __init__(self, results):
        super(FlossTabbedViewer, self).__init__()
        self.results = results
        self.title = "FLOSS Strings Viewer"
        self.choosers = []

    def OnCreate(self, form):
        try:
            parent = self.FormToPySideWidget(form)
            if not parent:
                print("FLOSS Viewer: Failed to get parent widget from form")
                return
                
            self.main_layout = QtWidgets.QVBoxLayout(parent)
            self.tabs = QtWidgets.QTabWidget()
            
            print(f"FLOSS Viewer: Creating tabs for {len(self.results)} results...")
            
            # Categorize results
            categories = ["ASCII", "Unicode", "Stack", "Tight", "Decoded"]
            tabs_added = 0
            for cat in categories:
                cat_items = [item for item in self.results if item[2] == cat]
                # Always show ASCII/Unicode tabs even if empty, others only if they have data
                if not cat_items and cat not in ["ASCII", "Unicode"]:
                    continue
                
                # Sort by address for each tab
                cat_items = sorted(cat_items, key=lambda x: x[0])
                
                chooser = FlossStringsChooser(f"FLOSS {cat}", cat_items, embedded=True)
                self.choosers.append(chooser) # Keep reference
                
                ret = chooser.Embedded()
                if ret == 0:
                    widget_raw = chooser.GetWidget()
                    widget = self.FormToPySideWidget(widget_raw)
                    if widget:
                        self.tabs.addTab(widget, f"FLOSS {cat} ({len(cat_items)})")
                        tabs_added += 1
                    else:
                        print(f"FLOSS Viewer: Failed to convert chooser widget for {cat}")
                else:
                    print(f"FLOSS Viewer: Failed to embed chooser for {cat} (error {ret})")
            
            self.main_layout.addWidget(self.tabs)
            parent.setLayout(self.main_layout)
            print(f"FLOSS Viewer: UI created with {tabs_added} tabs.")
        except Exception as e:
            print(f"FLOSS Viewer: Error in OnCreate: {e}")
            import traceback
            traceback.print_exc()

    def Show(self):
        return super(FlossTabbedViewer, self).Show(self.title, options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_RESTORE | ida_kernwin.PluginForm.WOPN_PERSIST)

class FlossWorker(QtCore.QThread):
    finished_signal = QtCore.Signal(str) # Pass results as JSON string to avoid OverflowError
    error_signal = QtCore.Signal(str)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            startupinfo = None
            if hasattr(subprocess, 'STARTUPINFO'):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 0)
            
            proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
            stdout, stderr = proc.communicate()
            
            if proc.returncode != 0:
                err_msg = stderr.decode('utf-8', 'ignore') if isinstance(stderr, bytes) else str(stderr)
                self.error_signal.emit(err_msg)
                return

            out_str = stdout.decode('utf-8', 'ignore') if isinstance(stdout, bytes) else str(stdout)
            data = json.loads(out_str)
            raw_entries = []
            
            # Ultra-robust recursive search: find ANY dictionary with a "string" key
            def find_anything_with_string(obj, parent_key=""):
                if isinstance(obj, dict):
                    if "string" in obj:
                        item = obj.copy()
                        item["_parent_key"] = parent_key
                        raw_entries.append(item)
                    for k, v in obj.items():
                        find_anything_with_string(v, k)
                elif isinstance(obj, list):
                    for item in obj:
                        find_anything_with_string(item, parent_key)

            find_anything_with_string(data)
            self.finished_signal.emit(json.dumps(raw_entries))
        except Exception as e:
            self.error_signal.emit(str(e))

def on_floss_finished(results_json):
    # CRITICAL: Move processing to the main thread immediately.
    # We use a wrapper to ensure all UI and IDA API calls happen safely.
    def _main_thread_handler():
        try:
            raw_entries = json.loads(results_json)
            ida_kernwin.msg("FLOSS scanning finished.\n")
            
            if not raw_entries:
                ida_kernwin.msg("No strings found by FLOSS in the JSON output.\n")
                return

            results = []
            counts = {"ASCII": 0, "Unicode": 0, "Stack": 0, "Tight": 0, "Decoded": 0}
            failed_to_map = 0
            
            for entry in raw_entries:
                s_val = entry.get("string", "")
                if not s_val: continue
                
                parent_key = entry.get("_parent_key", "").lower()
                base_cat = "Static"
                if "stack" in parent_key: base_cat = "Stack"
                elif "tight" in parent_key: base_cat = "Tight"
                elif "decoded" in parent_key: base_cat = "Decoded"

                final_ea = 0
                instances = entry.get("instances", [])
                if instances and isinstance(instances, list):
                    for inst in instances:
                        if not isinstance(inst, dict): continue
                        for k in ["location", "va", "address"]:
                            ea = inst.get(k, 0)
                            if ea and idaapi.is_mapped(ea):
                                final_ea = ea; break
                        if final_ea: break
                
                if not final_ea:
                    for k in ["va", "address", "location", "function", "decoding_routine"]:
                        ea = entry.get(k, 0)
                        if ea and idaapi.is_mapped(ea):
                            final_ea = ea; break
                
                if not final_ea:
                    offset = entry.get("offset", 0)
                    if offset:
                        ea = idaapi.get_fileregion_ea(offset)
                        if ea != idaapi.BADADDR and idaapi.is_mapped(ea):
                            final_ea = ea

                if final_ea:
                    label = base_cat
                    if label == "Static":
                        enc = entry.get("encoding", "").upper()
                        label = "Unicode" if ("UTF-16" in enc or "UNICODE" in enc) else "ASCII"
                    
                    if label in ["ASCII", "Unicode"]:
                        if len(s_val) < 4: continue
                        
                        noise_patterns = [
                            r'^[a-zA-Z\\\|]\$[0-9A-Za-z@`]{1,3}$',
                            r'^[a-zA-Z]\$[0-9A-Za-z]{1,3}[A-Z]?$',
                            r'^(AVH|TAVH|VATAVH|VATH|AVD|AV|SVWH|UVWH|SUVWH|A\^A\\A_)$',
                            r'^(A_A\^A\]A\\_|HA\\A\^|HA\\_\^|\^A\^|_\^|\[|\])$',
                            r'^[A-Z_\^\[\]\\]{4,}$',
                            r'^[DTL]\$[0-9A-Za-z]{1,4}$',
                            r'^(U{3,}|f{4,}|A{3,}|_{3,}|\*{3,}|\.{3,}|>{3,})$',
                            r"^[A-Za-z]'[HI];$",
                            r'^[0-9A-Fa-f]{1,2}$',
                            r'^[A-Za-z@\$\\]$',
                            r'^\([a-z]\$[0-9]{1,3}\)$',
                            r'^[\+\-\*/\)][>\<][0-9A-Za-z]{1,3}$',
                            r'^[#=:][A-Za-z]{1,3}[\?]?$',
                            r'^\\t+$',
                            r'^\s+$',
                            r'^[@#\$%\^&\*\(\)\[\]\{\}\\\/\|~`]$',
                            r'^\d+\.\d{10,}$',
                            r'^0x[0-9A-Fa-f]{1,4}$',
                            r'^\.[a-z]+\$[a-z0-9]*$',
                        ]
                        
                        is_noise = False
                        for p in noise_patterns:
                            if re.search(p, s_val):
                                is_noise = True
                                break
                        if is_noise: continue

                        seg = idaapi.getseg(final_ea)
                        if seg:
                            seg_name = idaapi.get_segm_name(seg).lower()
                            if "text" in seg_name or "code" in seg_name:
                                symbol_count = sum(1 for c in s_val if not c.isalnum() and not c.isspace())
                                if symbol_count / len(s_val) > 0.3 or len(s_val) < 10:
                                    continue
                        
                        if sum(1 for c in s_val if not (32 <= ord(c) <= 126)) / len(s_val) > 0.1:
                            continue

                    if label in counts: counts[label] += 1
                    results.append((final_ea, s_val, label))
                else:
                    failed_to_map += 1

            summary_parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
            if summary_parts:
                ida_kernwin.msg(f"Mapped to IDA: {', '.join(summary_parts)}\n")
            
            if failed_to_map > 0:
                ida_kernwin.msg(f"Note: {failed_to_map} strings found in JSON could not be mapped to binary segments.\n")

            if not results:
                ida_kernwin.msg("FLOSS found results, but none could be mapped to your current segments.\n")
                return

            seen = set()
            unique_results = []
            for ea, s, t in results:
                if (ea, s) not in seen:
                    unique_results.append((ea, s, t))
                    seen.add((ea, s))
            results = sorted(unique_results, key=lambda x: x[0])

            # Save to IDB for persistence
            save_results_to_idb(results)

            global floss_strings_chooser
            floss_strings_chooser = FlossTabbedViewer(results)
            floss_strings_chooser.Show()
        except Exception as e:
            ida_kernwin.msg(f"Error in FLOSS finish handler: {str(e)}\n")

    ida_kernwin.execute_sync(_main_thread_handler, ida_kernwin.MFF_WRITE)

def on_floss_error(err):
    ida_kernwin.msg(f"FLOSS failed with error: {err}\n")

def show_floss_strings_ui():
    # Check for existing results in IDB first
    cached_results = load_results_from_idb()
    if cached_results:
        choice = ida_kernwin.ask_buttons("Reload Results", "New Scan", "Cancel", 1, "Cached FLOSS results ({} strings) found in IDB.\nWould you like to reload them or start a fresh scan?".format(len(cached_results)))
        if choice == 1: # Reload
            global floss_strings_chooser
            floss_strings_chooser = FlossTabbedViewer(cached_results)
            floss_strings_chooser.Show()
            return
        elif choice == -1 or choice == 0: # Cancel or Close
            return
        # If choice == 0 (New Scan), continue below

    # Handle cross-platform binary names
    is_windows = os.name == 'nt' or sys.platform.startswith('win')
    ext = ".exe" if is_windows else ""
    binary_name = f"floss{ext}"

    floss_path = CONFIG.floss_path
    if not floss_path or not os.path.exists(floss_path):
        ida_kernwin.msg(f"Can't found the FLOSS binary. Please select {binary_name}.\n")
        floss_path = ida_kernwin.ask_file(0, binary_name, f"Locate FLOSS binary ({binary_name}). Download from https://github.com/mandiant/flare-floss/releases")
        if not floss_path or not os.path.exists(floss_path):
            ida_kernwin.msg("Can't found the FLOSS binary. Operation cancelled.\n")
            return
        CONFIG.floss_path = floss_path
        CONFIG.save()

    # Try to find the original binary
    input_file = idc.get_input_file_path()
    if not input_file or not os.path.exists(input_file):
        # Fallback to IDB based discovery
        idb_path = idc.get_idb_path()
        if idb_path:
            base_name = os.path.splitext(idb_path)[0]
            for ext in ["", ".exe", ".dll", ".sys", ".bin"]:
                p = base_name + ext
                if os.path.exists(p):
                    input_file = p; break

    if not input_file or not os.path.exists(input_file):
        ida_kernwin.msg("Could not automatically locate the binary. Please select the file you are analyzing.\n")
        input_file = ida_kernwin.ask_file(0, "*.*", "Select Binary for FLOSS Scan")
        if not input_file or not os.path.exists(input_file): return
        
    cmd = [floss_path, "-j", "--", input_file]
    
    global floss_thread
    floss_thread = FlossWorker(cmd)
    floss_thread.finished_signal.connect(on_floss_finished)
    floss_thread.error_signal.connect(on_floss_error)
    
    ida_kernwin.msg("Starting FLOSS in background....\n")
    floss_thread.start()

if __name__ == "__main__":
    show_floss_strings_ui()
