# -*- coding: utf-8 -*-
"""
Agentic Malware Reverse Engineering module for PseudoNote.
Allows an AI agent to autonomously investigate a function by running tools.
"""

import re
import json
import html

import idaapi
import ida_kernwin
import ida_hexrays
import ida_bytes
import idc
import idautils
import sys
import io
import json

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui
import pseudonote.ai_client as _ai_mod
import pseudonote.idb_storage as _idb_mod
from pseudonote.idb_storage import save_to_idb, load_from_idb
from pseudonote.chat import ChatBubble, ChatInput, get_ida_colors, get_chat_font, markdown_to_html
from pseudonote.renamer import count_sub_calls_fast, is_valid_seg, is_sys_func

AGENTIC_HISTORY_TAG = 101

# Tool implementations for the Agent
def tool_decompile(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
        return "Error: Could not decompile function."
    except Exception as e:
        return f"Error decompiling: {e}"

def tool_get_xrefs(ea):
    callers = []
    for ref in idautils.CodeRefsTo(ea, 0):
        name = idc.get_func_name(ref) or f"sub_{ref:X}"
        callers.append(f"{name} (0x{ref:X})")
    
    callees = []
    for ref in idautils.CodeRefsFrom(ea, 0):
        name = idc.get_func_name(ref) or f"sub_{ref:X}"
        callees.append(f"{name} (0x{ref:X})")
    
    res = []
    if callers:
        res.append(f"Callers:\n- " + "\n- ".join(set(callers)))
    else:
        res.append("Callers: None")
        
    if callees:
        res.append(f"Callees:\n- " + "\n- ".join(set(callees)))
    else:
        res.append("Callees: None")
        
    return "\n\n".join(res)

def tool_rename_func(ea, new_name):
    from pseudonote.renamer import clean_name
    old_name = idc.get_func_name(ea)
    safe_name = clean_name(new_name, ea=ea)
    if idc.set_name(ea, safe_name, idc.SN_AUTO):
        save_to_idb(ea, "renamed_by_agent", tag=83)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Renamed '{old_name}' to '{safe_name}'"
    return f"Error: Failed to rename to '{safe_name}'"

def tool_rename_vars(ea, renames_dict):
    try:
        from pseudonote.var_renamer import apply_var_renames
        applied, failed, _ = apply_var_renames(ea, renames_dict, log_fn=None)
        if applied > 0:
            save_to_idb(ea, "variables_renamed_agent", tag=86)
            idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: {applied} variables renamed, {failed} failed."
    except Exception as e:
        return f"Error applying variable renames: {e}"

def tool_add_comment(ea, comment_text):
    try:
        current = idc.get_func_cmt(ea, 0)
        new_comment = comment_text if not current else current + "\n" + comment_text
        idc.set_func_cmt(ea, new_comment, 0)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return "Success: Comment added to function."
    except Exception as e:
        return f"Error adding comment: {e}"

def tool_analyze_subfunction(ea):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return f"Pseudocode for subfunction at 0x{ea:X}:\n```c\n{str(cfunc)}\n```"
        return f"Error: Could not decompile subfunction at 0x{ea:X}."
    except Exception as e:
        return f"Error decompiling subfunction: {e}"

def tool_create_apply_struct(name, fields_json):
    try:
        # Fallback for IDA 9+ where ida_struct is removed and replaced by ida_typeinf
        try:
            import ida_struct
            tid = ida_struct.add_struc(idaapi.BADADDR, name)
        except ImportError:
            # IDA 9.0+ 
            import ida_typeinf
            # Creating structs in IDA 9 is complex and requires UDTs
            return f"Error: Struct creation not fully supported in IDA 9 via this tool. Please define via Local Types."

        if tid == idaapi.BADADDR:
            return f"Error: Could not create struct '{name}' (may already exist)."
        
        sptr = ida_struct.get_struc(tid)
        if not sptr: return "Error: Could not get struct pointer."
        
        # Basic parsing, expect list of dicts: [{"name": "field1", "type": "DWORD", "size": 4}]
        # Simplified creation for demonstration
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Created struct '{name}'. (Note: full field population requires complex IDAPython typing APIs, stubbed for safety)."
    except Exception as e:
        return f"Error creating struct: {e}"

def tool_query_threat_intel(indicator):
    return f"Threat Intel (Simulated VT Result):\nIndicator `{indicator}` has 0 detections (clean). Note: Configure VirusTotal API key in settings for real results."

def tool_read_memory(ea, size=32):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        data = ida_bytes.get_bytes(ea, size)
        if not data: return f"Error: Could not read {size} bytes at 0x{ea:X}."
        
        # Format as standard hex dump
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{ea+i:08X}: {hex_part:<48} | {ascii_part}")
            
        return "Memory Dump:\n```\n" + "\n".join(lines) + "\n```"
    except Exception as e:
        return f"Error reading memory: {e}"

def tool_patch_bytes(ea, hex_string):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        # Clean hex string
        hex_string = hex_string.replace(" ", "").replace("\\x", "")
        patch_data = bytes.fromhex(hex_string)
        
        # User Safety Check
        res = [False]
        def _ask_patch():
            orig_data = ida_bytes.get_bytes(ea, len(patch_data))
            if not orig_data: orig_data = b""
            orig_hex = " ".join(f"{b:02X}" for b in orig_data)
            new_hex = " ".join(f"{b:02X}" for b in patch_data)
            
            prompt = (
                f"Agent wants to patch binary at 0x{ea:X}:\n\n"
                f"Original: {orig_hex}\n"
                f"New:      {new_hex}\n\n"
                f"Allow patch?"
            )
            # 1 = Yes, 0 = No, -1 = Cancel
            res[0] = ida_kernwin.ask_yn(1, prompt) == 1
            
        ida_kernwin.execute_sync(_ask_patch, ida_kernwin.MFF_READ)
        if not res[0]:
            return "Error: User denied the patch request."
        
        ida_bytes.patch_bytes(ea, patch_data)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Patched {len(patch_data)} bytes at 0x{ea:X}."
    except Exception as e:
        return f"Error patching bytes: {e}"

def tool_save_finding(key, value):
    try:
        _idb_mod.agent_save_finding(key, value)
        return f"Success: Saved finding for '{key}'."
    except Exception as e:
        return f"Error saving finding: {e}"

def tool_search_findings(query):
    try:
        return _idb_mod.agent_search_findings(query)
    except Exception as e:
        return f"Error searching findings: {e}"

def tool_get_vtable_ptrs(ea, count=10):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
        
        ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
        
        results = []
        for i in range(count):
            curr_ea = ea + (i * ptr_size)
            if ptr_size == 8:
                ptr_val = idc.get_qword(curr_ea)
            else:
                ptr_val = idc.get_dword(curr_ea)
                
            name = idc.get_func_name(ptr_val)
            if name:
                results.append(f"+0x{i*ptr_size:X} -> 0x{ptr_val:X} ({name})")
            else:
                results.append(f"+0x{i*ptr_size:X} -> 0x{ptr_val:X}")
                
        return "VTable/Pointer Array:\n" + "\n".join(results)
    except Exception as e:
        return f"Error reading pointers: {e}"

def tool_set_func_type(ea, signature):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        res = idc.SetType(ea, signature)
        if res:
            idaapi.request_refresh(idaapi.IWID_DISASM)
            return f"Success: Set function signature to '{signature}' at 0x{ea:X}."
        else:
            return f"Error: Failed to apply signature '{signature}'. Ensure it is valid C syntax."
    except Exception as e:
        return f"Error setting function type: {e}"

def tool_execute_idapython(script):
    try:
        # User Safety Check
        res = [False]
        def _ask_exec():
            prompt = (
                f"Agent wants to execute the following IDAPython script:\n\n"
                f"{script}\n\n"
                f"Allow execution?"
            )
            res[0] = ida_kernwin.ask_yn(0, prompt) == 1
            
        ida_kernwin.execute_sync(_ask_exec, ida_kernwin.MFF_READ)
        if not res[0]:
            return "Error: User denied script execution."
            
        old_stdout = sys.stdout
        sys.stdout = mystdout = io.StringIO()
        
        # We execute in a new dictionary to avoid polluting globals
        exec_globals = {"idaapi": idaapi, "idc": idc, "idautils": idautils, "ida_hexrays": ida_hexrays}
        exec(script, exec_globals)
        
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        if not output: return "Success: Script executed with no output."
        return f"Script Output:\n{output}"
    except Exception as e:
        sys.stdout = old_stdout
        return f"Error executing script:\n{e}"

def tool_jump_to_address(ea):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
        
        def _do_jump():
            ida_kernwin.jumpto(ea)
        
        # safely execute UI request
        def wrapper():
            try:
                _do_jump()
            except: pass
            return False
        
        try:
            ida_kernwin.execute_ui_requests((wrapper,))
            return f"Success: Jumped IDA View to 0x{ea:X}"
        except:
            ida_kernwin.execute_sync(_do_jump, ida_kernwin.MFF_WRITE)
            return f"Success: Jumped IDA View to 0x{ea:X}"
    except Exception as e:
        return f"Error jumping to address: {e}"

# UI and Agentic Loop
class AgenticForm(ida_kernwin.PluginForm):
    def __init__(self, address, function_name):
        super(AgenticForm, self).__init__()
        self.address = address
        self.function_name = function_name
        self.system_prompt = {
            "role": "system",
            "content": (
                f"You are an autonomous Malware Reverse Engineering Agent analyzing `{function_name}` at `0x{address:X}`.\n"
                "You have access to the following tools:\n"
                "1. `decompile`: Returns C pseudocode for the current function.\n"
                "2. `get_xrefs`: Returns cross-references (callers/callees) for the current function.\n"
                "3. `rename_func`: Renames the current function. Arg: `new_name` (string).\n"
                "4. `rename_vars`: Renames variables. Arg: `renames` (dict mapping old name to new name).\n"
                "5. `add_comment`: Adds a comment to the function. Arg: `text` (string).\n"
                "6. `analyze_subfunction`: Decompiles a target callee function. Arg: `ea` (integer or hex string).\n"
                "8. `create_apply_struct`: Creates a struct type. Args: `name` (string), `fields_json` (string).\n"
                "9. `query_threat_intel`: Queries VT for an IOC. Arg: `indicator` (string).\n"
                "10. `get_vtable_ptrs`: Reads pointers from an address (e.g., vtable). Args: `ea` (int/hex str), `count` (int, default 10).\n"
                "12. `read_memory`: Reads memory and returns a hex dump. Args: `ea` (int/hex str), `size` (int, default 32).\n"
                "13. `patch_bytes`: Patches memory. Args: `ea` (int/hex str), `hex_string` (str, e.g. \"90 90\"). USER WILL BE PROMPTED.\n"
                "14. `save_finding`: Save data to global IDB memory for later use. Args: `key` (str), `value` (str).\n"
                "15. `search_findings`: Search global IDB memory. Arg: `query` (str).\n"
                "16. `execute_idapython`: Executes raw IDAPython code and returns stdout. Arg: `script` (string). USER WILL BE PROMPTED.\n"
                "17. `jump_to_address`: Moves the IDA UI to a specific address. Arg: `ea` (int/hex str).\n\n"
                "To use a tool, respond with ONLY a JSON block containing `tool` and `args`.\n"
                "IMPORTANT: JSON requires numbers to be base-10. For addresses/hex values, pass them as STRINGS (e.g. `\"0x10010798\"`).\n"
                "Example:\n"
                "```json\n"
                "{\"tool\": \"decompile\", \"args\": {}}\n"
                "```\n\n"
                "CRITICAL INSTRUCTION: If you spot a subfunction that appears to contain the core malicious logic, payload, or decryption routines, you MUST use `analyze_subfunction` to dive deeply into it. When you provide your final analysis, you MUST include a detailed, step-by-step breakdown of what those subfunctions do, including specific variables and decompiled logic. Do not just give a high-level summary!\n\n"
                "If you have fully exhausted the analysis of the main logic and subfunctions, respond with your normal text (no JSON tool call) to provide a final analysis. "
                "Always start by decompiling the function."
            )
        }
        self.history = [self.system_prompt]
        self.is_running = False
        self.is_paused = False
        self.error_count = 0

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.setup_ui()
        # self.start_agent() no longer auto-starts

    def setup_ui(self):
        colors = get_ida_colors()
        self.parent.setStyleSheet(f"background-color: {colors['window']};")
        
        btn_style = f"""
        QPushButton {{ 
            background-color: {colors['button']}; 
            color: {colors['button_text']}; 
            border: 1px solid {colors['mid']}; 
            padding: 4px 10px; 
            border-radius: 3px; 
            font-weight: bold; 
            font-family: {get_chat_font().family()}; 
            font-size: 11px; 
        }}
        QPushButton:disabled {{
            color: gray;
        }}
        """
        
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']};")
        header_vbox = QtWidgets.QVBoxLayout(header)
        header_vbox.setContentsMargins(20, 10, 20, 10)
        
        header_hbox = QtWidgets.QHBoxLayout()
        self.title_label = QtWidgets.QLabel(f'<span style="font-size: 13px; color: {colors["window_text"]};">Agentic Analysis: </span><b style="font-size: 14px; color: {colors["highlight"]}; font-family: monospace;">{self.function_name}</b>')
        header_hbox.addWidget(self.title_label)
        header_hbox.addStretch()
        
        self.btn_kb = QtWidgets.QPushButton("🧠 View Knowledge Base")
        self.btn_kb.setStyleSheet(btn_style)
        self.btn_kb.clicked.connect(self.on_view_kb)
        header_hbox.addWidget(self.btn_kb)
        
        header_vbox.addLayout(header_hbox)
        layout.addWidget(header)

        # Chat History
        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll.setStyleSheet("background: transparent;")
        
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(5, 5, 5, 5)
        self.scroll_layout.addStretch()
        
        self.scroll.setWidget(self.scroll_content)
        layout.addWidget(self.scroll, stretch=1)

        # Chat Input
        self.chat_input = ChatInput()
        self.chat_input.input_box.setPlaceholderText("Steer the agent... (e.g. 'Focus on the loop at 0x401000')")
        self.chat_input.submitted.connect(self.on_user_chat)
        layout.addWidget(self.chat_input)

        # Controls and Typing Indicator
        self.controls_container = QtWidgets.QFrame()
        self.controls_container.setMinimumHeight(40)
        self.controls_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        controls_layout = QtWidgets.QHBoxLayout(self.controls_container)
        controls_layout.setContentsMargins(10, 5, 10, 5)
        
        self.btn_start = QtWidgets.QPushButton("▶ Auto-Pilot Bulk Analyze")
        self.btn_start.setStyleSheet(btn_style)
        self.btn_start.clicked.connect(self.on_start_autopilot)
        controls_layout.addWidget(self.btn_start)
        
        self.btn_pause = QtWidgets.QPushButton("⏸ Pause")
        self.btn_pause.setStyleSheet(btn_style)
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_pause.setEnabled(False)
        controls_layout.addWidget(self.btn_pause)
        
        self.btn_continue = QtWidgets.QPushButton("⏭ Continue")
        self.btn_continue.setStyleSheet(btn_style)
        self.btn_continue.clicked.connect(self.on_continue)
        self.btn_continue.setEnabled(False)
        controls_layout.addWidget(self.btn_continue)
        
        controls_layout.addStretch()
        
        self.typing_indicator = QtWidgets.QLabel("Agent is thinking...")
        self.typing_indicator.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-weight: bold; font-size: 11px;")
        self.typing_indicator.setVisible(False)
        controls_layout.addWidget(self.typing_indicator)
        
        layout.addWidget(self.controls_container)

    def on_view_kb(self):
        res = _idb_mod.agent_search_findings("")
        QtWidgets.QMessageBox.information(self.parent, "Agent Knowledge Base", res)

    def on_user_chat(self, text):
        text = text.strip()
        if not text: return
        
        self.add_message(text, is_user=True)
        self.history.append({"role": "user", "content": text})
        
        # Resume or start loop
        if not self.is_running or getattr(self, 'is_paused', False):
            self.is_running = True
            self.is_paused = False
            self.btn_start.setEnabled(False)
            self.btn_pause.setEnabled(True)
            self.btn_continue.setEnabled(False)
            self.run_loop()

    def add_message(self, text, is_user=False):
        bubble = ChatBubble(text, is_user)
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def on_start_autopilot(self):
        # Clear chat history visually
        self.history = []
        self.error_count = 0
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_continue.setEnabled(False)
        self.chat_input.setEnabled(False)
        self.is_running = True
        self.is_paused = False
        self.add_message("▶ Auto-Pilot Bulk Analysis started. Scanning binary...", is_user=False)
        self.typing_indicator.setText("Scanning functions...")
        self.typing_indicator.setVisible(True)
        
        # Build the queue
        self.active_queue = []
        self.blocked_queue = []
        self.processed_eas = set()
        self.markdown_report = "# Full Binary Analysis Report\n\n"
        
        def _scan():
            for ea in idautils.Functions():
                if not is_valid_seg(ea) or is_sys_func(idc.get_func_name(ea)): continue
                sub_count = count_sub_calls_fast(ea)
                if sub_count == 0:
                    self.active_queue.append(ea)
                else:
                    self.blocked_queue.append(ea)
        
        ida_kernwin.execute_sync(_scan, ida_kernwin.MFF_READ)
        
        self.add_message(f"Found {len(self.active_queue)} leaf functions and {len(self.blocked_queue)} blocked functions.", is_user=False)
        
        # Start processing
        QtCore.QTimer.singleShot(100, self.run_autopilot_loop)

    def on_pause(self):
        self.is_paused = True
        self.btn_pause.setEnabled(False)
        self.btn_continue.setEnabled(True)
        self.add_message("⏸ Agent paused. It will stop after the current thought completes.", is_user=False)
        
    def on_continue(self):
        self.is_paused = False
        self.btn_pause.setEnabled(True)
        self.btn_continue.setEnabled(False)
        self.add_message("⏭ Auto-Pilot continuing...", is_user=False)
        self.typing_indicator.setText("Agent is thinking...")
        self.run_autopilot_loop()

    def run_autopilot_loop(self):
        if not self.is_running or getattr(self, 'is_paused', False):
            return

        # Refill active queue if empty
        if not self.active_queue:
            new_blocked = []
            moved = 0
            def _check_blocked():
                nonlocal moved
                for ea in self.blocked_queue:
                    if count_sub_calls_fast(ea) == 0:
                        self.active_queue.append(ea)
                        moved += 1
                    else:
                        new_blocked.append(ea)
            ida_kernwin.execute_sync(_check_blocked, ida_kernwin.MFF_READ)
            self.blocked_queue = new_blocked
            
            if moved > 0:
                self.add_message(f"Moved {moved} functions from blocked to active queue.", is_user=False)
            elif self.blocked_queue:
                # Cycle detected or functions that call unnamed things that couldn't be renamed
                self.add_message(f"Force-moving {len(self.blocked_queue)} blocked functions to active queue to finish.", is_user=False)
                self.active_queue.extend(self.blocked_queue)
                self.blocked_queue = []

        if not self.active_queue:
            # We are completely done!
            self.is_running = False
            self.typing_indicator.setVisible(False)
            self.btn_start.setEnabled(True)
            self.add_message("✅ Auto-Pilot Bulk Analysis Complete!", is_user=False)
            self._save_markdown_report()
            return

        self.current_ea = self.active_queue.pop(0)
        self.processed_eas.add(self.current_ea)
        
        cfunc_str = None
        func_name = None
        def _get_code():
            nonlocal cfunc_str, func_name
            func_name = idc.get_func_name(self.current_ea)
            try:
                cf = ida_hexrays.decompile(self.current_ea)
                if cf: cfunc_str = str(cf)
            except: pass
        ida_kernwin.execute_sync(_get_code, ida_kernwin.MFF_READ)

        if not cfunc_str:
            self.add_message(f"⚠️ Skipping 0x{self.current_ea:X}: Could not decompile.", is_user=False)
            QtCore.QTimer.singleShot(50, self.run_autopilot_loop)
            return

        prompt = (
            "You are an expert reverse engineer analyzing a malware binary. Analyze the following C pseudocode.\n"
            "You MUST reply with ONLY a valid JSON object matching this schema exactly:\n"
            "{\n"
            "  \"function_name\": \"suggested_snake_case_name\",\n"
            "  \"variables\": {\n"
            "     \"v1\": \"new_var_name\",\n"
            "     \"a1\": \"new_arg_name\"\n"
            "  },\n"
            "  \"comments\": \"High-level summary of what the function does.\"\n"
            "}\n"
            "If you cannot determine a better name, return the original function name. DO NOT invent purposes. "
            "Keep variable names concise (e.g. 'key', 'index', 'buffer').\n\n"
            f"Original Function Name: {func_name}\n"
            f"Pseudocode:\n```c\n{cfunc_str}\n```"
        )
        
        self.typing_indicator.setVisible(True)
        self.typing_indicator.setText(f"Analyzing {func_name} (0x{self.current_ea:X})...")
        
        # We don't stream to chat to avoid UI lag for batch jobs, just a simple status
        def _autopilot_response(response, **kwargs):
            if not response:
                is_throttle = kwargs.get("is_throttle", False)
                err_msg = kwargs.get("error_msg", "Unknown error")
                if is_throttle:
                    self.add_message(f"⚠️ API Rate Limit (429) hit: {err_msg[:100]}...\\nPausing for 4 minutes before auto-continuing...", is_user=False)
                    self.is_paused = True
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(True)
                    
                    self.throttle_remaining = 240 # 4 minutes
                    self.typing_indicator.setVisible(True)
                    
                    # Push the failed EA back to the front of the queue so it gets retried
                    self.active_queue.insert(0, self.current_ea)
                    
                    def update_countdown():
                        if not getattr(self, 'is_paused', False) or getattr(self, 'throttle_remaining', 0) <= 0:
                            self.typing_indicator.setText("Agent is thinking...")
                            self.typing_indicator.setVisible(False)
                            if getattr(self, 'throttle_remaining', 0) <= 0 and getattr(self, 'is_paused', False):
                                self.on_continue()
                            return
                            
                        mins, secs = divmod(self.throttle_remaining, 60)
                        self.typing_indicator.setText(f"API Rate Limited. Auto-continuing in {mins}m {secs}s...")
                        self.throttle_remaining -= 1
                        QtCore.QTimer.singleShot(1000, update_countdown)
                        
                    update_countdown()
                    return
                else:
                    self.add_message(f"Error: API failure on 0x{self.current_ea:X} ({err_msg}). Skipping.", is_user=False)
                    QtCore.QTimer.singleShot(50, self.run_autopilot_loop)
                    return
                
            # Extract JSON
            json_str = ""
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                elif "{" in response and "}" in response:
                    json_str = response[response.find("{"):response.rfind("}")+1]
                
                if json_str:
                    data = json.loads(json_str)
                    
                    new_name = data.get("function_name", "")
                    vars_dict = data.get("variables", {})
                    comments = data.get("comments", "")
                    
                    self.markdown_report += f"## Function: {func_name} (0x{self.current_ea:X})\n"
                    
                    def _apply():
                        from pseudonote.renamer import clean_name
                        from pseudonote.var_renamer import apply_var_renames
                        
                        log_lines = []
                        if new_name and new_name != func_name and new_name != "sub_" + hex(self.current_ea)[2:]:
                            safe_name = clean_name(new_name, ea=self.current_ea)
                            if idc.set_name(self.current_ea, safe_name, idc.SN_AUTO):
                                log_lines.append(f"- **Renamed Function**: `{func_name}` -> `{safe_name}`")
                                
                        if vars_dict:
                            app, fail, _ = apply_var_renames(self.current_ea, vars_dict, log_fn=None)
                            if app > 0:
                                log_lines.append(f"- **Renamed Variables**: {app} successfully applied.")
                                
                        if comments:
                            curr = idc.get_func_cmt(self.current_ea, 0)
                            nc = comments if not curr else curr + "\\n" + comments
                            idc.set_func_cmt(self.current_ea, nc, 0)
                            log_lines.append(f"- **Comments**: {comments}")
                            
                        return "\\n".join(log_lines)
                        
                    res_log = []
                    ida_kernwin.execute_sync(lambda: res_log.append(_apply()), ida_kernwin.MFF_WRITE)
                    
                    if res_log and res_log[0]:
                        self.markdown_report += res_log[0] + "\n\n"
                    else:
                        self.markdown_report += "- No changes applied.\n\n"
                        
                    self.add_message(f"✅ Processed {func_name} -> {new_name}", is_user=False)
            except Exception as e:
                self.add_message(f"⚠️ JSON Parse Error on {func_name}: {e}", is_user=False)
            
            QtCore.QTimer.singleShot(100, self.run_autopilot_loop)

        AI_CLIENT = _ai_mod.AI_CLIENT
        history = [{"role": "user", "content": prompt}]
        AI_CLIENT.query_model_async(history, _autopilot_response)
        
    def _save_markdown_report(self):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Save Analysis Report", "analysis_report.md", "Markdown Files (*.md);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.markdown_report)
                self.add_message(f"💾 Report saved successfully to: {file_path}", is_user=False)
            except Exception as e:
                self.add_message(f"❌ Error saving report: {e}", is_user=False)
                
    def run_loop(self):
        if not self.is_running or getattr(self, 'is_paused', False):
            return

        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_message("Error: AI Client not initialized.", is_user=False)
            return

        self.typing_indicator.setVisible(True)
        
        self.live_bubble = ChatBubble("...", is_user=False)
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, self.live_bubble)
        self.scroll_to_bottom()
        
        # Accumulator for streaming chunks
        self._streamed_text = ""
        
        def handle_chunk(text):
            if hasattr(self, 'live_bubble') and self.live_bubble:
                self._streamed_text += text
                # Use raw text during streaming to prevent markdown parser from freezing the UI
                safe_text = html.escape(self._streamed_text).replace('\n', '<br>')
                self.live_bubble.msg_label.setText(safe_text)
                self.scroll_to_bottom()
        
        def handle_response(response, **kwargs):
            self.typing_indicator.setVisible(False)
            
            if hasattr(self, 'live_bubble') and self.live_bubble:
                self.scroll_layout.removeWidget(self.live_bubble)
                self.live_bubble.deleteLater()
                self.live_bubble = None
                
            if not response:
                is_throttle = kwargs.get("is_throttle", False)
                err_msg = kwargs.get("error_msg", "Unknown error")
                if is_throttle:
                    self.add_message(f"⚠️ API Rate Limit (429) hit: {err_msg[:100]}...\nPausing for 4 minutes before auto-continuing...", is_user=False)
                    self.is_paused = True
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(True)
                    
                    self.throttle_remaining = 240 # 4 minutes
                    self.typing_indicator.setVisible(True)
                    
                    def update_countdown():
                        if not getattr(self, 'is_paused', False) or getattr(self, 'throttle_remaining', 0) <= 0:
                            self.typing_indicator.setText("Agent is thinking...")
                            self.typing_indicator.setVisible(False)
                            if getattr(self, 'throttle_remaining', 0) <= 0 and getattr(self, 'is_paused', False):
                                self.on_continue()
                            return
                            
                        mins, secs = divmod(self.throttle_remaining, 60)
                        self.typing_indicator.setText(f"API Rate Limited. Auto-continuing in {mins}m {secs}s...")
                        self.throttle_remaining -= 1
                        QtCore.QTimer.singleShot(1000, update_countdown)
                        
                    update_countdown()
                    return
                else:
                    self.add_message(f"Error: No response from AI. ({err_msg})", is_user=False)
                    self.is_running = False
                    self.btn_start.setEnabled(True)
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(False)
                    return

            self.history.append({"role": "assistant", "content": response})
            
            # Parse for JSON block
            tool_call = None
            json_error = None
            has_json_block = False
            
            try:
                json_str = ""
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                    has_json_block = True
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                    has_json_block = True
                elif "{" in response and "}" in response:
                    json_str = response[response.find("{"):response.rfind("}")+1]
                    if '"tool"' in json_str: # High confidence it's a tool call if it contains "tool"
                        has_json_block = True
                
                if json_str:
                    # Fix unquoted hex values in JSON: "args": {"ea": 0x1000} -> "args": {"ea": "0x1000"}
                    json_str = re.sub(r'(:\s*)(0x[0-9a-fA-F]+)', r'\1"\2"', json_str)
                    tool_call = json.loads(json_str)
            except Exception as e:
                json_error = str(e)
                tool_call = None

            if tool_call and "tool" in tool_call:
                self.error_count = 0
                tool_name = tool_call["tool"]
                args = tool_call.get("args", {})
                self.add_message(f"🛠️ Executing Tool: `{tool_name}`\nArgs: {json.dumps(args, indent=2)}", is_user=False)
                
                # Execute tool
                result = "Tool not found."
                if tool_name == "decompile":
                    result = tool_decompile(self.address)
                elif tool_name == "get_xrefs":
                    result = tool_get_xrefs(self.address)
                elif tool_name == "rename_func":
                    result = tool_rename_func(self.address, args.get("new_name", ""))
                elif tool_name == "rename_vars":
                    result = tool_rename_vars(self.address, args.get("renames", {}))
                elif tool_name == "add_comment":
                    result = tool_add_comment(self.address, args.get("text", ""))
                elif tool_name == "analyze_subfunction":
                    result = tool_analyze_subfunction(args.get("ea", 0))
                elif tool_name == "create_apply_struct":
                    result = tool_create_apply_struct(args.get("name", ""), args.get("fields_json", ""))
                elif tool_name == "query_threat_intel":
                    result = tool_query_threat_intel(args.get("indicator", ""))
                elif tool_name == "get_vtable_ptrs":
                    result = tool_get_vtable_ptrs(args.get("ea", 0), args.get("count", 10))
                elif tool_name == "set_func_type":
                    result = tool_set_func_type(args.get("ea", 0), args.get("signature", ""))
                elif tool_name == "read_memory":
                    result = tool_read_memory(args.get("ea", 0), args.get("size", 32))
                elif tool_name == "patch_bytes":
                    result = tool_patch_bytes(args.get("ea", 0), args.get("hex_string", ""))
                elif tool_name == "save_finding":
                    result = tool_save_finding(args.get("key", ""), args.get("value", ""))
                elif tool_name == "search_findings":
                    result = tool_search_findings(args.get("query", ""))
                elif tool_name == "execute_idapython":
                    result = tool_execute_idapython(args.get("script", ""))

                # Create a concise summary for the UI to prevent spam
                if result.startswith("Error") or result.startswith("Failed") or "Exception" in result[:50]:
                    ui_msg = f"⚙️ Tool `{tool_name}` returned an error:\n{result[:200]}{'...' if len(result)>200 else ''}"
                else:
                    if tool_name == "decompile":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Successfully decompiled function ({len(result)} chars)."
                    elif tool_name == "analyze_subfunction":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Successfully decompiled subfunction."
                    elif tool_name == "get_xrefs":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Xrefs retrieved."
                    elif tool_name == "get_vtable_ptrs":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Retrieved pointers."
                    elif tool_name == "set_func_type":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Set function signature."
                    elif tool_name == "read_memory":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Dumped memory."
                    elif tool_name == "patch_bytes":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Memory patched."
                    elif tool_name == "save_finding":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Saved to global memory."
                    elif tool_name == "search_findings":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Searched global memory."
                    elif tool_name == "execute_idapython":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Script executed.\n{result[:150]}{'...' if len(result)>150 else ''}"
                    else:
                        ui_msg = f"⚙️ Tool `{tool_name}`: {result[:100]}{'...' if len(result)>100 else ''}"

                self.add_message(ui_msg, is_user=True)
                
                # The agent still needs the full result in its history
                self.history.append({"role": "user", "content": f"Tool '{tool_name}' result:\n{result}"})
                
                # Context Management: Truncate history if it gets too large (>20,000 characters)
                current_length = sum(len(str(m.get("content", ""))) for m in self.history)
                if current_length > 20000 and len(self.history) > 5:
                    # Keep system prompt (index 0) and the last 3 exchanges
                    self.history = [self.history[0]] + self.history[-3:]
                    self.add_message("⚠️ Context limit reached. Truncated older history to preserve memory.", is_user=False)
                
                # Continue loop
                QtCore.QTimer.singleShot(100, self.run_loop)
            elif has_json_block and json_error:
                self.error_count += 1
                if self.error_count >= 3:
                    self.add_message(f"⚠️ Agent repeatedly failed to produce valid JSON. Stopping analysis to prevent infinite loops.", is_user=False)
                    self.is_running = False
                    self.btn_start.setEnabled(True)
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(False)
                    return
                
                # Agent tried to output JSON but failed syntax
                err_str = f"⚠️ JSON Parse Error: {json_error}\nPlease format your tool call as valid JSON. Ensure you DO NOT put normal text inside the JSON block."
                self.add_message(err_str, is_user=True)
                self.history.append({"role": "user", "content": f"Failed to parse JSON tool call. You wrote invalid JSON. Error: {json_error}. Remember: ONLY output the JSON block, no surrounding text inside the block. Hex values must be strings."})
                QtCore.QTimer.singleShot(100, self.run_loop)
            else:
                self.error_count = 0
                # Agent provided final analysis
                self.add_message(f"✅ Final Analysis:\n\n{response}", is_user=False)
                self.is_running = False
                self.btn_start.setEnabled(True)
                self.btn_pause.setEnabled(False)
                self.btn_continue.setEnabled(False)

        AI_CLIENT.query_model_async(self.history, handle_response, on_chunk=handle_chunk)

    def OnClose(self, form):
        self.is_running = False


class AgenticAnalysisHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            print("[PseudoNote] No function at cursor.")
            return 0
        
        name = idc.get_func_name(func.start_ea)
        
        title = "Agentic Analysis"
        widget = ida_kernwin.find_widget(title)
        if widget:
            ida_kernwin.activate_widget(widget, True)
        else:
            form = AgenticForm(func.start_ea, name)
            form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_PERSIST)
        
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
