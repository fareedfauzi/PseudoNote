# -*- coding: utf-8 -*-
"""
IDA action handlers for PseudoNote (rename, comment, signature, struct, bulk rename).
"""

import re
import json
import functools

import idaapi
import ida_kernwin
import ida_hexrays
import idc
import ida_lines

from pseudonote.qt_compat import QtWidgets, QtGui
from pseudonote.config import CONFIG, LOGGER
import pseudonote.ai_client as _ai_mod
import pseudonote.chat as _chat
import pseudonote.view as _view_mod
from pseudonote.renamer import clean_name
from pseudonote.idb_storage import save_to_idb


def _get_ai_client():
    return _ai_mod.AI_CLIENT

# Conversation history cache for Ask AI chat (keyed by address or other convo id)
# Stores list of tuples: (role: 'user'|'ai', text)
ASK_AI_HISTORY = {}


# ---------------------------------------------------------------------------
# Rename Variables handler
# ---------------------------------------------------------------------------
def _pn_rename_callback(address, view, response):
    """Apply AI-suggested variable renames to the decompiled function."""
    if not response:
        print("[PseudoNote] Rename Variables: no response from AI.")
        return
    try:
        names = json.loads(response)
    except Exception as e:
        # Try to extract JSON if it's wrapped in markdown or other text
        try:
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                names = json.loads(response[start:end+1])
            else:
                raise e
        except:
            print(f"[PseudoNote] Rename Variables: failed to parse JSON response: {e}")
            return

    func = idaapi.get_func(address)
    if not func:
        print("[PseudoNote] Rename Variables: no function at cursor.")
        return

    try:
        from pseudonote.var_renamer import apply_var_renames
    except Exception as e:
        print(f"[PseudoNote] Rename Variables: failed to import var_renamer: {e}")
        return

    applied, failed, _ = apply_var_renames(func.start_ea, names, log_fn=None)
    if applied > 0:
        idaapi.execute_sync(lambda: save_to_idb(func.start_ea, "variables_renamed", tag=86), idaapi.MFF_WRITE)

    # Update comment if any names actually changed
    if applied > 0:
        comment = idc.get_func_cmt(address, 0)
        if comment:
            for old_name, new_name in names.items():
                comment = re.sub(fr'\\b{re.escape(old_name)}\\b', new_name, comment)
            idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
    print(f"[PseudoNote] Rename Variables: {applied} renamed, {failed} failed.")


class RenameVariablesHandler(idaapi.action_handler_t):
    """Ask AI to suggest better variable names and apply them automatically."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not decompiler_output or not v: return 0
        
        _view_mod.show_ai_progress("Renaming Variables")
        prompt = (
            "You are an expert reverse engineer. Review the C function code provided below:\n\n{decompiler_output}\n\n"
            "Identify variables with generic or unhelpful names (e.g., v1, a2, result, qword_1234, dword_5678). "
            "Propose more descriptive names based on their usage, context, and data flow. "
            "Output ONLY a valid JSON object mapping the original variable names (keys) to the suggested new names (values). "
            "Do NOT include any explanations or markdown formatting outside the JSON."
        ).format(decompiler_output=str(decompiler_output))
        
        def wrapped_cb(response, **kwargs):
            try: _pn_rename_callback(address=idaapi.get_screen_ea(), view=v, response=response)
            finally: _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, additional_options={"max_completion_tokens": 8192})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Globals / Helpers for caller context
# ---------------------------------------------------------------------------
class CallerSelectionDialog(QtWidgets.QDialog):
    def __init__(self, callers_info, parent=None):
        super(CallerSelectionDialog, self).__init__(parent)
        self.setWindowTitle("Select Callers for Context")
        self.resize(400, 300)
        
        layout = QtWidgets.QVBoxLayout(self)
        
        label = QtWidgets.QLabel("Select which calling functions to include as AI context:")
        layout.addWidget(label)
        
        scroll = QtWidgets.QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll_content = QtWidgets.QWidget()
        self.checkboxes = []
        
        vbox = QtWidgets.QVBoxLayout(scroll_content)
        for ea, name in callers_info:
            cb = QtWidgets.QCheckBox(f"0x{ea:X} - {name}")
            self.checkboxes.append((cb, ea))
            vbox.addWidget(cb)
            
        for i, (cb, ea) in enumerate(self.checkboxes):
            if i < 3:
                cb.setChecked(True)
        
        vbox.addStretch(1)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        btn_box = QtWidgets.QDialogButtonBox()
        btn_box.addButton(QtWidgets.QDialogButtonBox.Ok)
        btn_box.addButton(QtWidgets.QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def get_selected(self):
        return [ea for cb, ea in self.checkboxes if cb.isChecked()]


def _get_caller_context_texts(target_func_ea):
    """Prompts user to select caller functions to decompile and returns text list. Returns None if cancelled."""
    import idautils
    callers = set()
    for ref in idautils.CodeRefsTo(target_func_ea, 0):
        caller_func = idaapi.get_func(ref)
        if caller_func and caller_func.start_ea != target_func_ea:
            callers.add(caller_func.start_ea)
            
    callers_info = []
    for c_ea in callers:
        name = idc.get_func_name(c_ea) or f"sub_{c_ea:X}"
        callers_info.append((c_ea, name))
        
    selected_callers = []
    if callers_info:
        dialog = CallerSelectionDialog(callers_info)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            selected_callers = dialog.get_selected()
        else:
            return None # Cancelled by user

    caller_texts = []
    if selected_callers:
        _view_mod.show_ai_progress("Decompiling Callers...")
        for c_ea in selected_callers:
            try:
                cfunc_caller = ida_hexrays.decompile(c_ea)
                if cfunc_caller:
                    name = idc.get_func_name(c_ea) or f"sub_{c_ea:X}"
                    caller_texts.append(f"Caller `{name}`:\n{str(cfunc_caller)}")
            except:
                pass
        _view_mod.hide_ai_progress()

    return caller_texts

# ---------------------------------------------------------------------------
# Rename Function (Code) handler
# ---------------------------------------------------------------------------
class RenameFunctionHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function name based on code logic and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        
        func = idaapi.get_func(ea)
        if not func: return 0
        try: cfunc = ida_hexrays.decompile(func.start_ea)
        except: return 0
        
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
        
        caller_texts = _get_caller_context_texts(func.start_ea)
        if caller_texts is None:
            return 0  # Cancelled dialog
        
        prefix = CONFIG.function_prefix if CONFIG.use_rename_prefix else ""
        _view_mod.show_ai_progress("Naming Function (Code)")
        
        prompt = (
            "Analyze the following C function code:\n"
            f"{str(cfunc)}\n"
        )
        if caller_texts:
            prompt += (
                "\nFor additional context, here is the decompiled code of functions that call this target function:\n"
                "---\n"
                + "\n\n".join(caller_texts) + "\n"
                "---\n"
            )
        prompt += (
            "\nSuggest a concise new name for this function based on its logic and caller context (if provided). "
            f"Only reply with the new function name, prefixed with '{prefix}' if appropriate."
        )
        def callback(response, **kwargs):
            try:
                if not response: return
                clean_resp = response.strip().replace("`", "").replace("'", "").replace("\"", "")
                if not clean_resp: return
                new_name = clean_resp.split()[0]
                func = idaapi.get_func(ea)
                if not func: return

                if getattr(CONFIG, 'rename_append_address', False):
                    use_0x = getattr(CONFIG, 'rename_use_0x', False)
                    addr_str = f"{func.start_ea:X}"
                    if use_0x:
                        new_name = f"{new_name}_0x{addr_str}"
                    else:
                        new_name = f"{new_name}_{addr_str}"

                old_name = idc.get_func_name(func.start_ea)
                new_name = clean_name(new_name, ea=func.start_ea)
                if not new_name or new_name == old_name: return
                
                if idc.set_name(func.start_ea, new_name, idc.SN_AUTO):
                    from pseudonote.idb_storage import save_to_idb
                    save_to_idb(func.start_ea, "renamed_by_pseudonote", tag=83)
                    if vdui: vdui.refresh_view(True)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Rename Function (Malware) handler
# ---------------------------------------------------------------------------
class RenameMalwareFunctionHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function name in malware analysis context and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        
        func = idaapi.get_func(ea)
        if not func: return 0
        try: cfunc = ida_hexrays.decompile(func.start_ea)
        except: return 0
        
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
        
        caller_texts = _get_caller_context_texts(func.start_ea)
        if caller_texts is None:
            return 0  # Cancelled dialog
        
        prefix = CONFIG.function_prefix if CONFIG.use_rename_prefix else ""
        _view_mod.show_ai_progress("Naming Function (Malware)")
        
        prompt = (
            "Analyze the following C function code in the context of malware reverse engineering:\n"
            f"{str(cfunc)}\n"
        )
        if caller_texts:
            prompt += (
                "\nFor additional context, here is the decompiled code of functions that call this target function:\n"
                "---\n"
                + "\n\n".join(caller_texts) + "\n"
                "---\n"
            )
        prompt += (
            "\nSuggest a concise new name for this function based on its logic and caller context (if provided). "
            f"Only reply with the new function name, prefixed with '{prefix}' if appropriate."
        )
        def callback(response, **kwargs):
            try:
                if not response: return
                clean_resp = response.strip().replace("`", "").replace("'", "").replace("\"", "")
                if not clean_resp: return
                new_name = clean_resp.split()[0]
                func = idaapi.get_func(ea)
                if not func: return

                if getattr(CONFIG, 'rename_append_address', False):
                    use_0x = getattr(CONFIG, 'rename_use_0x', False)
                    addr_str = f"{func.start_ea:X}"
                    if use_0x:
                        new_name = f"{new_name}_0x{addr_str}"
                    else:
                        new_name = f"{new_name}_{addr_str}"

                old_name = idc.get_func_name(func.start_ea)
                new_name = clean_name(new_name, ea=func.start_ea)
                if not new_name or new_name == old_name: return
                
                if idc.set_name(func.start_ea, new_name, idc.SN_AUTO):
                    from pseudonote.idb_storage import save_to_idb
                    save_to_idb(func.start_ea, "renamed_by_pseudonote", tag=83)
                    if vdui: vdui.refresh_view(True)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS





# ---------------------------------------------------------------------------
# Suggest Function Prototype Handler
# ---------------------------------------------------------------------------
class SuggestFunctionPrototypeHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function prototype and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        
        func = idaapi.get_func(ea)
        if not func: return 0
        
        try: cfunc = ida_hexrays.decompile(func.start_ea)
        except: return 0
             
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui: return 0
        
        caller_texts = _get_caller_context_texts(func.start_ea)
        if caller_texts is None:
            return 0  # Cancelled dialog

        _view_mod.show_ai_progress("Suggesting Prototype")
        prompt = (
            "You are an expert reverse engineer analyzing Hex-Rays pseudocode to determine the exact C function prototype.\n\n"
            "Your task is to infer the most accurate prototype, specifically determining the:\n"
            "1. Return type\n"
            "2. Calling convention\n"
            "3. Function name\n"
            "4. Parameter types\n"
            "5. Parameter names\n\n"
            "Analyze the following decompiled function:\n"
            "---\n"
            f"{str(cfunc)}\n"
            "---\n\n"
        )
        
        if caller_texts:
            prompt += (
                "For additional context, here is the decompiled code of functions that call the target function:\n"
                "---\n"
                + "\n\n".join(caller_texts) + "\n"
                "---\n\n"
            )
            
        prompt += (
            "STRICT INSTRUCTIONS:\n"
            "- Base your inferences ONLY on observable behavior in the target pseudocode AND how it is used in the caller contexts (e.g., arguments passed, return value usage).\n"
            "- Do NOT hallucinate known APIs or rename the function to a Windows API unless the match is extremely clear.\n"
            "- If a type cannot be determined confidently, you must fall back to safe generic types such as: int, void *, or char *.\n"
            "- If structure usage is detected (e.g., ptr->field or ptr + offset), prefer pointer types.\n"
            "- Generate descriptive parameter names based on their usage context, avoiding generic names like a1 or v5.\n"
            "- IMPORTANT: If the original function is `__usercall`, you MUST preserve `__usercall` and the `@<register>` annotations exactly! Removing them breaks Hex-Rays variable mapping.\n"
            "- If the calling convention is unclear and not `__usercall`, default to __fastcall.\n"
            "- The output MUST be a single valid C function prototype.\n"
            "- The output MUST NOT include a trailing semicolon.\n"
            "- The output MUST NOT include markdown formatting, code blocks, explanations, or any extra text.\n\n"
            "Examples of exact expected output format:\n"
            "int __fastcall fn_process_packet(char *buffer, int size)\n"
            "void * __stdcall fn_allocate_buffer(size_t size)\n"
            "void __usercall fn_collect_system_info(int info_buffer@<edi>, int status@<eax>)\n\n"
            "Provide the single C function prototype string now."
        )
        
        def callback(response, **kwargs):
            try:
                import re
                if not response: return
                clean_sig = response.strip().split('{')[0].strip().rstrip(';')
                func = idaapi.get_func(ea)
                if not func: return
                
                def normalize_sig(s):
                    # Remove comments (single line and multi-line)
                    s = re.sub(r'//.*', '', s)
                    s = re.sub(r'/\*.*?\*/', '', s, flags=re.DOTALL)
                    # Normalize whitespace
                    return ' '.join(s.split())

                existing_sig = normalize_sig(str(cfunc).split('{')[0])
                new_sig = normalize_sig(clean_sig)

                # Extract function names
                match_new = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', new_sig)
                new_func_name = match_new.group(1) if match_new else None

                old_name = idc.get_func_name(func.start_ea)
                match_old = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', existing_sig)
                old_func_name = match_old.group(1) if match_old else old_name

                # Compare structurally (ignoring function names)
                new_sig_anon = new_sig
                existing_sig_anon = existing_sig
                if new_func_name:
                    new_sig_anon = new_sig.replace(new_func_name, "F_NAME", 1)
                if old_func_name:
                    existing_sig_anon = existing_sig.replace(old_func_name, "F_NAME", 1)

                if new_sig_anon == existing_sig_anon and new_func_name == old_name:
                    ida_kernwin.info("The AI suggested the exact same prototype as the current one.\nNothing to change.")
                    return
                
                msg = f"AI Suggested Signature:\n\n{clean_sig}\n\nApply this signature?"
                if ida_kernwin.ask_yn(1, msg) == 1:
                    name_changed = False
                    if new_func_name and new_func_name != old_name and not new_func_name.startswith("sub_"):
                        # Apply name first so SetType works correctly with the matching name
                        safe_name = clean_name(new_func_name, ea=func.start_ea)
                        if idc.set_name(func.start_ea, safe_name, idc.SN_AUTO):
                            name_changed = True

                    # Now apply the signature
                    if idc.SetType(func.start_ea, clean_sig + ";"):
                        if vdui: vdui.refresh_view(True)
                    else:
                        ida_kernwin.warning("IDA failed to apply the exact prototype types.\n(The function may have been renamed, but types were rejected due to unknown structs/syntax.)")
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, callback, on_chunk=chunk_cb)
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


# ---------------------------------------------------------------------------
# Comment Handler (AI)
# ---------------------------------------------------------------------------
def get_commentable_lines(cfunc):
    """
    Extracts information for each line of decompiled pseudocode.
    Returns: List of tuples: (lineIndex, lineText, comment_address, comment_placement, has_user_comment)
    """
    result = []
    pseudocode_lines = cfunc.get_pseudocode()

    place_comments_above = True 

    for idx, line in enumerate(pseudocode_lines):
        try:
            line_text = idaapi.tag_remove(line.line)
        except:
            line_text = str(line.line)

        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        phead_addr = None
        phead_place = None
        ptail_addr = None
        ptail_place = None

        has_user_comment = False
        comment_address = None
        comment_placement = 0

        try:
            found = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
            if found:
                if not place_comments_above:
                    phead, ptail = ptail, phead

                if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                    try:
                        has_user_comment |= (cfunc.get_user_cmt(phead.loc, True) is not None)
                    except: pass
                    phead_addr = phead.loc.ea
                    phead_place = phead.loc.itp
                
                if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                    try:
                        has_user_comment |= (cfunc.get_user_cmt(ptail.loc, True) is not None)
                    except: pass
                    ptail_addr = ptail.loc.ea
                    ptail_place = ptail.loc.itp

                if phead_addr is not None:
                    comment_address = phead_addr
                    comment_placement = phead_place
                elif ptail_addr is not None:
                    comment_address = ptail_addr
                    comment_placement = ptail_place
        except:
            pass

        result.append((idx, idaapi.tag_remove(line_text), comment_address, comment_placement, has_user_comment))

    return result

def format_commentable_lines(commentable_lines):
    output = []
    for idx, text, comment_address, comment_placement, has_user_comment in commentable_lines:
        prefix = "+" if comment_address is not None and not has_user_comment else ""
        output.append(f"{prefix}{idx}\t{text}")
    return "\n".join(output)

def _pn_comment_callback(cfunc, pseudocode_lines, view, response):
    if not response:
        print("[PseudoNote] Comments: no response from AI.")
        return

    try:
        content = response.strip()
        if "```" in content:
            matches = re.findall(r"```(?:json)?\n(.*?)```", content, re.DOTALL)
            if matches:
                content = matches[0]
            else:
                parts = content.split("```")
                if len(parts) >= 3: content = parts[1]
        
        items = json.loads(content)
    except Exception as exc:
        print(f"[PseudoNote] Comment callback JSON failure: {exc}")
        return

    applied_count = 0
    for line_key, raw_comment in items.items():
        try:
            line_index = int(line_key)
        except ValueError:
            continue

        if line_index < 0 or line_index >= len(pseudocode_lines):
            continue

        comment_address = pseudocode_lines[line_index][2]
        comment_placement = pseudocode_lines[line_index][3]
        if comment_placement is None:
            comment_placement = idaapi.ITP_SEMI

        if comment_address is None or comment_address == idaapi.BADADDR:
            continue

        comment_text = str(raw_comment).strip()
        if not comment_text:
            continue

        # Add PseudoNote prefix for consistency
        full_comment = f"{comment_text}"
        
        # Prepend a newline for better visual spacing in pseudocode
        pseudocode_comment = "\n" + full_comment

        target = idaapi.treeloc_t()
        target.ea = int(comment_address)
        target.itp = comment_placement
        cfunc.set_user_cmt(target, pseudocode_comment)
        
        # Sync to assembly view (repeatable comment so it's visible in both)
        idc.set_cmt(target.ea, full_comment, 1)
        
        applied_count += 1

    if applied_count > 0:
        cfunc.save_user_cmts()
        cfunc.del_orphan_cmts()
        if view:
            view.refresh_view(True)
        # Also refresh disassembly if it's there
        idaapi.request_refresh(idaapi.IWID_DISASM)
        print(f"[PseudoNote] Applied {applied_count} comments (Synced to ASM).")
    else:
        print("[PseudoNote] No comments were applied.")

class CommentHandler(idaapi.action_handler_t):
    """Ask AI to add helpful comments to the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0
        ea = idaapi.get_screen_ea()
        try: cfunc = ida_hexrays.decompile(ea)
        except: return 0
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not v: return 0

        _view_mod.show_ai_progress("Commenting Code")
        pseudocode_lines = get_commentable_lines(cfunc)
        formatted_lines = format_commentable_lines(pseudocode_lines)
        prompt = (
            "You are a reverse-engineering assistant adding helpful pseudocode comments.\n"
            "- Output format (strict): exactly one JSON object mapping integer lineNumber -> string comment.\n"
            "  * No Markdown, no code fences, no explanations outside the JSON object.\n"
            "  * If no comments are warranted, return {}.\n"
            "- Scope: Only annotate lines that start with '+' in the listing below.\n"
            "- Guidance: Explain intent, side-effects, or non-obvious control flow. Skip trivial operations.\n"
            "- Style: Keep comments concise (one sentence when possible).\n"
            "\n"
            "```C\n"
            f"{formatted_lines}\n"
            "```"
        )
        def wrapped_cb(response, **kwargs):
            try: _pn_comment_callback(cfunc=cfunc, pseudocode_lines=pseudocode_lines, view=v, response=response)
            finally:
                _view_mod.hide_ai_progress()

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, additional_options={"max_completion_tokens": 8192})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DeleteCommentsHandler(idaapi.action_handler_t):
    """Delete all AI-generated comments from the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        try:
            cfunc = ida_hexrays.decompile(ea)
        except:
            print("[PseudoNote] Could not decompile function.")
            return 0
            
        if not cfunc:
            print("[PseudoNote] No pseudocode available.")
            return 0

        # Ask for confirmation
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Are you sure you want to delete ALL comments in this function?") != idaapi.ASKBTN_YES:
             return 0

        pseudocode_lines = cfunc.get_pseudocode()
        deleted_count = 0
        
        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        for line in pseudocode_lines:
            try:
                if cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail):
                    if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                        if cfunc.get_user_cmt(phead.loc, 1):
                            cfunc.set_user_cmt(phead.loc, "")
                            deleted_count += 1
                    if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                        if cfunc.get_user_cmt(ptail.loc, 1):
                            cfunc.set_user_cmt(ptail.loc, "")
                            deleted_count += 1
            except:
                continue

        cfunc.save_user_cmts()
        cfunc.del_orphan_cmts()
        
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if v:
            v.refresh_view(True)
            
        print(f"[PseudoNote] Comments deleted.")
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


# ---------------------------------------------------------------------------
# ASM Section Comment Handler (IDA Disassembly View)
# ---------------------------------------------------------------------------

def _get_asm_sections(start_ea, end_ea):
    """
    Return a list of (ea, label, [insn_text, ...]) tuples for the address
    range [start_ea, end_ea).  A new section starts at start_ea and at every
    address that is a jump/branch target or has a named label.
    """
    import idautils
    sections = []
    current_label = None
    current_ea = None
    current_insns = []

    # Collect all branch-target addresses inside the range
    jump_targets = set()
    for head in idautils.Heads(start_ea, end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            if start_ea <= ref < end_ea:
                jump_targets.add(ref)

    for head in idautils.Heads(start_ea, end_ea):
        is_section_start = (
            head == start_ea
            or head in jump_targets
            or bool(idc.get_name(head))
        )
        if is_section_start:
            if current_ea is not None and current_insns:
                sections.append((current_ea, current_label, current_insns))
            current_ea = head
            current_label = idc.get_name(head) or f"loc_{head:X}"
            current_insns = []
        disasm = idc.generate_disasm_line(head, 0)
        if disasm:
            current_insns.append(disasm)

    if current_ea is not None and current_insns:
        sections.append((current_ea, current_label, current_insns))

    return sections


def _resolve_asm_range(ea):
    """
    Try to resolve a (start_ea, end_ea, context_name) for the given address.
    Priority:
      1. Active selection in the disassembly widget
      2. Enclosing function bounds
    Returns None if neither is available.
    """
    # 1. Try active selection
    ok, sel_start, sel_end = idaapi.read_range_selection(None)
    if ok and sel_start != idaapi.BADADDR and sel_end != idaapi.BADADDR and sel_end > sel_start:
        return sel_start, sel_end, f"selection {hex(sel_start)}–{hex(sel_end)}"

    # 2. Fall back to enclosing function
    func = idaapi.get_func(ea)
    if func:
        name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
        return func.start_ea, func.end_ea, name

    return None


class AsmCommentHandler(idaapi.action_handler_t):
    """Add concise section-level comments to the IDA disassembly view using AI.
    Works on a user selection (for shellcode) or the enclosing function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        import json as _json
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT: return 0

        ea = idaapi.get_screen_ea()
        result = _resolve_asm_range(ea)
        if not result:
            print("[PseudoNote] No selection and no function found. "
                  "Select a range of instructions first, or place the cursor inside a defined function.")
            return 0

        start_ea, end_ea, context_name = result
        sections = _get_asm_sections(start_ea, end_ea)
        if not sections:
            print("[PseudoNote] Could not collect disassembly sections in range.")
            return 0

        # Build compact representation for the AI (cap each section at 12 lines)
        lines = []
        for i, (sec_ea, label, insns) in enumerate(sections):
            snippet = "\n  ".join(insns[:12])
            if len(insns) > 12:
                snippet += f"\n  ... ({len(insns) - 12} more)"
            lines.append(f"Section {i+1} [{hex(sec_ea)}] {label}:\n  {snippet}")

        asm_text = "\n\n".join(lines)

        prompt = (
            f"You are an expert reverse engineer analyzing `{context_name}`.\n\n"
            "Below are the logical sections of its disassembly. "
            "For each section provide a VERY SHORT description (≤6 words, plain English, no punctuation).\n\n"
            f"{asm_text}\n\n"
            "Output ONLY valid JSON — a list of objects with keys \"section\" (1-based int) and \"comment\" (string).\n"
            "Example: [{\"section\": 1, \"comment\": \"init stack frame\"}, {\"section\": 2, \"comment\": \"validate argument\"}]\n"
            "No markdown, no extra text."
        )

        _view_mod.show_ai_progress("Annotating Disassembly Sections...")

        def done_cb(response, **kwargs):
            _view_mod.hide_ai_progress()
            if not response:
                print("[PseudoNote] No response from AI.")
                return
            try:
                text = response.strip()
                # Strip optional markdown fences
                if text.startswith("```"):
                    text = "\n".join(text.split("\n")[1:])
                if text.endswith("```"):
                    text = text[:text.rfind("```")]
                text = text.strip()

                items = _json.loads(text)
                applied = 0
                
                # Try to get pseudocode context for syncing
                cfunc = None
                itp_map = {}
                try:
                    func = idaapi.get_func(start_ea)
                    if func:
                        # Only decompile if it's a relatively small/normal function to avoid lag
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            # Build map of address -> (lineIndex, itp, has_user_comment)
                            for _, _, addr, itp, has_user_cmt in get_commentable_lines(cfunc):
                                if addr not in itp_map:
                                    itp_map[addr] = itp
                except:
                    pass

                for item in items:
                    idx = item.get("section", 0) - 1
                    cmt = item.get("comment", "").strip()
                    if not cmt or idx < 0 or idx >= len(sections):
                        continue
                        
                    sec_ea = sections[idx][0]
                    full_cmt = f"{cmt}"
                    
                    # 1. Set repeatable comment in IDA (Disassembly)
                    # Repeatable (1) ensures it shows up in Pseudocode too
                    idc.set_cmt(sec_ea, full_cmt, 1)
                    
                    # 2. If we have pseudocode, also set a block comment for better visuals
                    if cfunc and sec_ea in itp_map:
                        target = idaapi.treeloc_t()
                        target.ea = sec_ea
                        target.itp = itp_map[sec_ea]
                        # Use newline prefix for block-style in C
                        cfunc.set_user_cmt(target, "\n" + full_cmt)
                        
                    applied += 1

                if cfunc:
                    cfunc.save_user_cmts()
                    cfunc.del_orphan_cmts()
                    # Trigger hex-rays refresh
                    idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)

                print(f"[PseudoNote] Applied {applied} section comment(s) to {context_name} (Synced to C).")
                idaapi.request_refresh(idaapi.IWID_DISASM)
            except Exception as e:
                print(f"[PseudoNote] ASM comment parse error: {e}\nRaw: {response[:300]}")

        total_chars = [0]
        def chunk_cb(t):
            total_chars[0] += len(t)
            _view_mod.update_ai_progress_details(total_chars[0])

        AI_CLIENT.query_model_async(prompt, done_cb, on_chunk=chunk_cb,
                                    additional_options={"max_completion_tokens": 2048})
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class DeleteAsmCommentsHandler(idaapi.action_handler_t):
    """Delete all regular (non-repeatable) IDA comments in the selected range or enclosing function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        import idautils
        ea = idaapi.get_screen_ea()
        result = _resolve_asm_range(ea)
        if not result:
            print("[PseudoNote] No selection and no function found.")
            return 0

        start_ea, end_ea, context_name = result

        if idaapi.ask_yn(idaapi.ASKBTN_NO,
                         f"Delete all IDA-view comments in {context_name}?") != idaapi.ASKBTN_YES:
            return 0

        deleted = 0
        for head in idautils.Heads(start_ea, end_ea):
            if idc.get_cmt(head, 0):   # regular comment
                idc.set_cmt(head, "", 0)
                deleted += 1
            if idc.get_cmt(head, 1):   # repeatable comment
                idc.set_cmt(head, "", 1)
                deleted += 1

        print(f"[PseudoNote] Deleted {deleted} comment(s) from {context_name}.")
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET




# ---------------------------------------------------------------------------
# Structure Analysis Handler & Dialog
# ---------------------------------------------------------------------------
class StructAnalysisDialog(QtWidgets.QDialog):
    def __init__(self, target_name, target_code, vdui, lvar_name, on_apply_callback=None, parent=None):
        super(StructAnalysisDialog, self).__init__(parent)
        self.setWindowTitle(f"Struct Creator / Editor: {target_name}")
        self.resize(700, 600)
        
        self.target_name = target_name
        self.target_code = target_code
        self.vdui = vdui
        self.lvar_name = lvar_name
        self.on_apply_callback = on_apply_callback
        
        layout = QtWidgets.QVBoxLayout()
        
        # Editor
        self.editor = QtWidgets.QTextEdit()
        self.editor.setPlainText(f"struct Struct_{target_name} {{\n    _DWORD dummy;\n}};\n")
        self.editor.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.editor)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        
        ai_btn = QtWidgets.QPushButton("AI Suggestion")
        ai_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: #FFFFFF;
                font-weight: bold;
                padding: 6px;
                border: 1px solid #005A9E;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #005A9E;
            }
            QPushButton:pressed {
                background-color: #004275;
            }
        """)
        ai_btn.clicked.connect(self.request_ai_suggestion)
        btn_layout.addWidget(ai_btn)
        
        copy_btn = QtWidgets.QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(copy_btn)
        
        import_btn = QtWidgets.QPushButton("Apply to IDA")
        import_btn.clicked.connect(self.import_to_ida)
        import_btn.setStyleSheet("font-weight: bold; padding: 5px;")
        btn_layout.addWidget(import_btn)
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def request_ai_suggestion(self):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT:
            QtWidgets.QMessageBox.warning(self, "No AI Client", "Please configure the AI provider in settings first.")
            return

        # 1. Ask for caller context (displays dialog; returns None if cancelled)
        caller_texts = _get_caller_context_texts(self.vdui.cfunc.entry_ea)
        if caller_texts is None:
            return  # Cancelled by user

        # 2. Ask for structure size
        size_input, ok = QtWidgets.QInputDialog.getText(
            self,
            "Structure Size (Optional)",
            "Enter known structure size in bytes (e.g. 0x354)\nLeave empty to let AI infer the size automatically:"
        )
        if not ok:
            return  # Cancelled by user

        size_input = size_input.strip()

        # 3. Start Request
        _view_mod.show_ai_progress(f"Analyzing Struct: {self.target_name}")
        
        size_instruction = "- Look carefully at `memset`, `malloc`, or function signatures to determine the EXACT total structure size in bytes, and add trailing padding to match it exactly.\n"
        if size_input and size_input != '?':
            size_instruction = f"- VERY IMPORTANT: The user has specified the EXPLICIT total size of this structure is {size_input} bytes. You MUST add trailing padding if necessary so its total size equals exactly {size_input} bytes.\n"
            
        prompt = (
            f"Analyze the C code below. Focus on the usage of variable `{self.target_name}`.\n"
            f"Infer the most likely C structure definition that `{self.target_name}` represents (or points to).\n"
            "Analyze all dereferences (e.g. `v5 + 16`, `v5->field_10`) to find fields.\n"
            "Return ONLY the C struct definition valid for an IDA header input.\n"
            f"Start the struct name with `Struct_{self.target_name}` or a descriptive name.\n\n"
            "CRITICAL RULES FOR STRUCT LAYOUT:\n"
            "- DO NOT hallucinate fields or arrays that are not explicitly accessed in the provided code.\n"
            "- Pad gaps strictly using `_BYTE padding_X[Y]` arrays to ensure subsequent offsets are perfectly aligned to the EXACT offsets seen in the code.\n"
            "- Pay very close attention to whether the offsets are in DECIMAL (e.g., `ptr + 306`) or HEXADECIMAL (e.g., `ptr + 0x132`). You must convert everything to a consistent size correctly! Do not confuse `0x132` for `132`.\n"
            "- The math MUST be perfect. Verify that `previous_offset + sizeof(previous_field) == current_offset`. If not, insert `_BYTE padding[N]` where `N = current_offset - (previous_offset + sizeof(previous_field))`.\n"
            f"{size_instruction}"
            "- Use ONLY standard explicit IDA types: `_DWORD` (4 bytes), `_WORD` (2 bytes), `_BYTE` (1 byte), `_QWORD` (8 bytes), `void *` (pointers). DO NOT USE types like `DWORD`, `BYTE`, `FILETIME`, `OSVERSIONINFO`, `wchar_t`, or `__int64` because IDA will throw a Syntax Error if they aren't pre-defined!\n"
            "- Include comments on EVERY line indicating both the offset and size: `// offset <hex>, size <decimal>`.\n"
            "- All array sizes and padding sizes MUST be pre-calculated integer literals (e.g. `_BYTE padding_1[42];`). DO NOT under any circumstances output arithmetic expressions like `[0x354 - 0x82C]` or negative sizes.\n"
            "- CRITICAL ANTI-LOOP RULE: To prevent endless generation, any and all trailing padding MUST be combined into ONE single array. NEVER output multiple consecutive padding fields. Once you have covered up to the highest offset accessed in the code, add exactly ONE trailing padding array to meet the structural size, ensure it has a semicolon `;`, and then on a NEW LINE output `};` to close the struct.\n"
            "- DO NOT use generic names like `field_0`, `field_112`, `dword_8C`. Every single member MUST be given a highly descriptive, semantic name based on the API functions it is passed to, the strings mapped to it, or its behavior in the code. If you cannot guess the specific name, guess its general purpose (e.g. `unknown_flag`, `config_data`, `linked_list_node`).\n"
            "- The Struct itself must also have a highly meaningful name representing its entire purpose, rather than just `Struct_buffer`.\n"
            "- FINAL OUTPUT ONLY: Do NOT output your thought process, do NOT output 'Let me recalculate', do NOT output multiple drafts or versions. Provide EXACTLY ONE structurally perfect C struct inside the markdown block and nothing else.\n\n"
            "```c\n"
            f"{self.target_code}\n"
            "```\n"
        )
        
        if caller_texts:
            prompt += (
                "\nFor additional context, here is the decompiled code of functions that call this target function.\n"
                "If the variable is passed to or returned from these callers, analyze its structure in their context as well:\n"
                "---\n"
                + "\n\n".join(caller_texts) + "\n"
                "---\n"
            )
        
        def wrapped_cb(response, **kwargs):
            _view_mod.hide_ai_progress()
            try: 
                self.handle_ai_response(response)
            except Exception as e:
                print(f"[PseudoNote] Struct Analysis Error: {e}")

        total_chars = [0]
        streamed_buffer = [""]
        def chunk_cb(t):
            total_chars[0] += len(t)
            streamed_buffer[0] += t
            _view_mod.update_ai_progress_details(total_chars[0])
            # Stream raw text to editor safely on the Main UI Thread
            from pseudonote.qt_compat import QtCore
            QtCore.QTimer.singleShot(0, lambda: self.editor.setPlainText(streamed_buffer[0]))

        self.editor.setReadOnly(True)
        AI_CLIENT.query_model_async(prompt, wrapped_cb, on_chunk=chunk_cb, on_status=_view_mod.update_ai_progress_details, additional_options={"max_completion_tokens": 8192})

    def handle_ai_response(self, response):
        self.editor.setReadOnly(False)
        if not response: 
            QtWidgets.QMessageBox.warning(self, "AI Error", "No response from AI or an error occurred.")
            return
        
        c_struct = response.strip()
        if "```" in c_struct:
            parts = c_struct.split("```")
            for i in range(1, len(parts), 2):
                p = parts[i].strip()
                if p:
                    lines = p.split('\n')
                    if lines and lines[0].strip().lower() in ["c", "cpp"]:
                        c_struct = "\n".join(lines[1:]).strip()
                    else:
                        c_struct = p
                    break
        
        self.editor.setPlainText(c_struct)

    def copy_to_clipboard(self):
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(self.editor.toPlainText())
        print("[PseudoNote] Copied to clipboard.")

    def import_to_ida(self):
        c_code = self.editor.toPlainText()
        try:
            # Check for struct name using regex
            match = re.search(r'struct\s+(\w+)', c_code)
            struct_name = match.group(1) if match else "unknown_struct"
            
            # Simple parse using idc.parse_decls which adds to Local Types
            err = idc.parse_decls(c_code, 0)
            if err == 0:
                msg = f"Structure '{struct_name}' imported to Local Types successfully."
                # If callback provided, ask to apply
                if self.on_apply_callback:
                    reply = QtWidgets.QMessageBox.question(
                        self, "Apply Type", 
                        f"{msg}\n\nDo you want to apply this type to the variable?", 
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
                    )
                    if reply == QtWidgets.QMessageBox.Yes:
                        if self.on_apply_callback(struct_name):
                            QtWidgets.QMessageBox.information(self, "Applied", "Variable type updated.")
                        else:
                            QtWidgets.QMessageBox.warning(self, "Failed", "Failed to apply type to variable.")
                else:
                    QtWidgets.QMessageBox.information(self, "Success", msg + "\n(Open Shift+F1 to view)")
            else:
                 QtWidgets.QMessageBox.warning(self, "Import Failed", f"IDA failed to parse the C code (Error code: {err}).\nCheck text for syntax errors.")
        except Exception as e:
             QtWidgets.QMessageBox.critical(self, "Error", f"Exception during import: {e}")


class StructAnalysisHandler(idaapi.action_handler_t):
    """Analyze a variable usage to infer a C structure."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        widget = ctx.widget
        wtype = ctx.widget_type
        
        target_name = ""
        target_code = "" 
        vdui = None
        target_lvar_name = None
        
        if wtype == idaapi.BWN_PSEUDOCODE:
            vdui = ida_hexrays.get_widget_vdui(widget)
            if not vdui: return 0
            
            # Check item under cursor
            item = vdui.item
            if item:
                # Case 1: Cursor on a local variable expression (usage)
                if item.citype == ida_hexrays.VDI_EXPR and item.e:
                    if item.e.op == ida_hexrays.cot_var:
                        lvar = vdui.cfunc.get_lvars()[item.e.v.idx]
                        target_name = lvar.name
                        target_lvar_name = lvar.name
                    elif item.e.op == ida_hexrays.cot_obj:
                         name = idc.get_name(item.e.obj_ea)
                         if name: target_name = name
                
                # Case 2: Cursor on local var declaration (e.g. at top of function)
                elif item.citype == ida_hexrays.VDI_LVAR and item.l:
                    target_name = item.l.name
                    target_lvar_name = item.l.name
            
            if not target_name:
                print("[PseudoNote] Please right-click directly on a variable name.")
                return 0
            
            # Get function code
            try:
                target_code = str(vdui.cfunc)
            except:
                pass
                
        else:
            print("[PseudoNote] Structure analysis currently supports Pseudocode view only.")
            return 0
            
        if not target_name or not target_code: return 0
            
        # Define apply callback to update the variable type in IDA
        def on_apply(type_name):
            if not vdui or not target_lvar_name: return False
            try:
                for lvar in vdui.cfunc.get_lvars():
                    if lvar.name == target_lvar_name:
                        new_type = idaapi.tinfo_t()
                        # parse_decl expects "TYPE NAME dummy;" snippet to infer the type
                        # We apply it as a pointer, because variables we analyze structure for are almost always pointers
                        decl_str = f"struct {type_name} *dummy;"
                        if idaapi.parse_decl(new_type, None, decl_str, 0) or idaapi.parse_decl(new_type, None, f"{type_name} *dummy;", 0):
                            if vdui.set_lvar_type(lvar, new_type):
                                vdui.refresh_view(True)
                                return True
            except Exception as e:
                print(f"[PseudoNote] Failed to apply struct type: {e}")
            return False

        # Create and show the result dialog immediately
        dlg = StructAnalysisDialog(target_name, target_code, vdui, target_lvar_name, on_apply_callback=on_apply)
        if not hasattr(_view_mod, "_struct_dialogs"):
            _view_mod._struct_dialogs = []
        _view_mod._struct_dialogs.append(dlg)
        
        from pseudonote.qt_compat import QtCore
        dlg.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        dlg.show()

    def update(self, ctx):
        """Enable this action only for the Pseudocode view (where structure analysis is supported)."""
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

# ---------------------------------------------------------------------------
# Bulk Rename Handler
# ---------------------------------------------------------------------------
class BulkRenameHandler(idaapi.action_handler_t):
    """Launch the Bulk Function Renamer Dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None

    def activate(self, ctx):
        if not CONFIG.active_provider:
            print("[PseudoNote] AI Provider not configured.")
            return 0
            
        try:
            from pseudonote import renamer
            
            self.dlg = renamer.BulkRenamer(CONFIG, parent=None)
            self.dlg.show()
        except Exception as e:
            print(f"[PseudoNote] Error launching Bulk Renamer: {e}")
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Bulk Function Analyzer Handler
# ---------------------------------------------------------------------------
class BulkAnalyzeHandler(idaapi.action_handler_t):
    """Launch the Bulk Function Analyzer Dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None

    def activate(self, ctx):
        if not CONFIG.active_provider:
            print("[PseudoNote] AI Provider not configured.")
            return 0
            
        try:
            from pseudonote import analyzer
            
            self.dlg = analyzer.BulkAnalyzer(parent=None)
            self.dlg.show()
        except Exception as e:
            print(f"[PseudoNote] Error launching Bulk Analyzer: {e}")
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Bulk Variable Renamer Handler
# ---------------------------------------------------------------------------
class BulkVarRenameHandler(idaapi.action_handler_t):
    """Launch the Bulk Variable Renamer Dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None

    def activate(self, ctx):
        if not CONFIG.active_provider:
            print("[PseudoNote] AI Provider not configured.")
            return 0

        try:
            from pseudonote import var_renamer

            self.dlg = var_renamer.BulkVariableRenamer(parent=None)
            self.dlg.show()
        except Exception as e:
            print(f"[PseudoNote] Error launching Bulk Variable Renamer: {e}")
            import traceback
            traceback.print_exc()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Ask AI (Chat) Handler
# ---------------------------------------------------------------------------
class AskAIHandler(idaapi.action_handler_t):
    """Open a chat interface to ask questions about the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        _chat.show_chat(idaapi.get_screen_ea())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



class SettingsHandler(idaapi.action_handler_t):
    """Open the API Settings dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # We need to reach the view or at least the config
        # The view usually has the on_settings method
        import pseudonote.view as vm
        if vm._view_instance:
            vm._view_instance.on_settings()
        else:
            # Fallback if view not open: open a standalone dialog
            d = vm.SettingsDialog(CONFIG)
            d.exec_()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ShellcodeAnalystHandler(idaapi.action_handler_t):
    """Open the Shellcode Analysis dialog."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # We need to get the view module lazily
        import pseudonote.view as _view_mod
        
        # Gather data from selection if possible
        hex_data = ""
        asm_data = ""
        
        selection, start_ea, end_ea = idaapi.read_range_selection(None)
        if not selection:
            # Fallback to current item if no selection
            start_ea = idaapi.get_screen_ea()
            end_ea = idc.next_head(start_ea)
        
        if start_ea != idaapi.BADADDR:
            try:
                # Gather bytes
                bytes_count = end_ea - start_ea
                if 0 < bytes_count < 10000: # Safety limit
                    blob = idaapi.get_bytes(start_ea, bytes_count)
                    if blob:
                        hex_data = blob.hex(" ").upper()
                
                # Gather assembly
                items = []
                curr = start_ea
                while curr < end_ea and curr != idaapi.BADADDR:
                    items.append(curr)
                    curr = idc.next_head(curr, end_ea)
                
                asm_lines = []
                for ea in items:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        asm_lines.append(line)
                asm_data = "\n".join(asm_lines)

                # BUG FIX: If we only got one line of assembly but the range is multiple bytes,
                # and it's not explicitly code, it's likely we just hit the start of a data blob.
                # In this case, clear asm_data to force fallback to hex_data (which is complete).
                if len(asm_lines) == 1 and (end_ea - start_ea) > 1:
                    flags = idaapi.get_full_flags(start_ea)
                    if not idc.is_code(flags):
                        asm_data = ""
            except:
                pass

        dialog = _view_mod.ShellcodeAnalystDialog(hex_data, asm_data)
        dialog.show()
        # Keep a reference to prevent GC if needed
        if not hasattr(_view_mod, "_shellcode_analyst_dialogs"):
            _view_mod._shellcode_analyst_dialogs = []
        _view_mod._shellcode_analyst_dialogs.append(dialog)
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_DISABLE_FOR_WIDGET
        return idaapi.AST_ENABLE_ALWAYS

# ---------------------------------------------------------------------------
# Search Utilities Handlers
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dump Bytes Handler
# ---------------------------------------------------------------------------
class DumpBytesHandler(idaapi.action_handler_t):
    """Dump bytes from a selected range or global variable to a file."""
    def __init__(self):
        super(DumpBytesHandler, self).__init__()

    def activate(self, ctx):
        import ida_bytes
        import ida_kernwin
        import os

        target_ea = idaapi.BADADDR
        size = 0

        # 1. Try to get selection
        ok, start_ea, end_ea = idaapi.read_range_selection(ctx.widget)
        if ok:
            target_ea = start_ea
            size = end_ea - start_ea
        else:
            # 2. Try to get item under cursor in Pseudocode
            v = ida_hexrays.get_widget_vdui(ctx.widget)
            if v:
                # In Hex-Rays, v.item usually holds the current item
                try:
                    if v.item.e.op == ida_hexrays.cot_obj:
                        target_ea = v.item.e.obj_ea
                except:
                    pass
                
                if target_ea == idaapi.BADADDR:
                    # Try highlight
                    h = ida_kernwin.get_highlight(v.ct)
                    if h and h[0]:
                        target_ea = idc.get_name_ea_simple(h[0])
            
            # 3. Try to get item under cursor in Disassembly
            if target_ea == idaapi.BADADDR:
                target_ea = ida_kernwin.get_screen_ea()
                # If we are on a name, it's better
                h = ida_kernwin.get_highlight(ctx.widget)
                if h and h[0]:
                    ea_h = idc.get_name_ea_simple(h[0])
                    if ea_h != idaapi.BADADDR:
                        target_ea = ea_h

        if target_ea == idaapi.BADADDR:
            print("[PseudoNote] Dump Bytes: Could not determine address.")
            return 0

        # Try to guess size if not from selection
        if size == 0:
            size = ida_bytes.get_item_size(target_ea)
            if size <= 1: # Default to something reasonable if it's just a byte or unknown
                size = 0x100 

        # Ask for size
        size_str = ida_kernwin.ask_str(hex(size), 0, f"Enter size to dump from 0x{target_ea:X}:")
        if not size_str:
            return 0
        
        try:
            if size_str.lower().startswith("0x"):
                base = 16
                s_val = size_str[2:]
            else:
                base = 10
                s_val = size_str
            size = int(s_val, base)
        except ValueError:
            print("[PseudoNote] Dump Bytes: Invalid size.")
            return 0

        if size <= 0:
            return 0

        # Read bytes
        blob = ida_bytes.get_bytes(target_ea, size)
        if not blob:
            print(f"[PseudoNote] Dump Bytes: Failed to read {size} bytes at 0x{target_ea:X}.")
            return 0

        # Open file dialog
        default_name = idc.get_name(target_ea) or f"dump_{target_ea:X}"
        # Sanitize filename
        default_name = "".join([c for c in default_name if c.isalnum() or c in (' ', '.', '_', '-')]).strip()
        if not default_name: default_name = "dump"
        
        save_path = ida_kernwin.ask_file(1, f"{default_name}.bin", "Save dump as...")
        if not save_path:
            return 0

        try:
            with open(save_path, "wb") as f:
                f.write(blob)
            print(f"[PseudoNote] Dumped {len(blob)} bytes to {save_path}")
        except Exception as e:
            print(f"[PseudoNote] Dump Bytes: Failed to write file: {e}")

        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS, idaapi.BWN_PSEUDOCODE):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class SearchBytesVTHandler(idaapi.action_handler_t):
    """Search highlighted bytes in VirusTotal."""
    def __init__(self):
        super(SearchBytesVTHandler, self).__init__()

    def activate(self, ctx):
        import binascii
        import urllib.parse
        from pseudonote.qt_compat import QtGui, QtCore
        import ida_bytes
        
        ok, start_ea, end_ea = idaapi.read_range_selection(ctx.widget)
        if not ok:
            # Fallback to current item if no selection
            start_ea = idaapi.get_screen_ea()
            end_ea = idc.next_head(start_ea)
            
        if start_ea != idaapi.BADADDR and end_ea > start_ea:
            size = end_ea - start_ea
            if size > 0 and size < 10000:
                blob = ida_bytes.get_bytes(start_ea, size)
                if blob:
                    hex_str = binascii.hexlify(blob).decode("utf-8").upper()
                    query = urllib.parse.quote("content: {" + hex_str + "}")
                    url = f"https://www.virustotal.com/gui/search?query={query}&type=files"
                    QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
                    return 1
        print("[PseudoNote] Please highlight assembly bytes to search.")
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class SearchBytesCyberChefHandler(idaapi.action_handler_t):
    """Add highlighted bytes to CyberChef input."""
    def __init__(self):
        super(SearchBytesCyberChefHandler, self).__init__()

    def activate(self, ctx):
        import base64
        from pseudonote.qt_compat import QtGui, QtCore
        import ida_bytes
        
        ok, start_ea, end_ea = idaapi.read_range_selection(ctx.widget)
        if not ok:
            start_ea = idaapi.get_screen_ea()
            end_ea = idc.next_head(start_ea)
            
        if start_ea != idaapi.BADADDR and end_ea > start_ea:
            size = end_ea - start_ea
            if size > 0 and size < 10000:
                blob = ida_bytes.get_bytes(start_ea, size)
                if blob:
                    encoded = base64.b64encode(blob).decode('utf-8')
                    url = f"https://gchq.github.io/CyberChef/#input={encoded}"
                    QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
                    return 1
        print("[PseudoNote] Please highlight assembly bytes to send.")
        return 1

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class SearchStringHandler(idaapi.action_handler_t):
    """Search string in various engines."""
    def __init__(self, mode):
        super(SearchStringHandler, self).__init__()
        self.mode = mode

    def activate(self, ctx):
        import urllib.parse
        from pseudonote.qt_compat import QtGui, QtCore
        import ida_kernwin
        
        text = ""
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if v:
            highlight = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
            if highlight and highlight[0]:
                text = highlight[0]
        else:
            highlight = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
            if highlight and highlight[0]:
                text = highlight[0]
                
        if not text:
            # If no highlight, prompt user
            text = ida_kernwin.ask_str("", 0, "Enter string to search:")
            
        if text:
            text = text.strip('"').strip("'")
            if self.mode == "vt":
                query = urllib.parse.quote('content: "' + text + '"')
                url = f"https://www.virustotal.com/gui/search?query={query}&type=files"
            elif self.mode == "google":
                query = urllib.parse.quote('"' + text + '"')
                url = f"https://www.google.com/search?q={query}"
            elif self.mode == "github":
                query = urllib.parse.quote(text)
                url = f"https://github.com/search?q={query}&type=code"
            elif self.mode == "msdn":
                query = urllib.parse.quote(text)
                url = f"https://learn.microsoft.com/en-us/search/?terms={query}&category=Documentation"
            elif self.mode == "cyberchef":
                import base64
                encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
                url = f"https://gchq.github.io/CyberChef/#input={encoded}"
            
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class FlossStringsHandler(idaapi.action_handler_t):
    """Launch the FLOSS string discovery tool."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            from pseudonote.floss_strings import show_floss_strings_ui
            show_floss_strings_ui()
        except ImportError:
            # Fallback if the file is in the current directory
            try:
                import floss_strings
                floss_strings.show_floss_strings_ui()
            except Exception as e:
                print(f"[PseudoNote] Failed to launch FLOSS Strings Tool: {e}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# IDA-View Advanced Copy handlers
# ---------------------------------------------------------------------------



def _get_selected_instructions():
    import ida_kernwin
    import ida_bytes
    selection, start_ea, end_ea = ida_kernwin.read_range_selection(None)
    if not selection:
        start_ea = ida_kernwin.get_screen_ea()
        end_ea = ida_bytes.next_head(start_ea, idaapi.BADADDR)
    
    ea = start_ea
    while ea < end_ea and ea != idaapi.BADADDR:
        if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            yield ea
        ea = ida_bytes.next_head(ea, end_ea)

def _extract_bytes_for_copy(ea, mask_mode=None):
    import ida_ua, idc, ida_bytes
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)
    
    if insn.size == 0:
        return []
    
    raw = ida_bytes.get_bytes(ea, insn.size)
    if not raw:
        return []
        
    mask = [False] * insn.size
    
    if mask_mode == "yara_mask":
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem == "call" or mnem.startswith("j"):
            off = insn.ops[0].offb if insn.ops[0].offb != 0 else 1
            for i in range(off, insn.size):
                mask[i] = True
        else:
            for op in insn.ops:
                if op.type != ida_ua.o_void and op.offb != 0:
                    if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
                        # Mask addresses
                        for i in range(op.offb, insn.size):
                            mask[i] = True
    elif mask_mode == "yara_no_imm":
        for op in insn.ops:
            if op.type != ida_ua.o_void and op.offb != 0:
                if op.type in (ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ):
                    for i in range(op.offb, insn.size):
                        mask[i] = True
    elif mask_mode == "yara_opcodes":
        first_offb = insn.size
        for op in insn.ops:
            if op.type != ida_ua.o_void and op.offb != 0 and op.offb < first_offb:
                first_offb = op.offb
        for i in range(1, insn.size):
            if i >= first_offb: mask[i] = True
        if first_offb > 2:
            for i in range(2, first_offb): mask[i] = True
    
    res = []
    for i in range(insn.size):
        if mask[i]:
            res.append(None) # '??'
        else:
            res.append(raw[i])
    return res

class AdvancedCopyHandler(idaapi.action_handler_t):
    """Handler for copying instruction bytes into various formats."""
    def __init__(self, mode):
        idaapi.action_handler_t.__init__(self)
        self.mode = mode
    
    def activate(self, ctx):
        from pseudonote.qt_compat import QtWidgets
        if self.mode == "disasm":
            import idc
            lines = []
            for ea in _get_selected_instructions():
                l = idc.generate_disasm_line(ea, 0)
                if l: lines.append(idaapi.tag_remove(l))
            output = "\n".join(lines)
            QtWidgets.QApplication.clipboard().setText(output)
            print("[PseudoNote] Copied disassembly to clipboard.")
            return 1

        all_bytes = []
        for ea in _get_selected_instructions():
            all_bytes.append(_extract_bytes_for_copy(ea, mask_mode=self.mode))
            
        if not all_bytes:
            print("[PseudoNote] No instructions selected for advanced copy.")
            return 0
            
        flat_bytes = []
        for b_arr in all_bytes:
            flat_bytes.extend(b_arr)
            
        output = ""
        if self.mode in ("yara_raw", "yara_mask", "yara_no_imm", "yara_opcodes"):
            hex_parts = ["??" if b is None else f"{b:02X}" for b in flat_bytes]
            output = " ".join(hex_parts)
        elif self.mode == "yara_rule":
            hex_parts = [f"{b:02X}" for b in flat_bytes]
            val = " ".join(hex_parts)
            output = f"rule auto_gen_rule {{\n    strings:\n        $seq1 = {{ {val} }}\n    condition:\n        $seq1\n}}"
        elif self.mode == "python":
            hex_parts = [f"\\x{b:02X}" if b is not None else "\\x00" for b in flat_bytes]
            output = 'b"' + "".join(hex_parts) + '"'
        elif self.mode == "c_array":
            hex_parts = [f"0x{b:02X}" if b is not None else "0x00" for b in flat_bytes]
            output = "unsigned char seq[] = { " + ", ".join(hex_parts) + " };"
            
        QtWidgets.QApplication.clipboard().setText(output)
        preview = output.replace('\n', ' ')
        if len(preview) > 60: preview = preview[:57] + "..."
        print(f"[PseudoNote] Copied: {preview}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
