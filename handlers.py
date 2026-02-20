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

from pseudonote.qt_compat import QtWidgets, QtGui
from pseudonote.config import CONFIG, LOGGER
import pseudonote.ai_client as _ai_mod


def _get_ai_client():
    return _ai_mod.AI_CLIENT


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
        print(f"[PseudoNote] Rename Variables: failed to parse JSON response: {e}")
        return

    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        if idaapi.IDA_SDK_VERSION < 760:
            lvars = {lvar.name: lvar for lvar in view.cfunc.lvars}
            if n in lvars:
                if view.rename_lvar(lvars[n], names[n], True):
                    replaced.append(n)
        else:
            if ida_hexrays.rename_lvar(function_addr, n, names[n]):
                replaced.append(n)

    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(fr'\b{n}\b', names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
    print(f"[PseudoNote] Rename Variables: {len(replaced)} variable(s) renamed.")


class RenameVariablesHandler(idaapi.action_handler_t):
    """Ask AI to suggest better variable names and apply them automatically."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT:
            print("[PseudoNote] AI client not initialised.")
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not decompiler_output or not v:
            print("[PseudoNote] Could not decompile the current function or get view.")
            return 0
        prompt = (
            "You are an expert reverse engineer. Review the C function code provided below:\n\n{decompiler_output}\n\n"
            "Identify variables with generic or unhelpful names (e.g., v1, a2, result). "
            "Propose more descriptive names based on their usage, context, and data flow. "
            "Output ONLY a valid JSON object mapping the original variable names (keys) to the suggested new names (values). "
            "Do NOT include any explanations or markdown formatting outside the JSON."
        ).format(decompiler_output=str(decompiler_output))
        AI_CLIENT.query_model_async(
            prompt,
            functools.partial(_pn_rename_callback, address=idaapi.get_screen_ea(), view=v)
        )
        print("[PseudoNote] Rename Variables request sent...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Rename Function (Code) handler
# ---------------------------------------------------------------------------
class RenameFunctionHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function name based on code logic and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT:
            print("[PseudoNote] AI client not initialised.")
            return 0
        ea = idaapi.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui:
            print("[PseudoNote] Could not decompile the current function or get view.")
            return 0
        prompt = (
            "Analyze the following C function code:\n"
            f"{str(cfunc)}\n"
            "Suggest a concise new name for this function. "
            "Only reply with the new function name, prefixed with 'fn_'."
        )
        def callback(response):
            if not response:
                print("[PseudoNote] Rename Function: no response from AI.")
                return
            new_name = response.strip().split()[0]
            func = idaapi.get_func(ea)
            if not func:
                print("[PseudoNote] Could not find function at address.")
                return
            old_name = idc.get_func_name(func.start_ea)
            if new_name == old_name or not re.match(r'^fn_[A-Za-z_][A-Za-z0-9_]*$', new_name):
                print(f"[PseudoNote] Invalid or unchanged name suggested: {new_name}")
                return
            success = idc.set_name(func.start_ea, new_name, idc.SN_AUTO)
            if success:
                print(f"[PseudoNote] Function renamed to: {new_name}")
                if vdui:
                    vdui.refresh_view(True)
            else:
                print(f"[PseudoNote] Failed to rename function to: {new_name}")
        AI_CLIENT.query_model_async(prompt, callback)
        print("[PseudoNote] Rename Function (Code) request sent...")
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
        if not AI_CLIENT:
            print("[PseudoNote] AI client not initialised.")
            return 0
        ea = idaapi.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui:
            print("[PseudoNote] Could not decompile the current function or get view.")
            return 0
        prompt = (
            "Analyze the following C function code in the context of malware reverse engineering:\n"
            f"{str(cfunc)}\n"
            "Suggest a concise new name for this function. "
            "Only reply with the new function name, prefixed with 'fn_'."
        )
        def callback(response):
            if not response:
                print("[PseudoNote] Rename Function (Malware): no response from AI.")
                return
            new_name = response.strip().split()[0]
            func = idaapi.get_func(ea)
            if not func:
                print("[PseudoNote] Could not find function at address.")
                return
            old_name = idc.get_func_name(func.start_ea)
            if new_name == old_name or not re.match(r'^fn_[A-Za-z_][A-Za-z0-9_]*$', new_name):
                print(f"[PseudoNote] Invalid or unchanged name suggested: {new_name}")
                return
            success = idc.set_name(func.start_ea, new_name, idc.SN_AUTO)
            if success:
                print(f"[PseudoNote] Function renamed to: {new_name}")
                if vdui:
                    vdui.refresh_view(True)
            else:
                print(f"[PseudoNote] Failed to rename function to: {new_name}")
        AI_CLIENT.query_model_async(prompt, callback)
        print("[PseudoNote] Rename Function (Malware) request sent...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Suggest Function Signature Handler
# ---------------------------------------------------------------------------
class SuggestFunctionSignatureHandler(idaapi.action_handler_t):
    """Ask AI to suggest a function signature and apply it."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT:
            print("[PseudoNote] AI client not initialised.")
            return 0
        ea = idaapi.get_screen_ea()
        try:
             cfunc = ida_hexrays.decompile(ea)
        except:
             print("[PseudoNote] Failed to decompile.")
             return 0
             
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not vdui:
            print("[PseudoNote] Could not decompile the current function or get view.")
            return 0
            
        prompt = (
            "Analyze the following C function code:\n"
            f"{str(cfunc)}\n\n"
            "Suggest a valid C function prototype (signature) for this function.\n"
            "Infer the return type, calling convention, function name, and argument types/names based on usage.\n"
            "Return ONLY the C signature string (e.g. `int __fastcall MyFunc(char *a1, int a2)`).\n"
            "Do not include semicolon or body."
        )
        
        def callback(response):
            if not response:
                print("[PseudoNote] Suggest Signature: no response from AI.")
                return
            
            # Extract signature
            clean_sig = response.strip()
            # Remove markdown code blocks
            match = re.search(r"```(?:c|cpp)?\s*(.*?)\s*```", clean_sig, re.DOTALL)
            if match:
                clean_sig = match.group(1).strip()
            
            # Remove trailing semicolon or braces
            clean_sig = clean_sig.split('{')[0].strip().rstrip(';')

            msg = f"AI Suggested Signature:\n\n{clean_sig}\n\nApply this signature?"
            # ask_yn returns 1 (Yes), 0 (No), -1 (Cancel)
            resp = ida_kernwin.ask_yn(1, msg)
            
            if resp == 1:
                # Apply - append semicolon for SetType
                if idc.SetType(cfunc.entry_ea, clean_sig + ";"):
                    print(f"[PseudoNote] Applied signature: {clean_sig}")
                    vdui.refresh_view(True)
                else:
                    print(f"[PseudoNote] Failed to apply signature: {clean_sig}. Check syntax.")
        
        AI_CLIENT.query_model_async(prompt, callback)
        print("[PseudoNote] Suggest Function Signature request sent...")
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

        target = idaapi.treeloc_t()
        target.ea = int(comment_address)
        target.itp = comment_placement
        cfunc.set_user_cmt(target, comment_text)
        applied_count += 1

    if applied_count > 0:
        cfunc.save_user_cmts()
        cfunc.del_orphan_cmts()
        if view:
            view.refresh_view(True)
        print(f"[PseudoNote] Applied {applied_count} comments.")
    else:
        print("[PseudoNote] No comments were applied.")

class CommentHandler(idaapi.action_handler_t):
    """Ask AI to add helpful comments to the current function."""
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        AI_CLIENT = _get_ai_client()
        if not AI_CLIENT:
            print("[PseudoNote] AI client not initialised.")
            return 0
        
        ea = idaapi.get_screen_ea()
        try:
            cfunc = ida_hexrays.decompile(ea)
        except:
            print("[PseudoNote] Could not decompile function.")
            return 0
            
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if not cfunc or not v:
            print("[PseudoNote] Could not decompile the current function or get view.")
            return 0

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
        
        AI_CLIENT.query_model_async(
            prompt,
            functools.partial(_pn_comment_callback, cfunc=cfunc, pseudocode_lines=pseudocode_lines, view=v),
             additional_options={"response_format": {"type": "json_object"}}
        )
        print("[PseudoNote] AI Commenting request sent...")
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
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Structure Analysis Handler & Dialog
# ---------------------------------------------------------------------------
class StructAnalysisDialog(QtWidgets.QDialog):
    def __init__(self, c_struct, on_apply_callback=None, parent=None):
        super(StructAnalysisDialog, self).__init__(parent)
        self.setWindowTitle("Structure Analysis (AI)")
        self.resize(600, 500)
        
        self.on_apply_callback = on_apply_callback
        
        layout = QtWidgets.QVBoxLayout()
        
        # Editor
        self.editor = QtWidgets.QTextEdit()
        self.editor.setPlainText(c_struct)
        self.editor.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.editor)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        
        copy_btn = QtWidgets.QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(copy_btn)
        
        import_btn = QtWidgets.QPushButton("Import to IDA")
        import_btn.clicked.connect(self.import_to_ida)
        btn_layout.addWidget(import_btn)
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        
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
                        self.on_apply_callback(struct_name)
                        QtWidgets.QMessageBox.information(self, "Applied", "Variable type updated.")
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
            
        if not target_name or not target_code:
            return 0
            
        print(f"[PseudoNote] Analyzing structure for '{target_name}'...")
        
        # Prepare Prompt
        prompt = (
            f"Analyze the C code below. Focus on the usage of variable `{target_name}`.\n"
            f"Infer the most likely C structure definition that `{target_name}` represents (or points to).\n"
            "Analyze all dereferences (e.g. `v5 + 16`, `v5->field_10`) to find fields.\n"
            "Return ONLY the C struct definition valid for an IDA header input.\n"
            "Start the struct name with `Struct_{target_name}` or a descriptive name.\n\n"
            "```c\n"
            f"{target_code}\n"
            "```"
        )
        
        if AI_CLIENT:
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_response, target_name=target_name, vdui=vdui, lvar_name=target_lvar_name),
                additional_options={"max_completion_tokens": 2048}
            )
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET
        
    def handle_response(self, response, target_name, vdui, lvar_name):
        if not response:
            print("[PseudoNote] AI Analysis failed or returned empty.")
            return
            
        # Robustly extract code block
        code_match = re.search(r"```(?:c|cpp|C)?\n(.*?)\n```", response, re.DOTALL)
        
        if code_match:
            clean_code = code_match.group(1).strip()
        else:
            # Fallback
            struct_match = re.search(r"(typedef\s+)?struct\s+\w+\s*\{.*?\};", response, re.DOTALL)
            if struct_match:
                clean_code = struct_match.group(0).strip()
            else:
                clean_code = response.strip()

        # Define Callback for applying type
        def apply_type_callback(struct_name):
             if not vdui or not lvar_name: return
             
             import ida_typeinf
             idati = ida_typeinf.get_idati()
             tif = ida_typeinf.tinfo_t()
             
             if tif.get_named_type(idati, struct_name):
                 # Find the lvar again by name (in case index shifted)
                 cfunc = vdui.cfunc
                 found_lvar = None
                 for lv in cfunc.get_lvars():
                     if lv.name == lvar_name:
                         found_lvar = lv
                         break
                 
                 if found_lvar:
                     success = False
                     is_ptr = False
                     
                     # Try direct type first
                     if vdui.set_lvar_type(found_lvar, tif):
                         success = True
                     else:
                         # Try pointer type
                         ptif = ida_typeinf.tinfo_t()
                         ptif.create_ptr(tif)
                         if vdui.set_lvar_type(found_lvar, ptif):
                             success = True
                             is_ptr = True
                     
                     if success:
                         print(f"[PseudoNote] Applied new type to {lvar_name}.")
                         vdui.refresh_view(True) # Force refresh to update cfunc
                         
                         # --- Auto-Rename Logic ---
                         # Derive base name from struct, e.g. "Struct_Student" -> "Student"
                         base_name = struct_name
                         if base_name.lower().startswith("struct_"):
                             base_name = base_name[7:]
                         elif base_name.lower().startswith("struct"):
                             base_name = base_name[6:]
                         
                         # Cleanup and formatting
                         base_name = base_name.strip("_")
                         if not base_name: base_name = "obj"
                         
                         base_name = base_name.lower()
                         
                         new_name = ("p_" if is_ptr else "") + base_name
                         
                         # We MUST find the lvar again because set_lvar_type/refresh invalidated old object
                         cfunc = vdui.cfunc
                         lvar_to_rename = None
                         for lv in cfunc.get_lvars():
                             # We search by the OLD name (lvar_name), because rename hasn't happened yet
                             if lv.name == lvar_name:
                                 lvar_to_rename = lv
                                 break
                        
                         if lvar_to_rename:
                             # 1 = make name unique if taken
                             vdui.rename_lvar(lvar_to_rename, new_name, 1)
                             print(f"[PseudoNote] Renamed '{lvar_name}' to '{new_name}'.")
                         else:
                             print(f"[PseudoNote] Could not find '{lvar_name}' to rename (maybe it optimized away?).")

                     else:
                         print(f"[PseudoNote] Failed to apply type to {lvar_name}. It might be incompatible.")
                 else:
                     print(f"[PseudoNote] Variable {lvar_name} not found in current view.")
             else:
                 print(f"[PseudoNote] Type {struct_name} not found in Local Types.")

        def show_ui():
            dlg = StructAnalysisDialog(clean_code, on_apply_callback=apply_type_callback if lvar_name else None)
            dlg.exec_()
            
        ida_kernwin.execute_sync(show_ui, ida_kernwin.MFF_FAST)


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


