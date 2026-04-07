import idaapi
import idc
import idautils
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_kernwin
from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem

_xrefs_win = None

_icon_cache = {}

def get_badge_icon(typ):
    """
    Generate a dynamic badge icon for the Call Hierarchy.
    typ: 'dir', 'api', or 'func'
    """
    if typ in _icon_cache:
        return _icon_cache[typ]
        
    try:
        pixmap = QtGui.QPixmap(16, 16)
        pixmap.fill(QtGui.QColor(0, 0, 0, 0)) # Safe transparent
        painter = QtGui.QPainter(pixmap)
        
        # Safely handle Antialiasing for PySide6 vs PyQt5
        try:
            if hasattr(QtGui.QPainter, 'RenderHint') and hasattr(QtGui.QPainter.RenderHint, 'Antialiasing'):
                painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
            elif hasattr(QtGui.QPainter, 'Antialiasing'):
                painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        except Exception:
            pass
            
        if typ == 'api':
            bg_color = QtGui.QColor("#2E7D32") # Dark green for API
            text = "API"
            font_size = 7
        elif typ == 'func':
            bg_color = QtGui.QColor("#0277BD") # Deep blue for Function
            text = "ƒx"
            font_size = 9
        else:
            painter.end()
            return QtWidgets.QApplication.style().standardIcon(QtWidgets.QStyle.SP_DirIcon)
            
        path = QtGui.QPainterPath()
        path.addRoundedRect(0, 0, 16, 16, 3, 3)
        painter.fillPath(path, bg_color)
        
        font = painter.font()
        font.setPixelSize(font_size)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QtGui.QColor(255, 255, 255)) # Safe white
        
        rect = QtCore.QRect(0, 0, 16, 16)
        
        # Safe AlignmentCenter
        align = QtCore.Qt.AlignCenter if hasattr(QtCore.Qt, 'AlignCenter') else QtCore.Qt.AlignmentFlag.AlignCenter
        painter.drawText(rect, align, text)
        painter.end()
        
        icon = QtGui.QIcon(pixmap)
        _icon_cache[typ] = icon
        return icon
    except Exception:
        style = QtWidgets.QApplication.style()
        if typ == 'api':
            return style.standardIcon(QtWidgets.QStyle.SP_ComputerIcon)
        return style.standardIcon(QtWidgets.QStyle.SP_FileIcon)

class XrefTreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, parent, text, target_func_ea, exact_ea, is_ref_to, is_root=False, is_api=False):
        super().__init__(parent)
        self.setText(0, text)
        self.target_func_ea = target_func_ea
        self.exact_ea = exact_ea
        self.is_ref_to = is_ref_to
        self.loaded = False
        self.is_root = is_root
        self.is_api = is_api
        
        # Apply specialized icons based on context
        if text in ["Used By", "Uses"]:
            style = QtWidgets.QApplication.style()
            icon = style.standardIcon(QtWidgets.QStyle.SP_DirIcon)
        elif self.is_api:
            icon = get_badge_icon('api')
        else:
            icon = get_badge_icon('func')
        self.setIcon(0, icon)
        
        if self.is_root:
            font = self.font(0)
            font.setBold(True)
            self.setFont(0, font)

        # Child dummy item
        dummy = QtWidgets.QTreeWidgetItem(self)
        dummy.setText(0, "Loading...")

class XrefsDialog(QtWidgets.QDialog):
    def __init__(self, target_ea):
        parent = QtWidgets.QApplication.activeWindow()
        super().__init__(parent)
        # Title will be set by reload_tree()
        self.resize(550, 600)
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowStaysOnTopHint)
        
        self.target_ea = target_ea
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Top Toolbar Area
        header_layout = QtWidgets.QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter functions (e.g. memset)...")
        # Ensure older Qt compat, as setClearButtonEnabled is Qt5.2+
        if hasattr(self.filter_edit, 'setClearButtonEnabled'):
            self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.on_filter_changed)
        self.filter_edit.setMinimumWidth(200)
        header_layout.addWidget(self.filter_edit)
        
        self.show_api_cb = QtWidgets.QCheckBox("Show API Functions")
        self.show_api_cb.setChecked(True)
        self.show_api_cb.toggled.connect(self.reload_tree)
        header_layout.addWidget(self.show_api_cb)
        
        self.show_reg_calls_cb = QtWidgets.QCheckBox("Show Indirect Calls")
        self.show_reg_calls_cb.setChecked(False)
        self.show_reg_calls_cb.setToolTip("Show register calls (e.g. call eax)")
        self.show_reg_calls_cb.toggled.connect(self.reload_tree)
        header_layout.addWidget(self.show_reg_calls_cb)
        
        # Add a refresh button
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setToolTip("Reload the cross-references")
        self.refresh_btn.clicked.connect(self.reload_tree)
        self.refresh_btn.setMaximumWidth(70)
        header_layout.addWidget(self.refresh_btn)
        
        # Add a sync button
        self.sync_btn = QtWidgets.QPushButton("Sync")
        self.sync_btn.setToolTip("Sync to current function in IDA")
        self.sync_btn.clicked.connect(self.sync_to_current)
        self.sync_btn.setMaximumWidth(60)
        header_layout.addWidget(self.sync_btn)
        
        layout.addLayout(header_layout)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemExpanded.connect(self.on_expand)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        self.tree.setStyleSheet("""
            QTreeWidget { 
                border: 1px solid #777777;
                border-radius: 4px;
            }
            QTreeWidget::item { padding: 4px; }
            QLineEdit {
                padding: 4px;
                border: 1px solid #777777;
                border-radius: 4px;
            }
            QPushButton {
                padding: 4px 8px;
                border: 1px solid #777777;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.tree)
        
        self.reload_tree()
        
    def reload_tree(self):
        self.tree.clear()
        name = idc.get_func_name(self.target_ea)
        if not name:
            name = idc.get_name(self.target_ea, idaapi.GN_VISIBLE)
        
        if name:
            self.setWindowTitle(f"Call Hierarchy: {name}")
        else:
            self.setWindowTitle(f"Call Hierarchy: 0x{self.target_ea:X}")
            
        f = idaapi.get_func(self.target_ea)
        is_api = bool(f and (f.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK)))
        
        top = XrefTreeItem(self.tree, f"Function: {name}()" if name else f"Function: 0x{self.target_ea:X}", self.target_ea, self.target_ea, is_ref_to=True, is_root=True, is_api=is_api)
        top.loaded = True
        top.takeChild(0)
        
        self.root_to = XrefTreeItem(top, "Used By", self.target_ea, self.target_ea, is_ref_to=True, is_root=True)
        self.root_from = XrefTreeItem(top, "Uses", self.target_ea, self.target_ea, is_ref_to=False, is_root=True)
        
        top.setExpanded(True)
        self.root_to.setExpanded(True)
        
    def on_expand(self, item):
        if getattr(item, 'loaded', True): return
        item.takeChild(0)
        item.loaded = True
        
        visited = set()
        
        if item.is_ref_to:
            refs = list(idautils.CodeRefsTo(item.target_func_ea, 0)) + list(idautils.DataRefsTo(item.target_func_ea))
            for xref in refs:
                f = idaapi.get_func(xref)
                if f:
                    name = idc.get_func_name(f.start_ea)
                    if (xref, f.start_ea) not in visited:
                        is_api = bool(f.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK))
                        XrefTreeItem(item, f"{name} (0x{xref:X})", f.start_ea, xref, True, is_root=False, is_api=is_api)
                        visited.add((xref, f.start_ea))
        else:
            for ea in idautils.FuncItems(item.target_func_ea):
                refs = list(idautils.CodeRefsFrom(ea, 0)) + list(idautils.DataRefsFrom(ea))
                has_func_call = False
                
                mnem = idc.print_insn_mnem(ea).lower()
                is_call_insn = (mnem == "call")
                is_jmp_insn = (mnem == "jmp")
                
                for xref in refs:
                    f = idaapi.get_func(xref)
                    if f and f.start_ea != item.target_func_ea:
                        has_func_call = True
                        name = idc.get_func_name(f.start_ea)
                        if (ea, f.start_ea) not in visited:
                            is_api = bool(f.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK))
                            XrefTreeItem(item, f"{name} (0x{ea:X})", f.start_ea, ea, False, is_root=False, is_api=is_api)
                            visited.add((ea, f.start_ea))
                    elif not f and self.show_api_cb.isChecked() and (is_call_insn or is_jmp_insn):
                        name = idc.get_name(xref, idaapi.GN_VISIBLE)
                        if name:
                            has_func_call = True
                            if (ea, xref) not in visited:
                                child = XrefTreeItem(item, f"{name} (0x{ea:X})", xref, ea, False, is_root=False, is_api=True)
                                child.takeChild(0) # API calls are leaf nodes
                                child.loaded = True
                                visited.add((ea, xref))
                                
                if self.show_reg_calls_cb.isChecked() and not has_func_call:
                    if is_call_insn:
                        disasm = idc.generate_disasm_line(ea, 0)
                        if disasm and (ea, 0) not in visited:
                            # Use clean disasm removing color codes if any
                            clean_disasm = idaapi.tag_remove(disasm)
                            child = XrefTreeItem(item, f"{clean_disasm} (0x{ea:X})", idaapi.BADADDR, ea, False, is_root=False, is_api=False)
                            child.takeChild(0) # Register calls are leaf nodes
                            child.loaded = True
                            visited.add((ea, 0))
                            
    def sync_to_current(self):
        ea = idaapi.get_screen_ea()
        f = idaapi.get_func(ea)
        if f:
            self.target_ea = f.start_ea
            self.reload_tree()
        else:
            # Try to see if we are on an API call or something
            view = idaapi.get_current_viewer()
            wtype = idaapi.get_widget_type(view)
            target_ea = idaapi.BADADDR
            
            if wtype == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(view)
                if vu and vu.item.citype == idaapi.VDI_EXPR:
                    if vu.item.e.op == idaapi.cot_obj:
                        target_ea = vu.item.e.obj_ea
                    elif vu.item.e.op == idaapi.cot_call and vu.item.e.x.op == idaapi.cot_obj:
                        target_ea = vu.item.e.x.obj_ea
            
            if target_ea == idaapi.BADADDR:
                hl = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
                if hl and hl[0]:
                    h_ea = idc.get_name_ea_simple(hl[0])
                    if h_ea != idaapi.BADADDR:
                        target_ea = h_ea
            
            if target_ea != idaapi.BADADDR:
                self.target_ea = target_ea
                self.reload_tree()
            else:
                print("[PseudoNote] No function at current EA to sync.")
                            
    def on_double_click(self, item, col):
        if hasattr(item, 'exact_ea') and item.exact_ea != idaapi.BADADDR and not getattr(item, 'is_root', False):
            vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
            if vu:
                vu.jumpto(item.exact_ea, True)
            else:
                idaapi.jumpto(item.exact_ea)

    def on_filter_changed(self, text):
        self._apply_filter(self.tree.invisibleRootItem(), text.lower())
        
    def _apply_filter(self, item, text):
        visible = False
        if text in item.text(0).lower():
            visible = True
            
        for i in range(item.childCount()):
            child = item.child(i)
            if self._apply_filter(child, text):
                visible = True
                
        # Root items ("Used By", "Uses") should always be visible if text is empty
        if getattr(item, 'is_root', False) and not text:
            visible = True
            
        # Top-level should always be visible
        if item.parent() is None:
            visible = True
            
        item.setHidden(not visible)
        return visible

def show_dnspy_xrefs():
    global _xrefs_win
    ea = idaapi.get_screen_ea()
    target_ea = idaapi.BADADDR
    
    view = idaapi.get_current_viewer()
    wtype = idaapi.get_widget_type(view)
    
    if wtype == idaapi.BWN_PSEUDOCODE:
        vu = idaapi.get_widget_vdui(view)
        if vu and vu.item.citype == idaapi.VDI_EXPR:
            if vu.item.e.op == idaapi.cot_obj:
                target_ea = vu.item.e.obj_ea
            elif vu.item.e.op == idaapi.cot_call and vu.item.e.x.op == idaapi.cot_obj:
                target_ea = vu.item.e.x.obj_ea

    if target_ea == idaapi.BADADDR:
        hl = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        if hl and hl[0]:
            h_ea = idc.get_name_ea_simple(hl[0])
            if h_ea != idaapi.BADADDR:
                target_ea = h_ea
                
    if target_ea == idaapi.BADADDR:
        target_ea = ea
        
    f = idaapi.get_func(target_ea)
    if not f:
        print("No function found for call hierarchy.")
        return
        
    if _xrefs_win:
        _xrefs_win.close()
        
    _xrefs_win = XrefsDialog(f.start_ea)
    _xrefs_win.show()

class DnspyXrefsHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
    def activate(self, ctx):
        show_dnspy_xrefs()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
