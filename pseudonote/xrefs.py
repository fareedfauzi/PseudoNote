import idaapi
import idc
import idautils
import ida_funcs
import ida_hexrays

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem

_xrefs_win = None

class XrefTreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, parent, text, target_func_ea, exact_ea, is_ref_to, is_root=False):
        super().__init__(parent)
        self.setText(0, text)
        self.target_func_ea = target_func_ea
        self.exact_ea = exact_ea
        self.is_ref_to = is_ref_to
        self.loaded = False
        self.is_root = is_root
        
        if self.is_root:
            font = self.font(0)
            font.setBold(True)
            self.setFont(0, font)

        # Child dummy item
        dummy = QtWidgets.QTreeWidgetItem(self)
        dummy.setText(0, "Loading...")

class XrefsDialog(QtWidgets.QDialog):
    def __init__(self, target_ea):
        super().__init__(None)
        self.setWindowTitle(f"Call Hierarchy: {idc.get_func_name(target_ea)}")
        self.resize(500, 600)
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
        
        # Add a refresh button
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setToolTip("Reload the cross-references")
        self.refresh_btn.clicked.connect(self.reload_tree)
        self.refresh_btn.setMaximumWidth(70)
        header_layout.addWidget(self.refresh_btn)
        
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
        top_name = idc.get_func_name(self.target_ea)
        top = XrefTreeItem(self.tree, f"Function: {top_name}()", self.target_ea, self.target_ea, is_ref_to=True, is_root=True)
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
            for xref in idautils.CodeRefsTo(item.target_func_ea, 0):
                f = idaapi.get_func(xref)
                if f:
                    name = idc.get_func_name(f.start_ea)
                    if (xref, f.start_ea) not in visited:
                        XrefTreeItem(item, f"{name} (0x{xref:X})", f.start_ea, xref, True, is_root=False)
                        visited.add((xref, f.start_ea))
        else:
            for ea in idautils.FuncItems(item.target_func_ea):
                for xref in idautils.CodeRefsFrom(ea, 0):
                    f = idaapi.get_func(xref)
                    if f and f.start_ea != item.target_func_ea:
                        name = idc.get_func_name(f.start_ea)
                        if (ea, f.start_ea) not in visited:
                            XrefTreeItem(item, f"{name} (0x{ea:X})", f.start_ea, ea, False, is_root=False)
                            visited.add((ea, f.start_ea))
                    elif not f and self.show_api_cb.isChecked():
                        name = idc.get_name(xref, idaapi.GN_VISIBLE)
                        if name:
                            if (ea, xref) not in visited:
                                child = XrefTreeItem(item, f"{name} (0x{ea:X})", xref, ea, False, is_root=False)
                                child.takeChild(0) # API calls are leaf nodes
                                child.loaded = True
                                visited.add((ea, xref))
                            
    def on_double_click(self, item, col):
        if hasattr(item, 'exact_ea') and item.exact_ea != idaapi.BADADDR and not getattr(item, 'is_root', False):
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
        import ida_kernwin
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
