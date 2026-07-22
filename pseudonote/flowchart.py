# -*- coding: utf-8 -*-
"""
PseudoNote Flowchart — Graphical control flow graph viewer for IDA Pro.
Provides a modern visual representation of decompiled C function blocks.
"""

import math
import re
import html
import idaapi
import idc
import idautils
import ida_hexrays

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui

# ---------------------------------------------------------------------------
# CFG Parser & Representation
# ---------------------------------------------------------------------------

class CFGNode:
    def __init__(self, block_id, start_ea, end_ea):
        self.block_id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.c_lines = []
        self.successors = []
        self.predecessors = []
        self.is_conditional = False

def extract_if_condition(c_lines):
    for line in reversed(c_lines):
        match = re.search(r'if\s*\((.*)\)', line)
        if match:
            return match.group(1).strip() + "?"
    return None

def get_function_cfg(func_ea):
    func = idaapi.get_func(func_ea)
    if not func:
        return None, []
    
    # 1. Get CFG structure from IDA FlowChart
    try:
        flowchart = idaapi.FlowChart(func)
    except Exception as e:
        print(f"[PseudoNote Flowchart] Failed to get FlowChart: {e}")
        return None, []
    
    # Create nodes mapping
    nodes = {}
    for block in flowchart:
        node = CFGNode(block.id, block.start_ea, block.end_ea)
        nodes[block.id] = node

    # Fill edges
    for block in flowchart:
        node = nodes[block.id]
        for succ in block.succs():
            node.successors.append(succ.id)
            nodes[succ.id].predecessors.append(block.id)
            
        if len(node.successors) == 2:
            node.is_conditional = True

    # 2. Get C lines mapping if decompiler is available
    ea_to_c_lines = {}
    try:
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                pseudocode_lines = cfunc.get_pseudocode()
                phead = idaapi.ctree_item_t()
                pitem = idaapi.ctree_item_t()
                ptail = idaapi.ctree_item_t()
                for idx, line in enumerate(pseudocode_lines):
                    line_text = idaapi.tag_remove(line.line)
                    found = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
                    if found:
                        for p in [phead, pitem, ptail]:
                            if hasattr(p, "loc") and p.loc and p.loc.ea != idaapi.BADADDR:
                                ea = p.loc.ea
                                if ea not in ea_to_c_lines:
                                    ea_to_c_lines[ea] = []
                                ea_to_c_lines[ea].append((idx, line_text))
                                break
    except Exception as e:
        print(f"[PseudoNote Flowchart] Failed to map decompiler code: {e}")

    # Map C lines to nodes
    for node_id, node in nodes.items():
        block_c_lines = []
        seen_indices = set()
        for head in idautils.Heads(node.start_ea, node.end_ea):
            if head in ea_to_c_lines:
                for idx, line_text in ea_to_c_lines[head]:
                    if idx not in seen_indices:
                        seen_indices.add(idx)
                        block_c_lines.append((idx, line_text))
        
        # Sort by line index
        block_c_lines.sort(key=lambda x: x[0])
        node.c_lines = [line_text for idx, line_text in block_c_lines]

        # If C lines are empty, add a placeholder
        if not node.c_lines:
            node.c_lines.append("// (No mapped C code)")
            
    return nodes, list(nodes.keys())

def assign_levels(nodes):
    """
    Assign levels to nodes using a DAG longest-path approach, 
    detecting and ignoring back-edges (loops) via DFS to ensure
    all forward flow lines go strictly from top to bottom.
    """
    if not nodes:
        return {}
        
    back_edges = set()
    visited = set()
    rec_stack = set()
    
    def dfs(node_id):
        visited.add(node_id)
        rec_stack.add(node_id)
        
        if node_id in nodes:
            for succ in nodes[node_id].successors:
                if succ in rec_stack:
                    back_edges.add((node_id, succ))
                elif succ not in visited:
                    dfs(succ)
                    
        rec_stack.remove(node_id)
        
    dfs(0)
    
    # Compute in-degrees on the DAG (ignoring back-edges)
    in_degree = {nid: 0 for nid in nodes}
    dag_successors = {nid: [] for nid in nodes}
    
    for nid, node in nodes.items():
        for succ in node.successors:
            if (nid, succ) not in back_edges:
                dag_successors[nid].append(succ)
                in_degree[succ] += 1
                
    # Longest path assignment
    levels = {nid: 0 for nid in nodes}
    queue = [nid for nid, deg in in_degree.items() if deg == 0]
    
    processed = set()
    while queue:
        curr = queue.pop(0)
        processed.add(curr)
        curr_level = levels[curr]
        
        for succ in dag_successors[curr]:
            levels[succ] = max(levels[succ], curr_level + 1)
            in_degree[succ] -= 1
            if in_degree[succ] == 0:
                queue.append(succ)
                
    # Handle orphan/unvisited nodes (if any)
    max_lvl = max(levels.values()) if levels else 0
    for nid in nodes:
        if nid not in processed:
            levels[nid] = max_lvl + 1
            
    return levels

# ---------------------------------------------------------------------------
# QGraphicsItem - Node
# ---------------------------------------------------------------------------

class FlowchartNodeItem(QtWidgets.QGraphicsItem):
    def __init__(self, node_id, is_entry, is_exit, is_cond, lines, parent=None):
        super().__init__(parent)
        self.node_id = node_id
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.is_cond = is_cond
        
        # Build text document
        self.doc = QtGui.QTextDocument()
        self.doc.setDefaultStyleSheet("""
            body {
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                color: #D4D4D4;
            }
            .keyword { color: #C586C0; font-weight: bold; }
            .type { color: #569CD6; }
            .number { color: #B5CEA8; }
            .comment { color: #6A9955; font-style: italic; }
            .string { color: #CE9178; }
            .address { color: #808080; }
        """)
        
        html_lines = []
        for line in lines:
            html_lines.append(self.highlight_line(line))
            
        html_content = "<body>" + "<br>".join(html_lines) + "</body>"
        self.doc.setHtml(html_content)
        
        # Size estimation
        self.doc.setTextWidth(400)
        ideal_w = max(180, self.doc.idealWidth())
        self.width = min(400, ideal_w + 24)
        self.doc.setTextWidth(self.width - 24)
        
        if self.is_cond:
            self.width = max(160, self.width + 40)
            self.height = self.width * 0.7
        else:
            self.height = self.doc.size().height() + 45
            
        self.setFlag(QtWidgets.QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QtWidgets.QGraphicsItem.ItemIsSelectable, True)

    def highlight_line(self, line):
        escaped = html.escape(line)
        
        if escaped.startswith("//") or escaped.startswith("/*"):
            return f'<span class="comment">{escaped}</span>'
            
        comment_idx = escaped.find("//")
        if comment_idx != -1:
            code_part = escaped[:comment_idx]
            comment_part = escaped[comment_idx:]
            comment_html = f'<span class="comment">{comment_part}</span>'
        else:
            code_part = escaped
            comment_html = ""
            
        # Highlight Keywords
        keywords = r'\b(if|else|return|while|for|do|switch|case|break|continue)\b'
        code_part = re.sub(keywords, r'<span class="keyword">\1</span>', code_part)
        
        # Highlight Types
        types = r'\b(int|char|void|float|double|size_t|uint32_t|uint64_t|int32_t|int64_t|bool|__int64|_BYTE|_DWORD|_QWORD|_WORD)\b'
        code_part = re.sub(types, r'<span class="type">\1</span>', code_part)
        
        # Highlight Numbers
        code_part = re.sub(r'\b(0x[0-9a-fA-F]+|[0-9]+)\b', r'<span class="number">\1</span>', code_part)
        
        # Highlight Strings
        code_part = re.sub(r'(&quot;.*?&quot;|\'.*?\')', r'<span class="string">\1</span>', code_part)
        
        return code_part + comment_html

    def boundingRect(self):
        return QtCore.QRectF(0, 0, self.width, self.height)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        
        if self.is_entry:
            border_color = QtGui.QColor("#2ECC71")
            bg_gradient_start = QtGui.QColor("#1B3C2A")
        elif self.is_exit:
            border_color = QtGui.QColor("#9B59B6")
            bg_gradient_start = QtGui.QColor("#331E3D")
        elif self.is_cond:
            border_color = QtGui.QColor("#3498DB")
            bg_gradient_start = QtGui.QColor("#1A2E40")
        else:
            border_color = QtGui.QColor("#4E4E50")
            bg_gradient_start = QtGui.QColor("#252526")
            
        bg_gradient_end = QtGui.QColor("#141416")
        
        grad = QtGui.QLinearGradient(0, 0, 0, self.height)
        grad.setColorAt(0, bg_gradient_start)
        grad.setColorAt(1, bg_gradient_end)
        
        pen_width = 2.0 if self.isSelected() else 1.2
        pen_color = QtGui.QColor("#FFA500") if self.isSelected() else border_color
        pen = QtGui.QPen(pen_color, pen_width)
        painter.setPen(pen)
        painter.setBrush(QtGui.QBrush(grad))
        
        if self.is_cond:
            path = QtGui.QPainterPath()
            path.moveTo(self.width / 2, 0)
            path.lineTo(self.width, self.height / 2)
            path.lineTo(self.width / 2, self.height)
            path.lineTo(0, self.height / 2)
            path.closeSubpath()
            painter.drawPath(path)
            
            doc_size = self.doc.size()
            tx = (self.width - doc_size.width()) / 2
            ty = (self.height - doc_size.height()) / 2
            painter.save()
            painter.translate(tx, ty)
            self.doc.drawContents(painter)
            painter.restore()
        else:
            rect = QtCore.QRectF(0, 0, self.width, self.height)
            painter.drawRoundedRect(rect, 6, 6)
            
            title_rect = QtCore.QRectF(1, 1, self.width - 2, 24)
            title_grad = QtGui.QLinearGradient(0, 0, 0, 24)
            title_grad.setColorAt(0, border_color.darker(110))
            title_grad.setColorAt(1, border_color.darker(140))
            
            title_path = QtGui.QPainterPath()
            title_path.moveTo(6, 1)
            title_path.lineTo(self.width - 6, 1)
            title_path.quadTo(self.width - 1, 1, self.width - 1, 6)
            title_path.lineTo(self.width - 1, 24)
            title_path.lineTo(1, 24)
            title_path.lineTo(1, 6)
            title_path.quadTo(1, 1, 6, 1)
            title_path.closeSubpath()
            
            painter.setPen(QtCore.Qt.NoPen)
            painter.setBrush(QtGui.QBrush(title_grad))
            painter.drawPath(title_path)
            
            painter.setPen(QtGui.QPen(border_color, 1))
            painter.drawLine(1, 24, self.width - 2, 24)
            
            painter.setPen(QtGui.QColor("#FFFFFF"))
            font = QtGui.QFont("Segoe UI", 9, QtGui.QFont.Bold)
            painter.setFont(font)
            title_text = f"Block {self.node_id}"
            if self.is_entry:
                title_text += " (Entry)"
            elif self.is_exit:
                title_text += " (Exit)"
            painter.drawText(title_rect, QtCore.Qt.AlignCenter, title_text)
            
            painter.save()
            painter.translate(12, 32)
            self.doc.drawContents(painter)
            painter.restore()

# ---------------------------------------------------------------------------
# QGraphicsPathItem - Edge
# ---------------------------------------------------------------------------

class FlowchartEdgeItem(QtWidgets.QGraphicsPathItem):
    def __init__(self, from_node, to_node, label="", parent=None):
        super().__init__(parent)
        self.from_node = from_node
        self.to_node = to_node
        self.label = label
        self.setZValue(-1)
        self.update_path()

    def update_path(self):
        p_rect = self.from_node.sceneBoundingRect()
        c_rect = self.to_node.sceneBoundingRect()
        
        if p_rect.isEmpty() or c_rect.isEmpty():
            return
            
        start = QtCore.QPointF(p_rect.x() + p_rect.width() / 2, p_rect.y() + p_rect.height())
        end = QtCore.QPointF(c_rect.x() + c_rect.width() / 2, c_rect.y())
        
        path = QtGui.QPainterPath()
        path.moveTo(start)
        
        if end.y() >= start.y():
            # Forward edge: draw clean orthogonal elbow connector
            my = start.y() + (end.y() - start.y()) / 2
            path.lineTo(start.x(), my)
            path.lineTo(end.x(), my)
            path.lineTo(end)
        else:
            # Backward edge (loop): route outwards to avoid overlapping other nodes
            ox = (min(start.x(), end.x()) - 80) if end.x() < start.x() else (max(start.x(), end.x()) + 80)
            path.lineTo(start.x(), start.y() + 15)
            path.lineTo(ox, start.y() + 15)
            path.lineTo(ox, end.y() - 15)
            path.lineTo(end.x(), end.y() - 15)
            path.lineTo(end)
            
        self.setPath(path)
        
        if self.label == "Yes":
            color = QtGui.QColor("#2ECC71")
            width = 1.8
        elif self.label == "No":
            color = QtGui.QColor("#E74C3C")
            width = 1.8
        else:
            color = QtGui.QColor("#7F8C8D")
            width = 1.5
            
        pen = QtGui.QPen(color, width)
        self.setPen(pen)

    def paint(self, painter, option, widget):
        super().paint(painter, option, widget)
        
        path = self.path()
        if path.length() <= 0:
            return
            
        end_pt = path.pointAtPercent(1.0)
        prev_pt = path.pointAtPercent(0.98)
        
        dy = end_pt.y() - prev_pt.y()
        dx = end_pt.x() - prev_pt.x()
        angle = math.atan2(dy, dx)
        
        size = 8
        p1 = end_pt
        p2 = QtCore.QPointF(end_pt.x() - size * math.cos(angle - math.pi/6),
                            end_pt.y() - size * math.sin(angle - math.pi/6))
        p3 = QtCore.QPointF(end_pt.x() - size * math.cos(angle + math.pi/6),
                            end_pt.y() - size * math.sin(angle + math.pi/6))
                            
        arrow = QtGui.QPolygonF([p1, p2, p3])
        
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setBrush(self.pen().color())
        painter.drawPolygon(arrow)
        
        if self.label:
            mid = path.pointAtPercent(0.5)
            painter.setPen(self.pen().color())
            font = QtGui.QFont("Segoe UI", 8, QtGui.QFont.Bold)
            painter.setFont(font)
            
            fm = QtGui.QFontMetrics(font)
            tw = fm.horizontalAdvance(self.label) if hasattr(fm, 'horizontalAdvance') else fm.width(self.label)
            th = fm.height()
            
            bg_rect = QtCore.QRectF(mid.x() - tw/2 - 4, mid.y() - th/2 - 2, tw + 8, th + 4)
            painter.setBrush(QtGui.QColor("#121214"))
            painter.setPen(QtGui.QPen(self.pen().color(), 0.5))
            painter.drawRoundedRect(bg_rect, 3, 3)
            
            painter.setPen(self.pen().color())
            painter.drawText(bg_rect, QtCore.Qt.AlignCenter, self.label)

# ---------------------------------------------------------------------------
# QGraphicsView - View Window
# ---------------------------------------------------------------------------

class FlowchartGraphicsView(QtWidgets.QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.setRenderHint(QtGui.QPainter.TextAntialiasing)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QtWidgets.QGraphicsView.FullViewportUpdate)
        self.setTransformationAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
        self.setStyleSheet("background-color: #121214; border: none;")

    def drawBackground(self, painter, rect):
        painter.fillRect(rect, QtGui.QColor("#121214"))
        
        pen = QtGui.QPen(QtGui.QColor("#1d1d22"), 1, QtCore.Qt.SolidLine)
        painter.setPen(pen)
        
        grid_size = 40
        left = int(rect.left()) - (int(rect.left()) % grid_size)
        top = int(rect.top()) - (int(rect.top()) % grid_size)
        
        x = left
        while x < rect.right():
            painter.drawLine(x, rect.top(), x, rect.bottom())
            x += grid_size
            
        y = top
        while y < rect.bottom():
            painter.drawLine(rect.left(), y, rect.right(), y)
            y += grid_size

    def wheelEvent(self, event):
        zoom_in_factor = 1.15
        zoom_out_factor = 1.0 / zoom_in_factor
        
        pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        old_pos = self.mapToScene(pos)
        
        if event.angleDelta().y() > 0:
            zoom_factor = zoom_in_factor
        else:
            zoom_factor = zoom_out_factor
            
        self.scale(zoom_factor, zoom_factor)
        
        new_pos = self.mapToScene(pos)
        delta = new_pos - old_pos
        self.translate(delta.x(), delta.y())

# ---------------------------------------------------------------------------
# QWidget - Flowchart Widget
# ---------------------------------------------------------------------------

class FlowchartWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_ea = None
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.scene = QtWidgets.QGraphicsScene()
        self.view = FlowchartGraphicsView(self.scene)
        layout.addWidget(self.view)
        
        self.scene.changed.connect(self.on_scene_changed)

    def on_scene_changed(self):
        for item in self.scene.items():
            if isinstance(item, FlowchartEdgeItem):
                item.update_path()

    def load_function(self, ea):
        self.current_ea = ea
        self.scene.clear()
        
        nodes, _ = get_function_cfg(ea)
        if not nodes:
            return
            
        levels = assign_levels(nodes)
                
        level_to_nodes = {}
        for node_id, lvl in levels.items():
            level_to_nodes.setdefault(lvl, []).append(node_id)
            
        self.layout_scene(self.scene, nodes, level_to_nodes)
        
        # Set generous scene bounds to allow panning/scrolling in all directions
        rect = self.scene.itemsBoundingRect()
        rect.adjust(-1000, -1000, 1000, 1000)
        self.scene.setSceneRect(rect)

    def layout_scene(self, scene, nodes, level_to_nodes):
        node_items = {}
        # 1. Create items
        for lvl in sorted(level_to_nodes.keys()):
            for node_id in level_to_nodes[lvl]:
                node_info = nodes[node_id]
                lines = node_info.c_lines
                is_entry = (node_id == 0)
                is_exit = (len(node_info.successors) == 0)
                
                is_cond = node_info.is_conditional
                if is_cond:
                    cond_text = extract_if_condition(lines)
                    if cond_text:
                        lines = [cond_text]
                
                item = FlowchartNodeItem(
                    node_id=node_id,
                    is_entry=is_entry,
                    is_exit=is_exit,
                    is_cond=is_cond,
                    lines=lines
                )
                scene.addItem(item)
                node_items[node_id] = item
                
        # 2. Position items top-to-bottom
        node_positions = {}
        current_y = 50
        vertical_gap = 100
        
        for lvl in sorted(level_to_nodes.keys()):
            nodes_in_lvl = level_to_nodes[lvl]
            
            # Align nodes in level by the average X of their predecessors
            if lvl > 0:
                def get_pred_x_avg(nid):
                    preds = nodes[nid].predecessors
                    positioned_preds = [node_positions[p].x() + node_items[p].width / 2
                                        for p in preds if p in node_positions]
                    if positioned_preds:
                        return sum(positioned_preds) / len(positioned_preds)
                    return 0
                nodes_in_lvl.sort(key=get_pred_x_avg)
            
            level_height = 0
            level_nodes_info = []
            
            for node_id in nodes_in_lvl:
                item = node_items[node_id]
                level_height = max(level_height, item.height)
                level_nodes_info.append((node_id, item))
                
            num_nodes = len(nodes_in_lvl)
            horiz_gap = 80
            total_width = sum(item.width for _, item in level_nodes_info) + (num_nodes - 1) * horiz_gap
            
            start_x = -total_width / 2
            for node_id, item in level_nodes_info:
                pos = QtCore.QPointF(start_x, current_y)
                item.setPos(pos)
                node_positions[node_id] = pos
                start_x += item.width + horiz_gap
                
            current_y += level_height + vertical_gap
            
        # 3. Create edges
        for node_id, node_info in nodes.items():
            from_item = node_items[node_id]
            for idx, succ_id in enumerate(node_info.successors):
                if succ_id in node_items:
                    to_item = node_items[succ_id]
                    label = ""
                    if len(node_info.successors) == 2:
                        label = "No" if idx == 0 else "Yes"
                        
                    edge = FlowchartEdgeItem(from_item, to_item, label)
                    scene.addItem(edge)

# ---------------------------------------------------------------------------
# IDA PluginForm Wrapper
# ---------------------------------------------------------------------------

_flowchart_form = None

def open_flowchart(ea=idaapi.BADADDR):
    global _flowchart_form
    if not _flowchart_form:
        _flowchart_form = FlowchartForm()
    _flowchart_form.Show("PseudoNote Flowchart")
    if ea != idaapi.BADADDR:
        if _flowchart_form.widget:
            _flowchart_form.widget.load_function(ea)

class FlowchartForm(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        self.widget = None
        self.hooks = None

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self.widget = FlowchartWidget(parent)
        layout = QtWidgets.QVBoxLayout(parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        parent.setLayout(layout)
        
        self.refresh_ui()
        
        self.hooks = FlowchartScreenHooks(self)
        self.hooks.hook()

    def OnClose(self, form):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
        global _flowchart_form
        _flowchart_form = None

    def refresh_ui(self):
        ea = idaapi.get_screen_ea()
        if ea != idaapi.BADADDR and self.widget:
            self.widget.load_function(ea)

class FlowchartScreenHooks(idaapi.UI_Hooks):
    def __init__(self, form):
        super().__init__()
        self.form = form
        self.last_func_ea = idaapi.BADADDR

    def screen_ea_changed(self, ea, prev_ea):
        if self.form and self.form.widget and ea != idaapi.BADADDR:
            func = idaapi.get_func(ea)
            if func and func.start_ea != self.last_func_ea:
                self.last_func_ea = func.start_ea
                self.form.widget.load_function(func.start_ea)
