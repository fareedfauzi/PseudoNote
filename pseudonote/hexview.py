# -*- coding: utf-8 -*-
"""
PseudoNote Hex Viewer — Clean light-theme hex editor widget for IDA Pro.

- Shows the entire binary (all segments, contiguous memory map)
- Syncs with IDA cursor (auto-follow)
- Multi-color highlights, all via right-click context menu
- Copy (hex, python, c_array, base64) via right-click
- No sidebar — full-width hex canvas
"""

import base64
import functools

#   - Added SearchResultsDialog for multi-hit navigation.
#
import idaapi
import idc
import idautils
import ida_bytes
import ida_segment
import ida_nalt

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui

# ─────────────────────────────────────────────────────────────────────────────
# THEME — detected at runtime from IDA's Qt palette
# ─────────────────────────────────────────────────────────────────────────────
BYTES_PER_ROW  = 16
GROUP_SIZE     = 8
HEADER_HEIGHT  = 26

# Always-red cursor ring
C_CURSOR_RING  = QtGui.QColor("#FF4444")


def _palette_from_widget(widget):
    """
    Build a color dict by reading the WIDGET's own QPalette.
    IDA propagates its dark/light theme palette to every child widget,
    so this is guaranteed to be correct on all platforms — no guessing.
    """
    pal  = widget.palette()

    base  = pal.color(QtGui.QPalette.Base)          # content background
    text  = pal.color(QtGui.QPalette.Text)           # normal text
    win   = pal.color(QtGui.QPalette.Window)         # chrome background
    winT  = pal.color(QtGui.QPalette.WindowText)     # chrome text
    hi    = pal.color(QtGui.QPalette.Highlight)      # selection bg
    hiT   = pal.color(QtGui.QPalette.HighlightedText)# selection text
    mid   = pal.color(QtGui.QPalette.Mid)            # separator / subtle
    dark  = pal.color(QtGui.QPalette.Dark)

    is_dark = base.lightness() < 128

    # Derive an "alt row" color by slightly shifting base brightness
    if is_dark:
        bg_alt = base.lighter(115)
    else:
        bg_alt = base.darker(103)

    # Gutter is the window-chrome color
    gutter_bg = win

    # Address text: use a vivid accent so it reads as a link/address
    if is_dark:
        gutter_fg = QtGui.QColor("#4FC1FF")
        ascii_fg  = QtGui.QColor("#6DB575")
        null_fg   = QtGui.QColor("#505050")
        hl_palette = [
            "#7B2020", "#1A4A6B", "#1A5C1A", "#6B4A00",
            "#4A1A6B", "#006B55", "#6B3A00", "#6B005C",
        ]
    else:
        gutter_fg = QtGui.QColor("#0066CC")
        ascii_fg  = QtGui.QColor("#007700")
        null_fg   = QtGui.QColor("#BBBBBB")
        hl_palette = [
            "#FFB3B3", "#B3D9FF", "#B3FFB3", "#FFE0B3",
            "#E0B3FF", "#B3FFF0", "#FFDDB3", "#FFB3E6",
        ]

    # Header slightly different shade from base
    header_bg = win.lighter(110) if is_dark else win.darker(102)

    # Toolbar / status: use window chrome bg, but ALWAYS use address blue for text
    # so labels are readable regardless of theme (same as gutter address color).
    tb_bg  = win.name()
    tb_fg  = gutter_fg.name()   # address blue — readable on both dark and light bg
    tb_bdr = mid.name() if mid.isValid() else dark.name()

    return dict(
        BG        = base,
        BG_ALT    = bg_alt,
        HEADER_BG = header_bg,
        HEADER_FG = winT,
        GUTTER_BG = gutter_bg,
        GUTTER_FG = gutter_fg,
        BYTE_FG   = QtGui.QColor("#FFFFFF") if is_dark else QtGui.QColor("#1A1A1A"),
        NULL_FG   = null_fg,
        ASCII_FG  = ascii_fg,
        UNPRINTABLE = mid if mid.isValid() else QtGui.QColor("#888888"),
        SEL_BG    = hi,
        SEL_FG    = hiT,
        SEPARATOR = mid if mid.isValid() else dark,
        STATUS_BG = win,
        STATUS_FG = gutter_fg,    # same address blue — always readable
        TOOLBAR_BG    = tb_bg,
        TOOLBAR_FG    = tb_fg,
        TOOLBAR_BORDER= tb_bdr,
        VP_BG     = base.name(),
        IS_DARK   = is_dark,
        HIGHLIGHT_PALETTE = hl_palette,
        SEARCH_BG = QtGui.QColor("#FFFFCC") if not is_dark else QtGui.QColor("#404000")
    )


# Keep _is_dark_theme for the highlight text-color check in _draw_rows
def _is_dark_theme():
    app = QtWidgets.QApplication.instance()
    if app:
        base = app.palette().color(QtGui.QPalette.Base)
        return base.lightness() < 128
    return False


# Backwards-compat stub (used for HIGHLIGHT_PALETTE module-level init)
def _build_palette():
    return _palette_from_widget(QtWidgets.QApplication.instance().activeWindow() or
                                QtWidgets.QWidget())


# Fallback palette used only for the AddHighlightDialog color picker default.
# The actual canvas picks its own palette at paint time from the widget.
HIGHLIGHT_PALETTE = [
    "#FFB3B3", "#B3D9FF", "#B3FFB3", "#FFE0B3",
    "#E0B3FF", "#B3FFF0", "#FFDDB3", "#FFB3E6",
]


# ─────────────────────────────────────────────────────────────────────────────
# BINARY MAP — build a flat sorted list of (start_ea, size) segments
# ─────────────────────────────────────────────────────────────────────────────
class BinaryMap:
    """Represents the entire loaded binary as a flat ordered list of segments."""

    def __init__(self):
        self.segments = []   # list of (start_ea, end_ea)
        self.total_bytes = 0
        self._refresh()

    def _refresh(self):
        segs = []
        seg = ida_segment.getseg(ida_nalt.get_imagebase())
        # Walk all segments
        ea = ida_segment.get_first_seg().start_ea if ida_segment.get_first_seg() else 0
        s = ida_segment.getseg(ea)
        while s:
            segs.append((s.start_ea, s.end_ea))
            s = ida_segment.getseg(idc.next_addr(s.end_ea - 1))
        self.segments = sorted(segs)
        self.total_bytes = sum(e - s for s, e in self.segments)

    def ea_to_flat(self, ea):
        """Convert an ea to a flat byte offset, or -1."""
        offset = 0
        for start, end in self.segments:
            if start <= ea < end:
                return offset + (ea - start)
            offset += (end - start)
        return -1

    def flat_to_ea(self, flat):
        """Convert a flat offset to an ea, or -1."""
        offset = 0
        for start, end in self.segments:
            size = end - start
            if flat < offset + size:
                return start + (flat - offset)
            offset += size
        return -1

    def row_start_ea(self, row):
        return self.flat_to_ea(row * BYTES_PER_ROW)

    def total_rows(self):
        return (self.total_bytes + BYTES_PER_ROW - 1) // BYTES_PER_ROW

    def read_byte(self, ea):
        if ea != idaapi.BADADDR and ida_bytes.is_loaded(ea):
            return idc.get_wide_byte(ea)
        return -1


# ─────────────────────────────────────────────────────────────────────────────
# HIGHLIGHT
# ─────────────────────────────────────────────────────────────────────────────
class HighlightRange:
    def __init__(self, start_ea, end_ea, color_hex, label=""):
        self.start_ea  = start_ea
        self.end_ea    = end_ea     # exclusive
        self.color     = QtGui.QColor(color_hex)
        self.color_hex = color_hex
        self.label     = label

    def contains(self, ea):
        return self.start_ea <= ea < self.end_ea


class AddHighlightDialog(QtWidgets.QDialog):
    def __init__(self, parent, start_ea, end_ea, palette_idx=0, existing_hl=None):
        super().__init__(parent)
        self.existing_hl = existing_hl
        self.setWindowTitle("Edit Highlight" if existing_hl else "Add Highlight")
        self.setModal(True)
        self.setMinimumWidth(380)
        
        if existing_hl:
            self._color_hex = existing_hl.color_hex
            s_ea, e_ea = existing_hl.start_ea, existing_hl.end_ea
            label = existing_hl.label
        else:
            self._color_hex = HIGHLIGHT_PALETTE[palette_idx % len(HIGHLIGHT_PALETTE)]
            s_ea, e_ea = start_ea, end_ea
            label = ""

        lay = QtWidgets.QFormLayout(self)
        lay.setSpacing(8)

        self.start_edit = QtWidgets.QLineEdit(f"{s_ea:X}")
        self.end_edit   = QtWidgets.QLineEdit(f"{e_ea:X}")
        self.label_edit = QtWidgets.QLineEdit(label)
        self.label_edit.setPlaceholderText("Optional label")

        lay.addRow("Start EA:", self.start_edit)
        lay.addRow("End EA:",   self.end_edit)
        lay.addRow("Label:",    self.label_edit)

        self.color_btn = QtWidgets.QPushButton("Choose Color")
        self._refresh_btn()
        self.color_btn.clicked.connect(self._pick)
        lay.addRow("Color:", self.color_btn)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addRow(btns)

    def _refresh_btn(self):
        c = QtGui.QColor(self._color_hex)
        lum = 0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue()
        fg = "#000000" if lum > 128 else "#FFFFFF"
        self.color_btn.setStyleSheet(
            f"background-color:{self._color_hex}; color:{fg}; "
            f"border:1px solid #999; border-radius:3px; padding:3px 12px;")

    def _pick(self):
        c = QtWidgets.QColorDialog.getColor(QtGui.QColor(self._color_hex), self)
        if c.isValid():
            self._color_hex = c.name()
            self._refresh_btn()

    def result_range(self):
        try:
            s = int(self.start_edit.text().strip(), 16)
            e = int(self.end_edit.text().strip(), 16)
            return HighlightRange(s, e, self._color_hex, self.label_edit.text().strip())
        except Exception:
            return None


class RangeDialog(QtWidgets.QDialog):
    def __init__(self, parent, start_ea=None, end_ea=None):
        super().__init__(parent)
        self.setWindowTitle("Address Range")
        self.setModal(True)
        lay = QtWidgets.QFormLayout(self)
        self.start_edit = QtWidgets.QLineEdit(f"{start_ea:X}" if start_ea is not None else "")
        self.end_edit   = QtWidgets.QLineEdit(f"{end_ea:X}" if end_ea is not None else "")
        lay.addRow("Start EA:", self.start_edit)
        lay.addRow("End EA (inclusive):", self.end_edit)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addRow(btns)

    def get_range(self):
        try:
            s = int(self.start_edit.text().strip(), 16)
            e = int(self.end_edit.text().strip(), 16)
            return min(s, e), max(s, e)
        except:
            return None, None


# ─────────────────────────────────────────────────────────────────────────────
# SEARCH RESULTS DIALOG
# ─────────────────────────────────────────────────────────────────────────────
class SearchResultsDialog(QtWidgets.QDialog):
    result_selected = QtCore.Signal(object)

    def __init__(self, parent, results, pattern, bmap):
        super().__init__(parent)
        self.setWindowTitle(f"Search Results: '{pattern.hex() if len(pattern) < 8 else pattern[:8].hex() + '...'}' ({len(results)} hits)")
        self.resize(700, 400)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        
        T = _build_palette()
        bg = "#F5F5F5" if not _is_dark_theme() else "#1E1E1E"
        fg = "#1A1A1A" if not _is_dark_theme() else "#CCCCCC"
        
        lay = QtWidgets.QVBoxLayout(self)
        
        self.table = QtWidgets.QTableWidget(len(results), 3)
        self.table.setHorizontalHeaderLabels(["Address", "Hex Preview", "Text Preview"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        
        theme_css = f"""
            QTableWidget {{
                background-color: {bg};
                color: {fg};
                gridline-color: #444444;
                font-family: 'Consolas', 'DejaVue Sans Mono', monospace;
                font-size: 12px;
            }}
            QHeaderView::section {{
                background-color: #333333; color: white; padding: 4px; border: 1px solid #444;
            }}
        """ if _is_dark_theme() else ""
        self.table.setStyleSheet(theme_css)

        for i, ea in enumerate(results):
            # Address
            item_ea = QtWidgets.QTableWidgetItem(f"{ea:010X}")
            item_ea.setData(QtCore.Qt.UserRole, ea)
            self.table.setItem(i, 0, item_ea)
            
            # Read a few bytes around match
            data = ida_bytes.get_bytes(ea, min(16, len(pattern) + 8))
            if data:
                h = " ".join(f"{b:02X}" for b in data)
                t = "".join(chr(b) if 0x20 <= b < 0x7F else "·" for b in data)
                self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(h))
                self.table.setItem(i, 2, QtWidgets.QTableWidgetItem(t))

        self.table.doubleClicked.connect(self._on_double_click)
        lay.addWidget(self.table)
        
        self.jump_btn = QtWidgets.QPushButton("Jump to Selected")
        self.jump_btn.clicked.connect(self._on_jump)
        lay.addWidget(self.jump_btn)

    def _on_double_click(self, index):
        self._on_jump()

    def _on_jump(self):
        row = self.table.currentRow()
        if row >= 0:
            ea = self.table.item(row, 0).data(QtCore.Qt.UserRole)
            self.result_selected.emit(ea)


# ─────────────────────────────────────────────────────────────────────────────
# HEX CANVAS
# ─────────────────────────────────────────────────────────────────────────────
class HexCanvas(QtWidgets.QAbstractScrollArea):
    selection_changed = QtCore.Signal(object, object)   # start_ea, end_ea (inclusive)
    hover_changed = QtCore.Signal(object, object)       # ea, byte_value

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bmap        = None
        self._highlights  = []
        self._palette_idx = 0

        self._sel_anchor  = -1
        self._sel_end     = -1
        self._hover_ea    = -1
        self._cursor_ea   = -1    # synced from IDA
        self._jump_ea     = -1    # last manually jumped-to EA (shown with amber rect)
        
        self._show_labels = True
        self._search_results = []  # list of EAs
        self._search_len     = 0

        # Font — prioritise aesthetically tuned code fonts
        self._font = QtGui.QFont()
        for candidate in ["IBM Plex Mono", "Fira Code", "Cascadia Code",
                          "JetBrains Mono", "Inconsolata", "Consolas", "monospace"]:
            self._font.setFamily(candidate)
            if QtGui.QFontDatabase().hasFamily(candidate):
                break
        self._font.setStyleHint(QtGui.QFont.Monospace)
        self._font.setPointSize(10)

        fm = QtGui.QFontMetrics(self._font)
        self._cw = fm.horizontalAdvance("0") if hasattr(fm, 'horizontalAdvance') else fm.width("0")
        self._ch = fm.height()
        self._rh = self._ch + 4

        # Cached layout
        self._gutter_w  = 0
        self._hex_x     = 0
        self._hex_w     = 0
        self._gap_x     = 0      # thin separator between hex / ascii
        self._ascii_x   = 0
        self._ascii_w   = 0
        self._label_x   = 0
        self._label_w   = 0
        self._total_w   = 0
        self._calc_layout()

        self.setMouseTracking(True)
        self.verticalScrollBar().setSingleStep(self._rh * 3)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.setFocusPolicy(QtCore.Qt.StrongFocus)

        # _T is refreshed at the START of every paintEvent from the real widget palette.
        # We do a first-pass init here; it will be overwritten on first paint.
        self._T = _palette_from_widget(self.viewport())
        # Don't hard-code a background: let the painter do it so it's always in sync.

    # ── layout ────────────────────────────────────────────────────────────────
    def _calc_layout(self):
        cw = self._cw
        # gutter: "1B0012CCB0:  " — 14 chars
        self._gutter_w = cw * 14
        # hex: each byte "XX " = cw*3, no group gap
        self._hex_w   = cw * (BYTES_PER_ROW * 3)
        self._hex_x   = self._gutter_w
        # separator position (no gap char)
        self._gap_x   = self._hex_x + self._hex_w
        # ascii
        self._ascii_x = self._gap_x + cw
        self._ascii_w = cw * (BYTES_PER_ROW + 1)
        
        self._label_x = self._ascii_x + self._ascii_w + cw
        self._label_w = cw * 30
        self._total_w = self._label_x + self._label_w

    def _byte_hex_x(self, col):
        return self._hex_x + col * self._cw * 3

    def _byte_ascii_x(self, col):
        return self._ascii_x + col * self._cw

    def _row_y(self, row):
        return HEADER_HEIGHT + row * self._rh - self.verticalScrollBar().value()

    def _ea_hit(self, x, y):
        """Return (ea, zone) where zone='hex' or 'ascii', or (-1, '')."""
        if not self._bmap or y < HEADER_HEIGHT:
            return -1, ''
        row = (y - HEADER_HEIGHT + self.verticalScrollBar().value()) // self._rh
        col = -1
        zone = ''
        if self._hex_x <= x < self._gap_x:
            zone = 'hex'
            rx   = x - self._hex_x
            col  = min(rx // (self._cw * 3), BYTES_PER_ROW - 1)
        elif self._ascii_x <= x < self._ascii_x + self._ascii_w:
            zone = 'ascii'
            col  = (x - self._ascii_x) // self._cw
        if col < 0 or col >= BYTES_PER_ROW:
            return -1, ''
        flat = row * BYTES_PER_ROW + col
        ea   = self._bmap.flat_to_ea(flat)
        return (ea if ea != idaapi.BADADDR else -1), zone

    # ── data ─────────────────────────────────────────────────────────────────
    def load_binary(self):
        self._bmap = BinaryMap()
        self._update_scrollbar()
        self.viewport().update()

    def _update_scrollbar(self):
        if not self._bmap:
            return
        total_h = HEADER_HEIGHT + self._bmap.total_rows() * self._rh
        vis_h   = self.viewport().height()
        self.verticalScrollBar().setRange(0, max(0, total_h - vis_h))
        self.verticalScrollBar().setPageStep(vis_h)

    def scroll_to_ea(self, ea):
        if not self._bmap:
            return
        flat = self._bmap.ea_to_flat(ea)
        if flat < 0:
            return
        row = flat // BYTES_PER_ROW
        # Place target row exactly 1 row from the top
        target_y = HEADER_HEIGHT + row * self._rh - self._rh
        self.verticalScrollBar().setValue(max(0, target_y))

    def sync_cursor(self, ea):
        """Called when IDA cursor moves."""
        self._cursor_ea = ea
        if self._bmap and ea != idaapi.BADADDR:
            self.scroll_to_ea(ea)
        self.viewport().update()

    # ── selection helpers ─────────────────────────────────────────────────────
    def _sel(self):
        a = self._sel_anchor
        b = self._sel_end
        if a < 0:
            return -1, -1
        return (min(a, b), max(a, b)) if b >= 0 else (a, a)

    def _in_sel(self, ea):
        a, b = self._sel()
        return a >= 0 and a <= ea <= b

    def _sel_bytes(self):
        a, b = self._sel()
        if a < 0 or not self._bmap:
            return b""
        return bytes([max(0, self._bmap.read_byte(e)) for e in range(a, b + 1)])

    # ── painting ──────────────────────────────────────────────────────────────
    def paintEvent(self, event):
        # Always re-read palette from the actual widget — IDA may have changed
        # the theme since last paint, and this is the only 100% reliable source.
        self._T = _palette_from_widget(self.viewport())
        p = QtGui.QPainter(self.viewport())
        p.setFont(self._font)
        T   = self._T
        vp  = self.viewport().rect()
        p.fillRect(vp, T['BG'])

        if not self._bmap:
            p.setPen(T['UNPRINTABLE'])
            p.drawText(vp, QtCore.Qt.AlignCenter, "No binary loaded.")
            return

        # Draw rows first, then header on top so it always sticks
        self._draw_rows(p)
        self._draw_header(p)

    def _draw_header(self, p):
        T = self._T
        r = QtCore.QRect(0, 0, max(self._total_w, self.viewport().width()), HEADER_HEIGHT)
        p.fillRect(r, T['HEADER_BG'])

        # Bottom border
        p.setPen(QtGui.QPen(T['SEPARATOR'], 1))
        p.drawLine(0, HEADER_HEIGHT - 1, r.width(), HEADER_HEIGHT - 1)

        p.setPen(T['HEADER_FG'])

        # Address column
        p.drawText(4, 0, self._gutter_w, HEADER_HEIGHT,
                   QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, "Address")

        # Byte columns
        for col in range(BYTES_PER_ROW):
            x = self._byte_hex_x(col)
            p.setPen(T['HEADER_FG'])
            p.drawText(x, 0, self._cw * 2, HEADER_HEIGHT,
                       QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, f"{col:02X}")

        # Gutter right border only
        p.setPen(QtGui.QPen(T['SEPARATOR'], 1))
        p.drawLine(self._gutter_w - 4, 0, self._gutter_w - 4, HEADER_HEIGHT)

        # ASCII header
        p.setPen(T['HEADER_FG'])
        p.drawText(self._ascii_x, 0, self._ascii_w, HEADER_HEIGHT,
                   QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, "ASCII")

        if self._show_labels:
            p.drawText(self._label_x, 0, self._label_w, HEADER_HEIGHT,
                       QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, "Labels")

    def _draw_rows(self, p):
        if not self._bmap:
            return
        T          = self._T
        scroll_y   = self.verticalScrollBar().value()
        vis_h      = self.viewport().height()
        total_rows = self._bmap.total_rows()

        first = max(0, (scroll_y - HEADER_HEIGHT) // self._rh)
        last  = min(total_rows, first + (vis_h // self._rh) + 2)

        sel_a, sel_b = self._sel()

        for row in range(first, last):
            row_ea = self._bmap.row_start_ea(row)
            ry     = self._row_y(row)
            rw     = max(self._total_w, self.viewport().width())

            # Row background
            p.fillRect(0, ry, rw, self._rh, T['BG'] if row % 2 == 0 else T['BG_ALT'])

            # Gutter background
            p.fillRect(0, ry, self._gutter_w - 4, self._rh, T['GUTTER_BG'])
            p.setPen(T['GUTTER_FG'])
            if row_ea != idaapi.BADADDR:
                p.drawText(4, ry, self._gutter_w - 8, self._rh,
                           QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft,
                           f"{row_ea:010X}:")
            else:
                p.setPen(T['UNPRINTABLE'])
                p.drawText(4, ry, self._gutter_w - 8, self._rh,
                           QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, "----------:")

            # Gutter separator only
            p.setPen(QtGui.QPen(T['SEPARATOR'], 1))
            p.drawLine(self._gutter_w - 4, ry, self._gutter_w - 4, ry + self._rh)

            for col in range(BYTES_PER_ROW):
                flat = row * BYTES_PER_ROW + col
                ea   = self._bmap.flat_to_ea(flat)
                if ea == idaapi.BADADDR or ea < 0:
                    ea = -1

                bv = self._bmap.read_byte(ea) if ea >= 0 else -1

                hx = self._byte_hex_x(col)
                ax = self._byte_ascii_x(col)

                # Determine cell background and text colors
                byte_fg  = T['NULL_FG'] if bv == 0 else T['BYTE_FG']
                ascii_fg = (T['ASCII_FG'] if (bv >= 0x20 and bv < 0x7F)
                            else T['UNPRINTABLE']) if bv >= 0 else T['UNPRINTABLE']
                cell_bg  = None

                if ea >= 0 and sel_a >= 0 and sel_a <= ea <= sel_b:
                    cell_bg  = T['SEL_BG']
                    byte_fg  = T['SEL_FG']
                    ascii_fg = T['SEL_FG']
                else:
                    for hl in self._highlights:
                        if ea >= 0 and hl.contains(ea):
                            cell_bg  = hl.color
                            byte_fg  = QtGui.QColor("#FFFFFF" if _is_dark_theme() else "#000000")
                            ascii_fg = byte_fg
                            break
                    
                    if not cell_bg and ea in self._search_results:
                         cell_bg = T['SEARCH_BG']

                if cell_bg:
                    p.fillRect(hx, ry, self._cw * 3, self._rh, cell_bg)
                    p.fillRect(ax, ry, self._cw, self._rh, cell_bg)

                # IDA cursor — red rectangle outline
                if ea >= 0 and ea == self._cursor_ea:
                    p.setPen(QtGui.QPen(C_CURSOR_RING, 1.5))
                    p.drawRect(hx, ry + 1, self._cw * 2, self._rh - 3)

                # Jump target — amber rectangle outline (Go button)
                if ea >= 0 and ea == self._jump_ea:
                    p.setPen(QtGui.QPen(QtGui.QColor("#FFA500"), 1.5))
                    p.drawRect(hx, ry + 1, self._cw * 2, self._rh - 3)

                # Hex bytes
                p.setPen(byte_fg)
                if bv >= 0:
                    p.drawText(hx, ry, self._cw * 2, self._rh,
                               QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, f"{bv:02X}")
                else:
                    p.setPen(T['UNPRINTABLE'])
                    p.drawText(hx, ry, self._cw * 2, self._rh,
                               QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, "..")

                # ASCII
                p.setPen(ascii_fg)
                ch = (chr(bv) if 0x20 <= bv < 0x7F else "·") if bv >= 0 else " "
                p.drawText(ax, ry, self._cw, self._rh,
                           QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, ch)

            # Draw Labels for highlights starting on this row
            if self._show_labels and self._highlights and row_ea != idaapi.BADADDR:
                starting_hls = []
                for hl in self._highlights:
                    if row_ea <= hl.start_ea < row_ea + BYTES_PER_ROW:
                        starting_hls.append(hl)
                
                if starting_hls:
                    starting_hls.sort(key=lambda h: h.start_ea)
                    lx = self._label_x
                    # Filter unique items to avoid redundant labels on same start addr
                    seen_texts = set()
                    unique_hls = []
                    for h in starting_hls:
                        text = h.label or f"Range:{h.start_ea:X}"
                        if text not in seen_texts:
                            seen_texts.add(text)
                            unique_hls.append((h, text))

                    for i, (h, text) in enumerate(unique_hls):
                        # Use HSL to extract hue and set a consistent, readable lightness
                        h_hue, h_sat, h_lum, _ = h.color.getHsl()
                        if _is_dark_theme():
                            # High lightness for dark themes
                            c = QtGui.QColor.fromHsl(h_hue, h_sat, 200)
                        else:
                            # Low lightness for light themes (ensure contrast on white)
                            # We keep the hue and saturation but make it dark enough to read
                            c = QtGui.QColor.fromHsl(h_hue, h_sat, 100)
                        
                        p.setPen(c)
                        f = p.font()
                        f.setBold(True)
                        p.setFont(f)
                        
                        tw = p.fontMetrics().horizontalAdvance(text) if hasattr(p.fontMetrics(), 'horizontalAdvance') else p.fontMetrics().width(text)
                        p.drawText(lx, ry, tw, self._rh, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)
                        lx += tw
                        
                        # Reset font for separator/next
                        f.setBold(False)
                        p.setFont(f)

                        if i < len(unique_hls) - 1:
                            sep = " | "
                            p.setPen(T['GUTTER_FG'])
                            sw = p.fontMetrics().horizontalAdvance(sep) if hasattr(p.fontMetrics(), 'horizontalAdvance') else p.fontMetrics().width(sep)
                            p.drawText(lx, ry, sw, self._rh, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, sep)
                            lx += sw

    # ── mouse ─────────────────────────────────────────────────────────────────
    def mousePressEvent(self, event):
        ea, _ = self._ea_hit(event.x(), event.y())
        if event.button() == QtCore.Qt.LeftButton and ea >= 0:
            shift = event.modifiers() & QtCore.Qt.ShiftModifier
            if shift and self._sel_anchor >= 0:
                # Shift+Click: extend selection from existing anchor to clicked ea
                self._sel_end = ea
            else:
                # Normal click: start fresh selection
                self._sel_anchor = ea
                self._sel_end    = ea
            self.viewport().update()
            self.selection_changed.emit(*self._sel())

    def mouseMoveEvent(self, event):
        ea, _ = self._ea_hit(event.x(), event.y())
        self._hover_ea = ea
        bv = self._bmap.read_byte(ea) if self._bmap and ea >= 0 else -1
        self.hover_changed.emit(ea, bv)

        if event.buttons() & QtCore.Qt.LeftButton and self._sel_anchor >= 0 and ea >= 0:
            # Drag always extends the selection end (works for normal drag AND shift-drag)
            self._sel_end = ea
            self.viewport().update()
            self.selection_changed.emit(*self._sel())
        else:
            self.viewport().update()

    def mouseReleaseEvent(self, event):
        pass  # keep selection

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        step  = self._rh * 5
        shift = event.modifiers() & QtCore.Qt.ShiftModifier

        # Scroll the view
        self.verticalScrollBar().setValue(
            self.verticalScrollBar().value() + (-step if delta > 0 else step))

        if shift and self._sel_anchor >= 0 and self._bmap:
            # Shift+Scroll: extend the selection to the byte now visible at the
            # leading edge of the scroll direction (top when scrolling up, bottom
            # when scrolling down).
            vis_h  = self.viewport().height()
            scroll = self.verticalScrollBar().value()
            if delta > 0:
                # scrolled up — extend selection toward lower addresses
                edge_y = HEADER_HEIGHT + self._rh
            else:
                # scrolled down — extend selection toward higher addresses
                edge_y = vis_h - self._rh
            row = (edge_y - HEADER_HEIGHT + scroll) // self._rh
            row = max(0, min(row, self._bmap.total_rows() - 1))
            edge_ea = self._bmap.flat_to_ea(row * BYTES_PER_ROW)
            if edge_ea >= 0:
                self._sel_end = edge_ea
                self.viewport().update()
                self.selection_changed.emit(*self._sel())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_scrollbar()

    def keyPressEvent(self, event):
        super().keyPressEvent(event)

    # ── context menu (right-click) ────────────────────────────────────────────
    def contextMenuEvent(self, event):
        ea, _ = self._ea_hit(event.x(), event.y())
        sel_a, sel_b = self._sel()
        has_sel = sel_a >= 0

        menu = QtWidgets.QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background: #FFFFFF;
                color: #1A1A1A;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 2px;
                font-size: 12px;
            }
            QMenu::item {
                padding: 5px 20px 5px 12px;
            }
            QMenu::item:selected {
                background: #E3EFFD;
                color: #0050A0;
                border-radius: 3px;
            }
            QMenu::separator {
                height: 1px;
                background: #E0E0E0;
                margin: 3px 6px;
            }
        """)

        # ── Jump ──────────────────────────────────────────────────────────────
        if ea >= 0:
            jump_act = menu.addAction(f"Jump to {ea:X} in IDA")
            jump_act.triggered.connect(lambda: idc.jumpto(ea))
            menu.addSeparator()

        # ── Manage highlights if any exist ───────────────────────────────────
        matching_hls = [h for h in self._highlights if h.contains(ea)] if ea >= 0 else []
        if matching_hls:
            hl = matching_hls[0]
            edit_act = menu.addAction(f"Edit Highlight ({hl.label})...")
            edit_act.triggered.connect(lambda: self._edit_highlight(hl))
            
            rem_act = menu.addAction(f"Remove Highlight")
            rem_act.triggered.connect(lambda: self._remove_highlight(hl))
            menu.addSeparator()

        # ── Copy (requires selection) ─────────────────────────────────────────
        if has_sel:
            n = sel_b - sel_a + 1
            info = menu.addAction(f"Selection: {sel_a:X} – {sel_b:X}  ({n} bytes)")
            info.setEnabled(False)
            menu.addSeparator()

            copy_menu = menu.addMenu("Copy selection as...")
            copy_menu.setStyleSheet(menu.styleSheet())

            for label, fmt in [
                ("Hex Bytes",       "hex"),
                ("Raw Bytes",       "raw_hex"),
                ("YARA pattern",    "yara"),
                ("Python literal",  "python"),
                ("C/C++ array",     "c_array"),
                ("Base64",          "base64"),
            ]:
                a = copy_menu.addAction(label)
                a.triggered.connect(functools.partial(self._do_copy, fmt))

            menu.addSeparator()

            save_act = menu.addAction("Save selection as raw file...")
            save_act.triggered.connect(lambda: self._save_range_as_file(sel_a, sel_b))
            menu.addSeparator()

            # ── Highlights ────────────────────────────────────────────────────
            hl_add = menu.addAction("Highlight selection...")
            hl_add.triggered.connect(lambda: self._add_highlight(sel_a, sel_b + 1))

        # ── Range Operations ──────────────────────────────────────────────────
        menu.addSeparator()
        range_menu = menu.addMenu("Range operations...")
        range_menu.setStyleSheet(menu.styleSheet())
        
        ca = range_menu.addAction("Copy bytes from address to address...")
        ca.triggered.connect(self._copy_range_dialog)
        
        sa = range_menu.addAction("Save bytes to file from address to address...")
        sa.triggered.connect(self._save_range_dialog)

        # ── Manage highlights if any exist ───────────────────────────────────
        if self._highlights:
            if ea >= 0:
                matching = [h for h in self._highlights if h.contains(ea)]
                if matching:
                    menu.addSeparator()
                    for hl in matching:
                        label = hl.label or f"{hl.start_ea:X}–{hl.end_ea:X}"
                        rm = menu.addAction(f"Remove highlight: {label}")
                        rm.triggered.connect(functools.partial(self._remove_highlight, hl))
            clr = menu.addAction("Clear all highlights")
            clr.triggered.connect(self._clear_highlights)

        menu.exec_(event.globalPos())

    # ── copy helpers ──────────────────────────────────────────────────────────
    def _do_copy(self, fmt):
        raw = self._sel_bytes()
        if not raw:
            return
        if fmt == "hex":
            text = " ".join(f"{b:02X}" for b in raw)
        elif fmt == "raw_hex":
            text = "".join(f"{b:02X}" for b in raw)
        elif fmt == "yara":
            text = "{ " + " ".join(f"{b:02X}" for b in raw) + " }"
        elif fmt == "python":
            text = 'b"' + "".join(f"\\x{b:02x}" for b in raw) + '"'
        elif fmt == "c_array":
            elems = ", ".join(f"0x{b:02X}" for b in raw)
            text  = f"unsigned char data[{len(raw)}] = {{ {elems} }};"
        elif fmt == "base64":
            text = base64.b64encode(raw).decode()
        else:
            text = " ".join(f"{b:02X}" for b in raw)
        QtWidgets.QApplication.clipboard().setText(text)

    def _save_range_as_file(self, start_ea, end_ea):
        """Saves bytes from start_ea to end_ea (inclusive) to a file."""
        if not self._bmap:
            return
        
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Raw Bytes", "", "Binary files (*.bin);;All files (*.*)")
        if not path:
            return
            
        data = bytes([max(0, self._bmap.read_byte(e)) for e in range(start_ea, end_ea + 1)])
        try:
            with open(path, "wb") as f:
                f.write(data)
            print(f"[PseudoNote] Saved {len(data)} bytes to {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def _copy_range_dialog(self):
        sel_a, sel_b = self._sel()
        dlg = RangeDialog(self, sel_a if sel_a >= 0 else None, sel_b if sel_b >= 0 else None)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            s, e = dlg.get_range()
            if s is not None and e is not None and self._bmap:
                data = bytes([max(0, self._bmap.read_byte(addr)) for addr in range(s, e + 1)])
                text = " ".join(f"{b:02X}" for b in data)
                QtWidgets.QApplication.clipboard().setText(text)
                print(f"[PseudoNote] Copied {len(data)} bytes from {s:X} to {e:X}")

    def _save_range_dialog(self):
        sel_a, sel_b = self._sel()
        dlg = RangeDialog(self, sel_a if sel_a >= 0 else None, sel_b if sel_b >= 0 else None)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            s, e = dlg.get_range()
            if s is not None and e is not None:
                self._save_range_as_file(s, e)

    # ── highlight helpers ─────────────────────────────────────────────────────
    def _add_highlight(self, start_ea, end_ea):
        dlg = AddHighlightDialog(self, start_ea, end_ea, self._palette_idx)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            hl = dlg.result_range()
            if hl:
                self._highlights.append(hl)
                self._palette_idx += 1
                self.viewport().update()

    def _edit_highlight(self, hl):
        dlg = AddHighlightDialog(self, hl.start_ea, hl.end_ea, existing_hl=hl)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            new_hl = dlg.result_range()
            if new_hl:
                # Replace existing with new values
                hl.start_ea = new_hl.start_ea
                hl.end_ea   = new_hl.end_ea
                hl.color    = new_hl.color
                hl.color_hex = new_hl.color_hex
                hl.label     = new_hl.label
                self.viewport().update()

    def _remove_highlight(self, hl):
        if hl in self._highlights:
            self._highlights.remove(hl)
            self.viewport().update()

    def _clear_highlights(self):
        self._highlights.clear()
        self.viewport().update()


# ─────────────────────────────────────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────────────────────────────────────
class KLineEdit(QtWidgets.QLineEdit):
    """A QLineEdit that explicitly handles copy/paste to avoid IDA shadowing."""
    def keyPressEvent(self, event):
        if event.modifiers() & QtCore.Qt.ControlModifier:
            if event.key() == QtCore.Qt.Key_V:
                self.paste(); return
            elif event.key() == QtCore.Qt.Key_C:
                self.copy(); return
            elif event.key() == QtCore.Qt.Key_X:
                self.cut(); return
            elif event.key() == QtCore.Qt.Key_A:
                self.selectAll(); return
        super().keyPressEvent(event)


# ─────────────────────────────────────────────────────────────────────────────
# TOOLBAR
# ─────────────────────────────────────────────────────────────────────────────
class HexToolbar(QtWidgets.QWidget):
    jump_requested  = QtCore.Signal(str)
    sync_requested  = QtCore.Signal()
    follow_toggled  = QtCore.Signal(bool)
    search_changed  = QtCore.Signal(str, bool)   # text, is_hex
    show_labels_toggled = QtCore.Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(34)
        
        T = _build_palette()
        fg  = T['TOOLBAR_FG']
        bg  = T['TOOLBAR_BG']
        bdr = T['TOOLBAR_BORDER']
        
        # Consistent theme-aware tokens
        self._edit_bg = "#3C3C3C" if _is_dark_theme() else "#FFFFFF"
        self._edit_fg = "#CCCCCC" if _is_dark_theme() else "#1A1A1A"
        self._edit_bdr = "#555555" if _is_dark_theme() else "#BBBBBB"
        self._cb_fg = "#CCCCCC" if _is_dark_theme() else "#444"
        self._btn_bg = "#444444" if _is_dark_theme() else "#E0E0E0"
        self._btn_fg = "#FFFFFF" if _is_dark_theme() else "#222222"
        self._btn_hover = "#555555" if _is_dark_theme() else "#D0D0D0"
        
        self.setStyleSheet(f"QWidget {{ background: {bg}; border-bottom: 1px solid {bdr}; }}")

        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(6, 2, 6, 2)
        lay.setSpacing(8)

        # ── Navigation Group ──────────────────────────────────────────────────
        self.ea_edit = KLineEdit()
        self.ea_edit.setPlaceholderText("EA (hex)…")
        self.ea_edit.setFixedWidth(110)
        self.ea_edit.setStyleSheet(self._edit_style())
        self.ea_edit.returnPressed.connect(lambda: self.jump_requested.emit(self.ea_edit.text()))
        lay.addWidget(self.ea_edit)

        go_btn = self._btn("Go", "#0066CC")
        go_btn.setFixedWidth(36)
        go_btn.clicked.connect(lambda: self.jump_requested.emit(self.ea_edit.text()))
        lay.addWidget(go_btn)
        
        lay.addWidget(self._vsep(bdr))

        # ── Sync & Follow ─────────────────────────────────────────────────────
        sync = self._btn("Sync", "#2E7D32")
        sync.setFixedWidth(50)
        sync.clicked.connect(self.sync_requested.emit)
        lay.addWidget(sync)

        self.follow_cb = QtWidgets.QCheckBox("Follow")
        self.follow_cb.setToolTip("Auto-follow IDA cursor")
        self.follow_cb.setChecked(True)
        self.follow_cb.setStyleSheet(f"background:transparent; color:{self._cb_fg}; font-size:11px;")
        self.follow_cb.toggled.connect(self.follow_toggled.emit)
        lay.addWidget(self.follow_cb)
        
        lay.addWidget(self._vsep(bdr))

        # ── Search Group ─────────────────────────────────────────────────────
        self.search_edit = KLineEdit()
        self.search_edit.setPlaceholderText("Find hex or text…")
        self.search_edit.setFixedWidth(160)
        self.search_edit.setStyleSheet(self._edit_style())
        self.search_edit.returnPressed.connect(self._on_search_clicked)
        lay.addWidget(self.search_edit)

        self.search_type = QtWidgets.QComboBox()
        self.search_type.addItems(["Hex", "Text"])
        self.search_type.setFixedWidth(55)
        self.search_type.setStyleSheet(f"""
            QComboBox {{
                background: {self._edit_bg}; color: {self._edit_fg}; padding: 1px 3px;
                border: 1px solid {self._edit_bdr}; border-radius: 2px; font-size: 11px;
            }}
            QComboBox::drop-down {{ border: none; width: 12px; }}
        """)
        lay.addWidget(self.search_type)

        search_btn = self._btn("Search", "#5E35B1")
        search_btn.setFixedWidth(60)
        search_btn.clicked.connect(self._on_search_clicked)
        lay.addWidget(search_btn)
        
        lay.addWidget(self._vsep(bdr))

        # ── Options ──────────────────────────────────────────────────────────
        self.labels_cb = QtWidgets.QCheckBox("Labels")
        self.labels_cb.setChecked(True)
        self.labels_cb.setStyleSheet(f"background:transparent; color:{self._cb_fg}; font-size:11px;")
        self.labels_cb.toggled.connect(self.show_labels_toggled.emit)
        lay.addWidget(self.labels_cb)

        lay.addStretch()

        self.func_lbl = QtWidgets.QLabel("")
        self.func_lbl.setStyleSheet("background:transparent; color:#4FC1FF; font-size:12px; font-weight:bold; padding-right:12px;")
        lay.addWidget(self.func_lbl)

    def _edit_style(self):
        return f"""
            QLineEdit {{
                border: 1px solid {self._edit_bdr};
                border-radius: 2px;
                padding: 1px 6px;
                font-family: Consolas, monospace;
                font-size: 12px;
                background: {self._edit_bg};
                color: {self._edit_fg};
            }}
            QLineEdit:focus {{ border-color: #3399FF; }}
        """

    def _vsep(self, color):
        s = QtWidgets.QFrame()
        s.setFrameShape(QtWidgets.QFrame.VLine)
        s.setFixedWidth(1)
        # Use a very subtle vertical line
        s.setStyleSheet(f"color:{color}; background:{color}; margin: 4px 0;")
        return s

    def _btn(self, text, brand_color):
        b = QtWidgets.QPushButton(text)
        b.setFixedHeight(22)
        b.setCursor(QtCore.Qt.PointingHandCursor)
        # Use brand_color only as a subtle left accent or border? 
        # For a clean look, let's keep them compact but solid brand color with a lighter font
        b.setStyleSheet(f"""
            QPushButton {{
                background: {brand_color}; color: white;
                border: none; border-radius: 2px;
                padding: 0 4px; font-size: 11px; font-weight: bold;
            }}
            QPushButton:hover {{ background: {brand_color}; opacity: 0.8; border: 1px solid white; }}
            QPushButton:pressed {{ background: #222; }}
        """)
        return b

    def _on_search_clicked(self):
        text = self.search_edit.text()
        is_hex = self.search_type.currentText() == "Hex"
        self.search_changed.emit(text, is_hex)


# ─────────────────────────────────────────────────────────────────────────────
# STATUS BAR
# ─────────────────────────────────────────────────────────────────────────────
class HexStatusBar(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(22)
        T   = _build_palette()
        bg  = T['STATUS_BG'].name()
        fg  = T['STATUS_FG'].name()
        bdr = T['SEPARATOR'].name()
        self.setStyleSheet(f"background:{bg}; border-top:1px solid {bdr};")
        self._lbl_fg = fg

        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(8, 0, 8, 0)
        lay.setSpacing(24)

        self._ea_lbl  = self._lbl("EA: —")
        self._sel_lbl = self._lbl("Selection: —")
        self._hl_lbl  = self._lbl("")
        lay.addWidget(self._ea_lbl)
        lay.addSpacing(20)
        lay.addWidget(self._sel_lbl)
        lay.addWidget(self._hl_lbl)
        lay.addStretch()

    def _lbl(self, t):
        l = QtWidgets.QLabel(t)
        l.setStyleSheet(f"color:{self._lbl_fg}; font-family:Consolas,monospace; font-size:11px; background:transparent;")
        return l

    def update_ea(self, ea, bv):
        if ea >= 0:
            self._ea_lbl.setText(f"EA: {ea:X}")

    def update_selection(self, a, b):
        if a >= 0:
            sz = b - a + 1
            self._sel_lbl.setText(f"Sel: {a:X} – {b:X}  ({sz:X}h bytes)")
        else:
            self._sel_lbl.setText("Selection: —")

    def update_highlight(self, hl):
        if hl:
            sz = hl.end_ea - hl.start_ea
            self._hl_lbl.setText(f"Highlight: {hl.start_ea:X} – {hl.end_ea-1:X}  ({sz:X}h bytes)")
        else:
            self._hl_lbl.setText("")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN FORM
# ─────────────────────────────────────────────────────────────────────────────
class PseudoNoteHexView(idaapi.PluginForm):
    def OnCreate(self, form):
        self.parent       = self.FormToPyQtWidget(form)
        self._auto_follow = True
        self._build_ui()
        self._hooks = _HexScreenHooks(self)
        self._hooks.hook()
        self.hex_canvas.load_binary()
        ea = idaapi.get_screen_ea()
        if ea != idaapi.BADADDR:
            self._go(ea)

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.toolbar = HexToolbar(self.parent)
        self.toolbar.jump_requested.connect(self._on_jump)
        self.toolbar.sync_requested.connect(lambda: self._go(idaapi.get_screen_ea()))
        self.toolbar.follow_toggled.connect(lambda v: setattr(self, '_auto_follow', v))
        self.toolbar.search_changed.connect(self._on_search)
        self.toolbar.show_labels_toggled.connect(self._on_labels_toggled)
        root.addWidget(self.toolbar)

        self.hex_canvas = HexCanvas(self.parent)
        self.hex_canvas.selection_changed.connect(self._on_sel)
        self.hex_canvas.hover_changed.connect(self._on_hover)
        root.addWidget(self.hex_canvas)

        self.status_bar = HexStatusBar(self.parent)
        root.addWidget(self.status_bar)

        self.parent.setLayout(root)

    def _on_jump(self, text):
        try:
            ea = int(text.strip(), 16)
            self.hex_canvas._jump_ea = ea          # mark for amber indicator
            self.hex_canvas.scroll_to_ea(ea)
            self.hex_canvas.viewport().update()
        except Exception:
            pass

    def _go(self, ea):
        if ea == idaapi.BADADDR:
            return
        self.hex_canvas.sync_cursor(ea)
        func = idaapi.get_func(ea)
        name = idc.get_func_name(ea) if func else ""
        self.toolbar.func_lbl.setText(name)
        bv   = self.hex_canvas._bmap.read_byte(ea) if self.hex_canvas._bmap else -1
        self.status_bar.update_ea(ea, bv)

    def _on_labels_toggled(self, enabled):
        self.hex_canvas._show_labels = enabled
        self.hex_canvas.viewport().update()

    def _on_search(self, text, is_hex):
        text = text.strip()
        if not text or not self.hex_canvas._bmap:
            self.hex_canvas._search_results = []
            self.hex_canvas.viewport().update()
            return

        pattern = b""
        if is_hex:
            try:
                h = text.replace(" ", "")
                pattern = bytes.fromhex(h)
            except:
                return
        else:
            pattern = text.encode()

        if not pattern:
            return

        results = []
        for start, end in self.hex_canvas._bmap.segments:
            chunk = ida_bytes.get_bytes(start, end - start)
            if not chunk: continue
            
            idx = chunk.find(pattern)
            while idx != -1:
                results.append(start + idx)
                if len(results) > 2000: break # Safety limit
                idx = chunk.find(pattern, idx + 1)
            if len(results) > 2000: break
        
        self.hex_canvas._search_results = results
        self.hex_canvas._search_len = len(pattern)
        self.hex_canvas.viewport().update()

        if results:
            dlg = SearchResultsDialog(self.parent, results, pattern, self.hex_canvas._bmap)
            dlg.result_selected.connect(self._on_search_result_picked)
            dlg.show() # Non-modal so user can keep it open

    def _on_search_result_picked(self, ea):
        self.hex_canvas._jump_ea = ea
        self.hex_canvas.scroll_to_ea(ea)
        self.hex_canvas.viewport().update()
        # We no longer idc.jumpto(ea) here to keep IDA view stable as per user request

    def _on_sel(self, a, b):
        self.status_bar.update_selection(a, b)

    def _on_hover(self, ea, bv):
        self.status_bar.update_ea(ea, bv)
        # Check if hovering over a highlight
        matching = [h for h in self.hex_canvas._highlights if h.contains(ea)] if ea >= 0 else []
        self.status_bar.update_highlight(matching[0] if matching else None)

    def cursor_moved(self, ea):
        if self._auto_follow and ea != idaapi.BADADDR:
            self._go(ea)

    def OnClose(self, form):
        if hasattr(self, '_hooks') and self._hooks:
            self._hooks.unhook()
            self._hooks = None


# ─────────────────────────────────────────────────────────────────────────────
# IDA HOOKS
# ─────────────────────────────────────────────────────────────────────────────
class _HexScreenHooks(idaapi.UI_Hooks):
    def __init__(self, view):
        super().__init__()
        self._view = view

    def screen_ea_changed(self, ea, prev_ea):
        if self._view:
            self._view.cursor_moved(ea)


# ─────────────────────────────────────────────────────────────────────────────
# ACTION HANDLER
# ─────────────────────────────────────────────────────────────────────────────
_hex_view_instance = None


class OpenHexViewHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global _hex_view_instance
        if _hex_view_instance is None:
            _hex_view_instance = PseudoNoteHexView()
        _hex_view_instance.Show("PseudoNote Hex Viewer")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
