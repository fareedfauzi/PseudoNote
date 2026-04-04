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
    def __init__(self, parent, start_ea, end_ea, palette_idx=0):
        super().__init__(parent)
        self.setWindowTitle("Add Highlight")
        self.setModal(True)
        self.setMinimumWidth(380)
        self._color_hex = HIGHLIGHT_PALETTE[palette_idx % len(HIGHLIGHT_PALETTE)]
        lay = QtWidgets.QFormLayout(self)
        lay.setSpacing(8)

        self.start_edit = QtWidgets.QLineEdit(f"{start_ea:X}")
        self.end_edit   = QtWidgets.QLineEdit(f"{end_ea:X}")
        self.label_edit = QtWidgets.QLineEdit()
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


# ─────────────────────────────────────────────────────────────────────────────
# HEX CANVAS
# ─────────────────────────────────────────────────────────────────────────────
class HexCanvas(QtWidgets.QAbstractScrollArea):
    selection_changed = QtCore.Signal(int, int)   # start_ea, end_ea (inclusive)

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
        self._total_w   = 0
        self._calc_layout()

        self.setMouseTracking(True)
        self.verticalScrollBar().setSingleStep(self._rh * 3)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)

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
        self._total_w = self._ascii_x + self._ascii_w

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
                ("YARA pattern",    "yara"),
                ("Python literal",  "python"),
                ("C/C++ array",     "c_array"),
                ("Base64",          "base64"),
            ]:
                a = copy_menu.addAction(label)
                a.triggered.connect(functools.partial(self._do_copy, fmt))

            menu.addSeparator()

            # ── Highlights ────────────────────────────────────────────────────
            hl_add = menu.addAction("Highlight selection...")
            hl_add.triggered.connect(lambda: self._add_highlight(sel_a, sel_b + 1))

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

    # ── highlight helpers ─────────────────────────────────────────────────────
    def _add_highlight(self, start_ea, end_ea):
        dlg = AddHighlightDialog(self, start_ea, end_ea, self._palette_idx)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            hl = dlg.result_range()
            if hl:
                self._highlights.append(hl)
                self._palette_idx += 1
                self.viewport().update()

    def _remove_highlight(self, hl):
        if hl in self._highlights:
            self._highlights.remove(hl)
            self.viewport().update()

    def _clear_highlights(self):
        self._highlights.clear()
        self.viewport().update()


# ─────────────────────────────────────────────────────────────────────────────
# TOOLBAR
# ─────────────────────────────────────────────────────────────────────────────
class HexToolbar(QtWidgets.QWidget):
    jump_requested  = QtCore.Signal(str)
    sync_requested  = QtCore.Signal()
    follow_toggled  = QtCore.Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(36)
        T = _build_palette()
        fg  = T['TOOLBAR_FG']
        bg  = T['TOOLBAR_BG']
        bdr = T['TOOLBAR_BORDER']
        edit_bg = "#3C3C3C" if _is_dark_theme() else "#FFFFFF"
        edit_fg = "#CCCCCC" if _is_dark_theme() else "#1A1A1A"
        edit_bdr = "#555555" if _is_dark_theme() else "#BBBBBB"
        cb_fg = "#CCCCCC" if _is_dark_theme() else "#444"
        self.setStyleSheet(f"QWidget {{ background: {bg}; border-bottom: 1px solid {bdr}; }}")

        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(6)

        lbl = QtWidgets.QLabel("Jump to EA:")
        lbl.setStyleSheet(f"background:transparent; color:{fg}; font-size:12px;")
        lay.addWidget(lbl)

        self.ea_edit = QtWidgets.QLineEdit()
        self.ea_edit.setPlaceholderText("hex address…")
        self.ea_edit.setFixedWidth(160)
        self.ea_edit.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid {edit_bdr};
                border-radius: 3px;
                padding: 2px 6px;
                font-family: Consolas, monospace;
                font-size: 12px;
                background: {edit_bg};
                color: {edit_fg};
            }}
            QLineEdit:focus {{ border-color: #3399FF; }}
        """)
        self.ea_edit.returnPressed.connect(lambda: self.jump_requested.emit(self.ea_edit.text()))
        lay.addWidget(self.ea_edit)

        go = self._btn("Go", "#0066CC", "#0052A3")
        go.clicked.connect(lambda: self.jump_requested.emit(self.ea_edit.text()))
        lay.addWidget(go)

        sep = QtWidgets.QFrame()
        sep.setFrameShape(QtWidgets.QFrame.VLine)
        sep.setStyleSheet(f"color:{bdr}; background:transparent;")
        lay.addWidget(sep)

        sync = self._btn("Sync to cursor", "#228B22", "#1A6B1A")
        sync.clicked.connect(self.sync_requested.emit)
        lay.addWidget(sync)

        self.follow_cb = QtWidgets.QCheckBox("Auto-follow cursor")
        self.follow_cb.setChecked(True)
        self.follow_cb.setStyleSheet(f"background:transparent; color:{cb_fg}; font-size:12px;")
        self.follow_cb.toggled.connect(self.follow_toggled.emit)
        lay.addWidget(self.follow_cb)

        lay.addStretch()

        self.func_lbl = QtWidgets.QLabel("")
        self.func_lbl.setStyleSheet("background:transparent; color:#4FC1FF; font-size:12px; font-weight:bold;")
        lay.addWidget(self.func_lbl)

    def _btn(self, text, bg, hover):
        b = QtWidgets.QPushButton(text)
        b.setFixedHeight(26)
        b.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; color: white;
                border: none; border-radius: 3px;
                padding: 0 12px; font-size: 12px;
            }}
            QPushButton:hover {{ background: {hover}; }}
        """)
        return b


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
        self._val_lbl = self._lbl("")
        lay.addWidget(self._ea_lbl)
        lay.addWidget(self._sel_lbl)
        lay.addWidget(self._val_lbl)
        lay.addStretch()

    def _lbl(self, t):
        l = QtWidgets.QLabel(t)
        l.setStyleSheet(f"color:{self._lbl_fg}; font-family:Consolas,monospace; font-size:11px; background:transparent;")
        return l

    def update_ea(self, ea, bv):
        if ea >= 0:
            self._ea_lbl.setText(f"EA: {ea:X}")
        if bv >= 0:
            ch = chr(bv) if 0x20 <= bv < 0x7F else '.'
            self._val_lbl.setText(f"Byte: {bv:02X}h  {bv}d  '{ch}'")

    def update_selection(self, a, b):
        if a >= 0:
            self._sel_lbl.setText(f"Sel: {a:X} – {b:X}  ({b - a + 1} bytes)")
        else:
            self._sel_lbl.setText("Selection: —")


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
        root.addWidget(self.toolbar)

        self.hex_canvas = HexCanvas(self.parent)
        self.hex_canvas.selection_changed.connect(self._on_sel)
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

    def _on_sel(self, a, b):
        self.status_bar.update_selection(a, b)

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
