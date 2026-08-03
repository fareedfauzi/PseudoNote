# -*- coding: utf-8 -*-
"""Vftable discovery and a method-level browser for IDA Pro."""

import re

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_name
import ida_segment
import idautils
import idc


_VFTABLE_NAME = re.compile(r"(?:vftable|vtable|virtual[_ ]?table|\?\?_7)", re.I)
_MAX_SLOTS = 4096
_MIN_UNNAMED_SLOTS = 3
_viewer = None


def _pointer_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _read_pointer(ea):
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def _function_start(ea):
    func = ida_funcs.get_func(ea)
    return func.start_ea if func else idaapi.BADADDR


def _is_method_pointer(ea):
    if ea in (0, idaapi.BADADDR) or not ida_bytes.is_loaded(ea):
        return False
    func_ea = _function_start(ea)
    if func_ea == idaapi.BADADDR:
        return False
    seg = ida_segment.getseg(func_ea)
    return bool(seg and (seg.perm & ida_segment.SEGPERM_EXEC))


def _table_name(ea):
    name = ida_name.get_name(ea) or ""
    return name if name else "vftable_%X" % ea


def _read_slots(start_ea):
    """Read the contiguous run of function pointers beginning at start_ea."""
    slots = []
    ptr_size = _pointer_size()
    for index in range(_MAX_SLOTS):
        entry_ea = start_ea + index * ptr_size
        target = _read_pointer(entry_ea)
        if not _is_method_pointer(target):
            break
        slots.append((entry_ea, _function_start(target)))
    return slots


def _named_candidates():
    candidates = set()
    for ea, name in idautils.Names():
        if _VFTABLE_NAME.search(name or ""):
            candidates.add(ea)
    return candidates


def _resolve_named_table(symbol_ea):
    """Handle both MSVC tables and Itanium ABI tables with two header words."""
    ptr_size = _pointer_size()
    choices = []
    for skip in range(3):
        table_ea = symbol_ea + skip * ptr_size
        slots = _read_slots(table_ea)
        if slots:
            choices.append((len(slots), -skip, table_ea, slots))
    if not choices:
        return None, []
    _, _, table_ea, slots = max(choices)
    return table_ea, slots


def _scan_unnamed_candidates(occupied):
    """Conservatively find unnamed function-pointer arrays in non-code segments."""
    candidates = set()
    ptr_size = _pointer_size()
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        ea = (seg.start_ea + ptr_size - 1) & ~(ptr_size - 1)
        while ea + ptr_size <= seg.end_ea:
            if ea in occupied or not _is_method_pointer(_read_pointer(ea)):
                ea += ptr_size
                continue
            # Only accept the beginning of a run. This avoids duplicate tables.
            if ea - ptr_size >= seg.start_ea and _is_method_pointer(_read_pointer(ea - ptr_size)):
                ea += ptr_size
                continue
            slots = _read_slots(ea)
            if len(slots) >= _MIN_UNNAMED_SLOTS:
                candidates.add(ea)
                ea += len(slots) * ptr_size
            else:
                ea += ptr_size
    return candidates


def _xref_callers(ea):
    callers = {}
    for xref in idautils.XrefsTo(ea, 0):
        func = ida_funcs.get_func(xref.frm)
        if func:
            callers[func.start_ea] = ida_funcs.get_func_name(func.start_ea) or "sub_%X" % func.start_ea
    return callers


def scan_vftables():
    """Return vftables with methods, direct callers, and code references to the table."""
    named = _named_candidates()
    tables = []
    occupied = set()
    ptr_size = _pointer_size()

    for symbol_ea in sorted(named):
        table_ea, slots = _resolve_named_table(symbol_ea)
        if slots:
            # Keep the useful demangled symbol even when ABI header words were skipped.
            tables.append((table_ea, _table_name(symbol_ea), slots, True))
            occupied.update(table_ea + i * ptr_size for i in range(len(slots)))

    for table_ea in sorted(_scan_unnamed_candidates(occupied)):
        slots = _read_slots(table_ea)
        if slots:
            tables.append((table_ea, _table_name(table_ea), slots, False))

    rows = []
    for table_ea, table_name, slots, is_named in sorted(tables):
        table_users = _xref_callers(table_ea)
        # Constructors often reference an interior/secondary table entry.
        for entry_ea, _ in slots:
            table_users.update(_xref_callers(entry_ea))
        users_text = ", ".join(sorted(set(table_users.values()))) or "-"
        for slot, (entry_ea, method_ea) in enumerate(slots):
            callers = _xref_callers(method_ea)
            rows.append({
                "table_ea": table_ea,
                "table_name": table_name,
                "named": is_named,
                "slot": slot,
                "entry_ea": entry_ea,
                "method_ea": method_ea,
                "method_name": ida_funcs.get_func_name(method_ea) or "sub_%X" % method_ea,
                "callers": ", ".join(sorted(set(callers.values()))) or "-",
                "users": users_text,
            })
    return rows


class VftableChooser(ida_kernwin.Choose):
    def __init__(self):
        self.rows = []
        columns = [
            ["Vftable", 34], ["Table address", 16 | ida_kernwin.Choose.CHCOL_HEX],
            ["Slot", 7 | ida_kernwin.Choose.CHCOL_DEC],
            ["Function address", 16 | ida_kernwin.Choose.CHCOL_HEX],
            ["Function", 36], ["Direct callers", 44], ["Vftable users", 44],
        ]
        super(VftableChooser, self).__init__(
            "PseudoNote - Vftable List", columns,
            flags=ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._rescan()

    def _rescan(self):
        ida_kernwin.show_wait_box("HIDECANCEL\nScanning vftables...")
        try:
            self.rows = scan_vftables()
        finally:
            ida_kernwin.hide_wait_box()

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        row = self.rows[n]
        return [
            row["table_name"], "%X" % row["table_ea"], str(row["slot"]),
            "%X" % row["method_ea"], row["method_name"], row["callers"], row["users"],
        ]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n]["method_ea"])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnRefresh(self, n):
        self._rescan()
        return n


def show_vftable_list():
    global _viewer
    _viewer = VftableChooser()
    _viewer.Show()
    ida_kernwin.msg("[PseudoNote] Vftable List: %d methods found.\n" % len(_viewer.rows))


class VftableListHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        try:
            show_vftable_list()
        except Exception as exc:
            ida_kernwin.warning("Vftable scan failed:\n%s" % exc)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
