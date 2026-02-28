# -*- coding: utf-8 -*-
"""
Main view, settings dialog, context-menu hooks, and supporting UI for PseudoNote.
"""
import re
import functools

import idaapi
import ida_kernwin
import ida_hexrays
import idc
import idautils

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, get_text_width, set_tab_stop_width, Signal
from pseudonote.config import CONFIG, LOGGER
from pseudonote.syntax import MultiHighlighter
from pseudonote.editors import CodeEditor, MarkdownEditor
from pseudonote.idb_storage import (
    get_netnode, save_to_idb, load_from_idb,
    gather_function_context, format_context_for_prompt, format_context_for_display,
)
import pseudonote.ai_client as _ai_mod
from pseudonote.ai_client import AI_CANCEL_REQUESTED

def _get_ai():
    return _ai_mod.AI_CLIENT

def set_ai_cancel(cancel=True):
    global _force_cancelled
    _ai_mod.AI_CANCEL_REQUESTED = cancel
    if cancel:
        _force_cancelled = True
        # Immediately hide the overlay for better UX
        get_overlay().hide()
        # Reset ref count to zero safely
        global _progress_ref_count
        _progress_ref_count = 0

_global_overlay = None
_progress_ref_count = 0
_force_cancelled = False
_view_instance = None
plugin_instance = None

def get_overlay():
    global _global_overlay
    if not _global_overlay:
        _global_overlay = ProgressOverlay()
    return _global_overlay

def show_ai_progress(task_name, modal=False):
    global _progress_ref_count
    _progress_ref_count += 1
    get_overlay().show_progress(task_name, modal=modal)

def update_ai_progress_details(chars, status_text=None):
    get_overlay().update_details(chars, status_text)

def hide_ai_progress():
    global _global_overlay, _progress_ref_count, _force_cancelled
    _progress_ref_count -= 1
    if _progress_ref_count <= 0 or getattr(sys.modules[__name__], '_force_cancelled', False):
        _progress_ref_count = 0
        _force_cancelled = False
        if _global_overlay is not None:
            try:
                _global_overlay.hide()
            except RuntimeError:
                pass # C++ object deleted


class ProgressOverlay(QtWidgets.QDialog):
    """A standalone floating progress dialog for AI tasks."""
    def __init__(self, parent=None):
        super().__init__(parent or QtWidgets.QApplication.activeWindow())
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        
        # Increase size for better readability
        self.setFixedSize(520, 110)
        
        self.container = QtWidgets.QFrame(self)
        self.container.setObjectName("Container")
        self.container.setFixedSize(500, 90)
        self.container.setCursor(QtCore.Qt.SizeAllCursor)
        self._drag_pos = None
        
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setXOffset(0)
        shadow.setYOffset(0)
        shadow.setColor(QtGui.QColor(0, 0, 0, 180))
        self.container.setGraphicsEffect(shadow)

        # Main centering layout
        outer_layout = QtWidgets.QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.addWidget(self.container)
        
        # Inner layout for the container
        self.inner_layout = QtWidgets.QVBoxLayout(self.container)
        self.inner_layout.setContentsMargins(15, 12, 15, 12)
        self.inner_layout.setSpacing(6)
        
        self.container.setStyleSheet("""
            #Container { 
                background-color: #2D2D2D; 
                border: 1px solid #4E4E4E;
                border-radius: 10px;
                color: #CCCCCC;
                font-family: 'Inter', 'Segoe UI', sans-serif;
            }
        """)

        # Row 1: Header (Status + Stop Button)
        header_layout = QtWidgets.QHBoxLayout()
        header_layout.setSpacing(10)
        
        self.status_label = QtWidgets.QLabel("AI Working...")
        self.status_label.setStyleSheet("font-size: 13px; font-weight: bold; border: none; background: transparent; color: #FFFFFF;")
        header_layout.addWidget(self.status_label, 1)
        
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setFixedSize(75, 30)
        self.stop_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.stop_btn.setStyleSheet("""
            QPushButton { 
                background-color: #3E3E3E; border: 1px solid #555555; color: #EEEEEE; border-radius: 6px; font-size: 13px; font-weight: bold; font-family: 'Inter', sans-serif;
            }
            QPushButton:hover { background-color: #D32F2F; border: 1px solid #D32F2F; color: white; }
        """)
        self.stop_btn.clicked.connect(lambda: set_ai_cancel(True))
        header_layout.addWidget(self.stop_btn)
        self.inner_layout.addLayout(header_layout)
        
        # Row 2: Progress Bar
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar { background-color: #3E3E42; border: none; border-radius: 3px; }
            QProgressBar::chunk { background-color: #007ACC; border-radius: 3px; }
        """)
        self.inner_layout.addWidget(self.progress_bar)
        
        # Row 3: Details Label
        self.details_label = QtWidgets.QLabel("Preparing...")
        self.details_label.setStyleSheet("font-size: 11px; color: #AAAAAA; border: none; background: transparent;")
        self.details_label.setWordWrap(True)
        self.inner_layout.addWidget(self.details_label)
        
        self.hide()

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.move(event.globalPos() - self._drag_pos)
            event.accept()

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Escape:
            # Pressing ESC now cancels the AI task safely
            set_ai_cancel(True)
            event.accept()
        else:
            super().keyPressEvent(event)

    def show_progress(self, task_name, modal=False):
        self.status_label.setText(task_name)
        # Avoid resetting to "Preparing..." if it's already visible with status
        if not self.isVisible():
            self.details_label.setText("Preparing...")
        
        # Always use NonModal for PseudoNote to prevent deadlocks with execute_sync
        self.setWindowModality(QtCore.Qt.NonModal)
        
        # Center in IDA only if it's the first show
        if not hasattr(self, "_user_moved") or not self.isVisible():
            ida_win = QtWidgets.QApplication.activeWindow()
            if ida_win:
                geo = ida_win.geometry()
                self.move(geo.center().x() - self.width() // 2, geo.center().y() - self.height() // 2)
            self._user_moved = True
            
        self.show()
        self.raise_()
        self.activateWindow()

    def update_details(self, chars, status_text=None):
        if status_text:
            self.details_label.setText(status_text)
        else:
            self.details_label.setText(f"Received result: {chars} chars...")

_view_instance = None
START_TEXT = "Click the button to generate the code"
plugin_instance = None


class PseudoNoteChooser(idaapi.Choose):
    def __init__(self, title, flags=0):
        idaapi.Choose.__init__(
            self, title,
            [["Address", 16 | idaapi.Choose.CHCOL_HEX], ["Function Name", 30], ["Content", 20]],
            flags=flags | idaapi.Choose.CH_CAN_REFRESH
        )
        self.items = []
        self.icon = 199

    def OnInit(self):
        self.items = self._get_items()
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        ea = int(self.items[n][0], 16)
        idaapi.jumpto(ea)

    def OnDeleteLine(self, n):
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Are you sure you want to delete the saved PseudoNote for this function?") != idaapi.ASKBTN_YES:
            return idaapi.Choose.NOTHING
        ea = int(self.items[n][0], 16)
        node = get_netnode()
        if not node:
            return idaapi.Choose.NOTHING
        node.delblob(ea, 0)
        node.delblob(ea, 78)
        self.items = self._get_items()
        return idaapi.Choose.ALL_CHANGED

    def OnRefresh(self, n):
        self.items = self._get_items()
        return n

    def _get_items(self):
        items = []
        node = get_netnode()
        if not node:
            return items
        for ea in idautils.Functions():
            has_code = node.getblob(ea, 0) is not None
            has_note = node.getblob(ea, 78) is not None
            if has_code or has_note:
                name = idc.get_func_name(ea)
                offset = f"{ea:X}"
                content = []
                if has_code: content.append("Code")
                if has_note: content.append("Note")
                items.append([offset, name, " & ".join(content)])
        return items


class SavedNotesHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        PseudoNoteChooser("Saved PseudoNotes").Show()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


if QtWidgets:
    class TestConnectionWorker(QtCore.QThread):
        finished_signal = Signal(bool, str)

        def __init__(self, cfg):
            super().__init__()
            self.cfg = cfg

        def run(self):
            from pseudonote.ai_client import SimpleAI
            try:
                # Use a fresh client for testing
                tester = SimpleAI(self.cfg)
                success, message = tester.test_connection()
                self.finished_signal.emit(success, message)
            except Exception as e:
                self.finished_signal.emit(False, str(e))

    class SettingsDialog(QtWidgets.QDialog):
        def __init__(self, config, parent=None, hide_extra_tabs=False, mode=None):
            super().__init__(parent)
            self.config = config
            self.hide_extra_tabs = hide_extra_tabs
            self.mode = mode
            self.setWindowTitle("PseudoNote Settings")
            self.resize(700, 500)
            self.providers = ["OpenAI", "Anthropic", "DeepSeek", "Gemini", "Ollama", "LMStudio", "OpenAICompatible"]
            self.temp_settings = {
                "OpenAI": {"key": config.openai_key, "url": config.openai_url, "model": config.openai_model},
                "Anthropic": {"key": config.anthropic_key, "url": config.anthropic_url, "model": config.anthropic_model},
                "DeepSeek": {"key": config.deepseek_key, "url": config.deepseek_url, "model": config.deepseek_model},
                "Gemini": {"key": config.gemini_key, "url": "", "model": config.gemini_model},
                "Ollama": {"key": "", "url": config.ollama_host, "model": config.ollama_model},
                "LMStudio": {"key": config.lmstudio_key, "url": config.lmstudio_url, "model": config.lmstudio_model},
                "OpenAICompatible": {"key": config.custom_key, "url": config.custom_url, "model": config.custom_model},
            }
            self.current_provider = self.config.active_provider
            found = False
            for p in self.providers:
                if p.lower() == self.current_provider.lower():
                    self.current_provider = p; found = True; break
            if not found: self.current_provider = "OpenAI"
            self.font_settings = {
                "ui_font": config.ui_font, "ui_size": config.ui_font_size,
                "code_font": config.code_font, "code_size": config.code_font_size,
                "md_font": config.markdown_font, "md_size": config.markdown_font_size
            }
            self.init_ui()

        def init_ui(self):
            # Application-wide styling for this dialog to match Deep Summarizer aesthetic
            self.setStyleSheet("""
                QTabWidget::tab-bar {
                    alignment: left;
                }
                QTabWidget::pane {
                    border: 1px solid #D1D1D6;
                    border-radius: 8px;
                    background: #FFFFFF;
                }
                QTabBar::tab {
                    background: #F2F2F7;
                    border: 1px solid #D1D1D6;
                    border-bottom: none;
                    padding: 8px 16px;
                    border-radius: 6px 6px 0 0;
                    font-weight: bold;
                    color: #636366;
                }
                QTabBar::tab:selected {
                    background: #FFFFFF;
                    color: #1C1C1E;
                    border-top: 2px solid #007AFF;
                }
            """)
            main_layout = QtWidgets.QVBoxLayout()
            self.tabs = QtWidgets.QTabWidget()
            self.provider_tab = QtWidgets.QWidget()
            self.init_provider_tab()
            self.tabs.addTab(self.provider_tab, "AI Providers")
            
            self.appearance_tab = QtWidgets.QWidget()
            self.init_appearance_tab()
            if not self.hide_extra_tabs:
                self.tabs.addTab(self.appearance_tab, "Pane Appearance")
                
            self.bulk_tab = QtWidgets.QWidget()
            self.init_bulk_tab()
            if not self.hide_extra_tabs or self.mode == 'renamer':
                self.tabs.addTab(self.bulk_tab, "Bulk Function Renamer")

            self.analyze_tab = QtWidgets.QWidget()
            self.init_analyze_tab()
            if not self.hide_extra_tabs or self.mode == 'analyzer':
                self.tabs.addTab(self.analyze_tab, "Bulk Function Analyzer")

            self.var_renamer_tab = QtWidgets.QWidget()
            self.init_var_renamer_tab()
            if not self.hide_extra_tabs or self.mode == 'var_renamer':
                self.tabs.addTab(self.var_renamer_tab, "Bulk Variable Renamer")

            self.summarizer_tab = QtWidgets.QWidget()
            self.init_summarizer_tab()
            if not self.hide_extra_tabs or self.mode == 'summarizer':
                self.tabs.addTab(self.summarizer_tab, "Deep Summarizer")

            self.renaming_tab = QtWidgets.QWidget()
            self.init_rename_tab()
            if not self.hide_extra_tabs:
                self.tabs.addTab(self.renaming_tab, "Function rename")
                
            self.log_tab = QtWidgets.QWidget()
            self.init_log_tab()
            if not self.hide_extra_tabs:
                self.tabs.addTab(self.log_tab, "Debug Logs")
            main_layout.addWidget(self.tabs)
            val_save = QtWidgets.QDialogButtonBox.Save
            val_cancel = QtWidgets.QDialogButtonBox.Cancel
            if hasattr(val_save, "value"):
                btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton(val_save.value | val_cancel.value))
            else:
                btns = QtWidgets.QDialogButtonBox(val_save | val_cancel)
            btns.accepted.connect(self.on_save)
            btns.rejected.connect(self.reject)
            main_layout.addWidget(btns)
            self.setLayout(main_layout)

        def init_provider_tab(self):
            layout = QtWidgets.QVBoxLayout()
            h = QtWidgets.QHBoxLayout()
            h.addWidget(QtWidgets.QLabel("Active Provider:"))
            self.combo = QtWidgets.QComboBox()
            self.combo.addItems(self.providers)
            self.combo.setCurrentText(self.current_provider)
            self.combo.currentTextChanged.connect(self.on_provider_changed)
            h.addWidget(self.combo)
            layout.addLayout(h)
            form_grp = QtWidgets.QGroupBox("Configuration")
            fl = QtWidgets.QFormLayout()
            self.key_edit = QtWidgets.QLineEdit()
            self.url_edit = QtWidgets.QLineEdit()
            self.model_edit = QtWidgets.QLineEdit()
            self.key_label = QtWidgets.QLabel("API Key:")
            self.url_label = QtWidgets.QLabel("Base URL:")
            self.model_label = QtWidgets.QLabel("Model Name:")
            fl.addRow(self.key_label, self.key_edit)
            fl.addRow(self.url_label, self.url_edit)
            fl.addRow(self.model_label, self.model_edit)
            self.info_label = QtWidgets.QLabel("* Grayed out fields are not needed")
            self.info_label.setStyleSheet("color: gray; font-size: 10px;")
            fl.addRow(self.info_label)
            form_grp.setLayout(fl)
            layout.addWidget(form_grp)

            # Test Connection Button
            self.test_conn_btn = QtWidgets.QPushButton("Test Connection")
            self.test_conn_btn.clicked.connect(self.on_test_connection)
            layout.addWidget(self.test_conn_btn)
            
            self.test_result_label = QtWidgets.QLabel("")
            self.test_result_label.setWordWrap(True)
            self.test_result_label.setStyleSheet("font-size: 11px;")
            layout.addWidget(self.test_result_label)

            layout.addStretch()
            self.provider_tab.setLayout(layout)
            self.load_fields(self.current_provider)

        def on_test_connection(self):
            self.test_conn_btn.setEnabled(False)
            self.test_result_label.setText("Testing... please wait.")
            self.test_result_label.setStyleSheet("color: black; font-size: 11px;")
            
            # Temporary save fields to config for testing
            self.save_fields_to_temp(self.current_provider)
            # Create a temporary config object for testing without modifying global state yet
            from pseudonote.config import Config
            test_cfg = Config()
            # Copy all temp settings to this test_cfg
            test_cfg.active_provider = self.current_provider
            s = self.temp_settings
            test_cfg.openai_key = s["OpenAI"]["key"]; test_cfg.openai_url = s["OpenAI"]["url"]; test_cfg.openai_model = s["OpenAI"]["model"]
            test_cfg.anthropic_key = s["Anthropic"]["key"]; test_cfg.anthropic_url = s["Anthropic"]["url"]; test_cfg.anthropic_model = s["Anthropic"]["model"]
            test_cfg.deepseek_key = s["DeepSeek"]["key"]; test_cfg.deepseek_url = s["DeepSeek"]["url"]; test_cfg.deepseek_model = s["DeepSeek"]["model"]
            test_cfg.gemini_key = s["Gemini"]["key"]; test_cfg.gemini_model = s["Gemini"]["model"]
            test_cfg.ollama_host = s["Ollama"]["url"]; test_cfg.ollama_model = s["Ollama"]["model"]
            test_cfg.lmstudio_key = s["LMStudio"]["key"]; test_cfg.lmstudio_url = s["LMStudio"]["url"]; test_cfg.lmstudio_model = s["LMStudio"]["model"]
            test_cfg.custom_key = s["OpenAICompatible"]["key"]; test_cfg.custom_url = s["OpenAICompatible"]["url"]; test_cfg.custom_model = s["OpenAICompatible"]["model"]
            
            active_data = s.get(self.current_provider, {})
            test_cfg.model = active_data.get("model", test_cfg.model)

            # Use background worker to keep UI alive
            self.test_worker = TestConnectionWorker(test_cfg)
            self.test_worker.finished_signal.connect(self.on_test_result)
            self.test_worker.start()

        def on_test_result(self, success, message):
            self.test_conn_btn.setEnabled(True)
            if success:
                self.test_result_label.setText(message)
                self.test_result_label.setStyleSheet("color: #4EC9B0; font-size: 11px; font-weight: bold;")
            else:
                self.test_result_label.setText(f"Fail: {message}")
                self.test_result_label.setStyleSheet("color: #F44336; font-size: 11px;")

        def init_bulk_tab(self):
            layout = QtWidgets.QVBoxLayout()

            grp = QtWidgets.QGroupBox("Batching and Performance")
            fl = QtWidgets.QFormLayout()

            self.force_rename_cb = QtWidgets.QCheckBox("Force renaming; do not skip functions, even if they are large.")
            self.force_rename_cb.setChecked(getattr(self.config, 'force_bulk_rename', False))
            fl.addRow(self.force_rename_cb)

            self.bulk_force_rename_sub_cb = QtWidgets.QCheckBox("Force renaming even if it contains sub_* functions within it.")
            self.bulk_force_rename_sub_cb.setChecked(getattr(self.config, 'bulk_force_rename_sub', False))
            fl.addRow(self.bulk_force_rename_sub_cb)

            force_warn = QtWidgets.QLabel("Caution: Forcing large functions into big batches may cause truncated results or timeouts.\nRecommendation: Don't tick this box.")
            force_warn.setStyleSheet("color: #d10e00; font-style: italic; font-size: 12px; margin-left: 0px;")
            force_warn.setWordWrap(True)
            fl.addRow(force_warn)
            
            self.cooldown_spin = QtWidgets.QSpinBox()
            self.cooldown_spin.setRange(0, 300)
            self.cooldown_spin.setValue(getattr(self.config, 'bulk_cooldown', 22))
            fl.addRow("Cooldown seconds (Avoid rate limits):", self.cooldown_spin)

            self.asm_max_spin = QtWidgets.QSpinBox()
            self.asm_max_spin.setRange(5, 500)
            self.asm_max_spin.setValue(getattr(self.config, 'bulk_asm_max', 25))
            fl.addRow("Max Assembly Lines (Fallback):", self.asm_max_spin)

            self.disable_bulk_prefix_cb = QtWidgets.QCheckBox("Disable prefix")
            self.disable_bulk_prefix_cb.setChecked(not getattr(self.config, 'use_bulk_prefix', True))
            fl.addRow("", self.disable_bulk_prefix_cb)

            self.prefix_edit = QtWidgets.QLineEdit()
            self.prefix_edit.setText(getattr(self.config, 'rename_prefix', 'bulkren_'))
            self.prefix_edit.setPlaceholderText("bulkren_")
            fl.addRow("Rename Prefix:", self.prefix_edit)

            # Gray out logic for bulk
            self.disable_bulk_prefix_cb.toggled.connect(lambda checked: self.prefix_edit.setEnabled(not checked))
            self.prefix_edit.setEnabled(not self.disable_bulk_prefix_cb.isChecked())

            self.bulk_append_addr_cb = QtWidgets.QCheckBox("Append offset address (e.g., {prefix}_FunctionName_18001db0)")
            self.bulk_append_addr_cb.setChecked(getattr(self.config, 'bulk_append_address', False))
            fl.addRow("", self.bulk_append_addr_cb)

            self.bulk_use_0x_cb = QtWidgets.QCheckBox("Use 0x prefix for address (e.g., _0x18001db0)")
            self.bulk_use_0x_cb.setChecked(getattr(self.config, 'bulk_use_0x', False))
            self.bulk_use_0x_cb.setEnabled(self.bulk_append_addr_cb.isChecked())
            self.bulk_append_addr_cb.toggled.connect(self.bulk_use_0x_cb.setEnabled)
            fl.addRow("", self.bulk_use_0x_cb)
            

            self.custom_batch_spin = QtWidgets.QSpinBox()
            self.custom_batch_spin.setRange(1, 100)
            self.custom_batch_spin.setValue(getattr(self.config, 'bulk_batch_size', 10))
            fl.addRow("Batch Size (Functions per prompt):", self.custom_batch_spin)
            
            self.custom_workers_spin = QtWidgets.QSpinBox()
            self.custom_workers_spin.setRange(1, 10)
            self.custom_workers_spin.setValue(getattr(self.config, 'bulk_parallel_workers', 5))
            fl.addRow("Parallel Workers (Simultaneous threads):", self.custom_workers_spin)

            grp.setLayout(fl)
            layout.addWidget(grp)
            layout.addStretch()
            self.bulk_tab.setLayout(layout)

        def init_var_renamer_tab(self):
            layout = QtWidgets.QVBoxLayout()

            grp_perf = QtWidgets.QGroupBox("Bulk Variable Renamer — Performance")
            fl_perf = QtWidgets.QFormLayout()

            self.var_batch_spin = QtWidgets.QSpinBox()
            self.var_batch_spin.setRange(1, 100)
            self.var_batch_spin.setValue(getattr(self.config, 'var_batch_size', 5))
            fl_perf.addRow("Batch Size (Functions per prompt):", self.var_batch_spin)

            self.var_workers_spin = QtWidgets.QSpinBox()
            self.var_workers_spin.setRange(1, 10)
            self.var_workers_spin.setValue(getattr(self.config, 'var_parallel_workers', 3))
            fl_perf.addRow("Parallel Workers (Simultaneous threads):", self.var_workers_spin)
            
            self.var_cooldown_spin = QtWidgets.QSpinBox()
            self.var_cooldown_spin.setRange(0, 300)
            self.var_cooldown_spin.setValue(getattr(self.config, 'var_cooldown', 15))
            fl_perf.addRow("Cooldown seconds (Avoid rate limits):", self.var_cooldown_spin)

            self.var_asm_max_spin = QtWidgets.QSpinBox()
            self.var_asm_max_spin.setRange(5, 500)
            self.var_asm_max_spin.setValue(getattr(self.config, 'var_asm_max', 25))
            fl_perf.addRow("Max Assembly Lines (Fallback):", self.var_asm_max_spin)

            grp_perf.setLayout(fl_perf)
            layout.addWidget(grp_perf)
            
            grp_apply = QtWidgets.QGroupBox("Bulk Variable Renamer — Options")
            fl_apply = QtWidgets.QFormLayout()

            self.var_auto_apply_cb = QtWidgets.QCheckBox(
                "Automatically apply renames as each function completes"
            )
            self.var_auto_apply_cb.setChecked(getattr(self.config, 'var_auto_apply', True))
            fl_apply.addRow(self.var_auto_apply_cb)

            auto_warn = QtWidgets.QLabel(
                "When enabled, renames are written to IDA immediately after each function's AI response.\n"
                "This means you cannot review suggestions before they are applied."
            )
            auto_warn.setWordWrap(True)
            auto_warn.setStyleSheet("color: #d10e00; font-style: italic; font-size: 11px;")
            fl_apply.addRow(auto_warn)

            self.var_force_rename_cb = QtWidgets.QCheckBox(
                "Force variable renaming even if it contains sub_* functions within it."
            )
            self.var_force_rename_cb.setChecked(getattr(self.config, 'var_force_rename', False))
            fl_apply.addRow(self.var_force_rename_cb)

            grp_apply.setLayout(fl_apply)
            layout.addWidget(grp_apply)
            
            layout.addStretch()
            self.var_renamer_tab.setLayout(layout)

        def init_analyze_tab(self):
            layout = QtWidgets.QVBoxLayout()
            grp = QtWidgets.QGroupBox("Analysis Settings")
            fl = QtWidgets.QFormLayout()

            info = QtWidgets.QLabel(
                "These settings affect the Bulk Function Analyzer.\n"
                "Batch Size and Workers are configured here since the Analyzer supports parallelism."
            )
            info.setWordWrap(True)
            info.setStyleSheet("color: gray; font-style: italic; margin-bottom: 5px;")
            fl.addRow(info)

            self.analyze_workers_spin = QtWidgets.QSpinBox()
            self.analyze_workers_spin.setRange(1, 10)
            self.analyze_workers_spin.setValue(getattr(self.config, 'analyze_parallel_workers', 5))
            fl.addRow("Parallel Workers:", self.analyze_workers_spin)

            self.analyze_batch_spin = QtWidgets.QSpinBox()
            self.analyze_batch_spin.setRange(1, 100)
            self.analyze_batch_spin.setValue(getattr(self.config, 'analyze_batch_size', 10))
            fl.addRow("Batch Size:", self.analyze_batch_spin)

            self.analyze_cooldown_spin = QtWidgets.QSpinBox()
            self.analyze_cooldown_spin.setRange(0, 300)
            self.analyze_cooldown_spin.setValue(getattr(self.config, 'analyze_cooldown', 22))
            fl.addRow("Rate Limit Cooldown (s):", self.analyze_cooldown_spin)

            grp.setLayout(fl)
            layout.addWidget(grp)
            layout.addStretch()
            self.analyze_tab.setLayout(layout)

        def init_appearance_tab(self):
            layout = QtWidgets.QVBoxLayout()
            db = QtGui.QFontDatabase()
            families = db.families()
            self.font_widgets = {}
            groups = [
                ("Plugin UI Logic", "ui", "Applies to buttons, menus, tabs."),
                ("Converted Code", "code", "Applies to C and Assembly editors."),
                ("Markdown/Notes", "md", "Applies to documentation and notes.")
            ]
            for title, key, desc in groups:
                grp = QtWidgets.QGroupBox(title)
                gl = QtWidgets.QGridLayout()
                font_combo = QtWidgets.QComboBox()
                font_combo.addItems(families)
                current_fam = self.font_settings[f"{key}_font"]
                idx = font_combo.findText(current_fam)
                if idx >= 0: font_combo.setCurrentIndex(idx)
                else: font_combo.setCurrentText("Inter" if key=="ui" else "Consolas")
                size_spin = QtWidgets.QSpinBox()
                size_spin.setRange(6, 72)
                size_spin.setValue(self.font_settings[f"{key}_size"])
                gl.addWidget(QtWidgets.QLabel("Font Family:"), 0, 0)
                gl.addWidget(font_combo, 0, 1)
                gl.addWidget(QtWidgets.QLabel("Size:"), 0, 2)
                gl.addWidget(size_spin, 0, 3)
                gl.addWidget(QtWidgets.QLabel(desc), 1, 0, 1, 4)
                grp.setLayout(gl)
                layout.addWidget(grp)
                self.font_widgets[key] = (font_combo, size_spin)
            layout.addStretch()
            self.appearance_tab.setLayout(layout)

        def init_summarizer_tab(self):
            layout = QtWidgets.QVBoxLayout()



            # Components
            comp_grp = QtWidgets.QGroupBox("Analysis Components")
            comp_layout = QtWidgets.QGridLayout()

            self.deep_bottom_up_rename_cb = QtWidgets.QCheckBox("Automated bottom-up function renaming")
            self.deep_bottom_up_rename_cb.setChecked(getattr(self.config, 'deep_do_bottom_up_rename', True))
            comp_layout.addWidget(self.deep_bottom_up_rename_cb, 0, 0)
            
            self.deep_var_rename_cb = QtWidgets.QCheckBox("Rename variables")
            self.deep_var_rename_cb.setChecked(getattr(self.config, 'deep_do_var_rename', True))
            comp_layout.addWidget(self.deep_var_rename_cb, 0, 1)
            
            self.deep_func_comment_cb = QtWidgets.QCheckBox("Add function's purpose as comments")
            self.deep_func_comment_cb.setChecked(getattr(self.config, 'deep_do_func_comment', True))
            comp_layout.addWidget(self.deep_func_comment_cb, 1, 0)
            
            self.deep_analysis_rename_cb = QtWidgets.QCheckBox("Final Rename based on whole-code semantic")
            self.deep_analysis_rename_cb.setChecked(getattr(self.config, 'deep_do_analysis_rename', True))
            comp_layout.addWidget(self.deep_analysis_rename_cb, 1, 1)

            comp_grp.setLayout(comp_layout)
            layout.addWidget(comp_grp)

            # Performance
            perf_grp = QtWidgets.QGroupBox("Performance & Rates")
            fl = QtWidgets.QFormLayout()
            
            self.deep_workers_spin = QtWidgets.QSpinBox()
            self.deep_workers_spin.setRange(1, 50)
            self.deep_workers_spin.setValue(getattr(self.config, 'deep_parallel_workers', 1))
            fl.addRow("Parallel Workers:", self.deep_workers_spin)
            
            self.deep_batch_spin = QtWidgets.QSpinBox()
            self.deep_batch_spin.setRange(1, 100)
            self.deep_batch_spin.setValue(getattr(self.config, 'deep_batch_size', 10))
            fl.addRow("Batch Size (Funcs):", self.deep_batch_spin)
            
            self.deep_lines_spin = QtWidgets.QSpinBox()
            self.deep_lines_spin.setRange(10, 5000)
            self.deep_lines_spin.setValue(getattr(self.config, 'deep_max_lines', 200))
            fl.addRow("Max Lines per Func:", self.deep_lines_spin)

            self.deep_cooldown_spin = QtWidgets.QSpinBox()
            self.deep_cooldown_spin.setRange(0, 300)
            self.deep_cooldown_spin.setValue(getattr(self.config, 'deep_cooldown', 0))
            fl.addRow("Cooldown (s):", self.deep_cooldown_spin)

            perf_grp.setLayout(fl)
            layout.addWidget(perf_grp)

            # Naming
            name_grp = QtWidgets.QGroupBox("Naming Convention")
            nl = QtWidgets.QVBoxLayout()
            
            h1 = QtWidgets.QHBoxLayout()
            self.deep_use_prefix_cb = QtWidgets.QCheckBox("Use Prefix")
            self.deep_use_prefix_cb.setChecked(getattr(self.config, 'deep_use_prefix', True))
            h1.addWidget(self.deep_use_prefix_cb)
            
            self.deep_prefix_edit = QtWidgets.QLineEdit()
            self.deep_prefix_edit.setText(getattr(self.config, 'deep_prefix', 'da_'))
            self.deep_prefix_edit.setPlaceholderText("da_")
            self.deep_prefix_edit.setFixedWidth(100)
            self.deep_prefix_edit.setEnabled(self.deep_use_prefix_cb.isChecked())
            self.deep_use_prefix_cb.toggled.connect(self.deep_prefix_edit.setEnabled)
            h1.addWidget(self.deep_prefix_edit)
            h1.addStretch()
            nl.addLayout(h1)
            
            self.deep_append_addr_cb = QtWidgets.QCheckBox("Append address postfix")
            self.deep_append_addr_cb.setChecked(getattr(self.config, 'deep_append_address', True))
            nl.addWidget(self.deep_append_addr_cb)
            
            self.deep_use_0x_cb = QtWidgets.QCheckBox("Use 0x for address (e.g., _0x18001db0)")
            self.deep_use_0x_cb.setChecked(getattr(self.config, 'deep_use_0x', False))
            self.deep_use_0x_cb.setEnabled(self.deep_append_addr_cb.isChecked())
            self.deep_append_addr_cb.toggled.connect(self.deep_use_0x_cb.setEnabled)
            nl.addWidget(self.deep_use_0x_cb)
            
            name_grp.setLayout(nl)
            layout.addWidget(name_grp)

            layout.addStretch()
            self.summarizer_tab.setLayout(layout)

        def on_provider_changed(self, text):
            self.save_fields_to_temp(self.current_provider)
            self.current_provider = text
            self.load_fields(text)

        def init_rename_tab(self):
            layout = QtWidgets.QVBoxLayout()
            
            grp = QtWidgets.QGroupBox("Function Renaming Settings")
            fl = QtWidgets.QFormLayout()
            
            self.disable_prefix_cb = QtWidgets.QCheckBox("Disable prefix")
            # If use_rename_prefix is True, disable_prefix is False
            use_pref = getattr(self.config, 'use_rename_prefix', True)
            self.disable_prefix_cb.setChecked(not use_pref)
            fl.addRow("", self.disable_prefix_cb)
            
            self.func_prefix_edit = QtWidgets.QLineEdit()
            self.func_prefix_edit.setText(getattr(self.config, 'function_prefix', 'fn_'))
            self.func_prefix_edit.setPlaceholderText("fn_ (empty for none)")
            fl.addRow("Rename prefix:", self.func_prefix_edit)

            self.disable_prefix_cb.toggled.connect(lambda checked: self.func_prefix_edit.setEnabled(not checked))
            self.func_prefix_edit.setEnabled(not self.disable_prefix_cb.isChecked())

            self.rename_append_addr_cb = QtWidgets.QCheckBox("Append offset address (e.g., fn_FunctionName_18001db0)")
            self.rename_append_addr_cb.setChecked(getattr(self.config, 'rename_append_address', False))
            fl.addRow("", self.rename_append_addr_cb)
            
            self.rename_use_0x_cb = QtWidgets.QCheckBox("Use 0x prefix for address (e.g., _0x18001db0)")
            self.rename_use_0x_cb.setChecked(getattr(self.config, 'rename_use_0x', False))
            self.rename_use_0x_cb.setEnabled(self.rename_append_addr_cb.isChecked())
            self.rename_append_addr_cb.toggled.connect(self.rename_use_0x_cb.setEnabled)
            fl.addRow("", self.rename_use_0x_cb)
            
            grp.setLayout(fl)
            layout.addWidget(grp)
            
            info = QtWidgets.QLabel("This prefix applies to 'Rename Function' context menu actions (both code and malware). You can leave it empty or uncheck the box above if you don't want any prefix.")
            info.setStyleSheet("color: gray; font-style: italic;")
            info.setWordWrap(True)
            layout.addWidget(info)
            
            layout.addStretch()
            self.renaming_tab.setLayout(layout)

        def save_fields_to_temp(self, provider):
            if provider in self.temp_settings:
                self.temp_settings[provider]["key"] = self.key_edit.text()
                self.temp_settings[provider]["url"] = self.url_edit.text()
                self.temp_settings[provider]["model"] = self.model_edit.text()

        def load_fields(self, provider):
            data = self.temp_settings.get(provider, {})
            self.key_edit.setText(data.get("key", ""))
            self.url_edit.setText(data.get("url", ""))
            self.model_edit.setText(data.get("model", ""))
            self.key_edit.setEnabled(True)
            self.url_edit.setEnabled(True)
            self.model_edit.setEnabled(True)
            self.key_edit.setPlaceholderText("")
            self.url_edit.setPlaceholderText("")
            self.key_label.setText("API Key:")
            if provider == "Ollama":
                self.key_edit.setEnabled(False)
                self.key_edit.setPlaceholderText("Not required")
                self.url_label.setText("Host:")
                self.url_edit.setPlaceholderText("http://localhost:11434")
            elif provider == "Gemini":
                self.url_edit.setEnabled(False)
                self.url_edit.setText("")
                self.url_edit.setPlaceholderText("Managed by Google GenAI SDK")
                self.url_label.setText("Base URL:")
            else:
                self.url_label.setText("Base URL:")
                if provider == "OpenAI":
                    self.url_edit.setPlaceholderText("https://api.openai.com/v1")
                elif provider == "LMStudio":
                    self.url_edit.setPlaceholderText("http://localhost:1234/v1")
                    self.key_label.setText("API Key (Optional):")

        def init_log_tab(self):
            layout = QtWidgets.QVBoxLayout()
            self.log_view = QtWidgets.QPlainTextEdit()
            self.log_view.setReadOnly(True)
            self.log_view.setStyleSheet("background-color: #1E1E1E; color: #D4D4D4; font-family: Consolas;")
            self.log_view.setPlainText("\n".join(LOGGER.logs))
            layout.addWidget(self.log_view)
            self.log_tab.setLayout(layout)
            sb = self.log_view.verticalScrollBar()
            sb.setValue(sb.maximum())
            if hasattr(LOGGER, 'log_signal'):
                LOGGER.log_signal.connect(self.append_log)

        def append_log(self, text):
            self.log_view.appendPlainText(text)

        def closeEvent(self, event):
            if hasattr(self, 'test_worker') and self.test_worker.isRunning():
                self.test_worker.terminate()
                self.test_worker.wait()
            if hasattr(LOGGER, 'log_signal'):
                try: LOGGER.log_signal.disconnect(self.append_log)
                except: pass
            super().closeEvent(event)

        def on_save(self):
            self.save_fields_to_temp(self.current_provider)
            c = self.config
            c.active_provider = self.combo.currentText()
            s = self.temp_settings
            c.openai_key = s["OpenAI"]["key"]; c.openai_url = s["OpenAI"]["url"]; c.openai_model = s["OpenAI"]["model"]
            c.anthropic_key = s["Anthropic"]["key"]; c.anthropic_url = s["Anthropic"]["url"]; c.anthropic_model = s["Anthropic"]["model"]
            c.deepseek_key = s["DeepSeek"]["key"]; c.deepseek_url = s["DeepSeek"]["url"]; c.deepseek_model = s["DeepSeek"]["model"]
            c.gemini_key = s["Gemini"]["key"]; c.gemini_model = s["Gemini"]["model"]
            c.ollama_host = s["Ollama"]["url"]; c.ollama_model = s["Ollama"]["model"]
            c.lmstudio_key = s["LMStudio"]["key"]; c.lmstudio_url = s["LMStudio"]["url"]; c.lmstudio_model = s["LMStudio"]["model"]
            c.custom_key = s["OpenAICompatible"]["key"]; c.custom_url = s["OpenAICompatible"]["url"]; c.custom_model = s["OpenAICompatible"]["model"]
            active_data = s.get(c.active_provider, {})
            if active_data.get("model"):
                c.model = active_data.get("model")

            # Appearance (only present when hide_extra_tabs=False)
            if hasattr(self, 'font_widgets'):
                fw = self.font_widgets
                c.ui_font = fw["ui"][0].currentText(); c.ui_font_size = fw["ui"][1].value()
                c.code_font = fw["code"][0].currentText(); c.code_font_size = fw["code"][1].value()
                c.markdown_font = fw["md"][0].currentText(); c.markdown_font_size = fw["md"][1].value()

            # Bulk Renamer tab settings
            if hasattr(self, 'force_rename_cb'):
                c.force_bulk_rename = self.force_rename_cb.isChecked()
            if hasattr(self, 'bulk_force_rename_sub_cb'):
                c.bulk_force_rename_sub = self.bulk_force_rename_sub_cb.isChecked()
            if hasattr(self, 'cooldown_spin'):
                c.bulk_cooldown = self.cooldown_spin.value()
            if hasattr(self, 'asm_max_spin'):
                c.bulk_asm_max = self.asm_max_spin.value()
            if hasattr(self, 'disable_bulk_prefix_cb'):
                c.use_bulk_prefix = not self.disable_bulk_prefix_cb.isChecked()
            if hasattr(self, 'prefix_edit'):
                c.rename_prefix = self.prefix_edit.text().strip() or "bulkren_"
            if hasattr(self, 'bulk_append_addr_cb'):
                c.bulk_append_address = self.bulk_append_addr_cb.isChecked()
                c.bulk_use_0x = self.bulk_use_0x_cb.isChecked()
            if hasattr(self, 'custom_batch_spin'):
                c.bulk_batch_size = self.custom_batch_spin.value()
            if hasattr(self, 'custom_workers_spin'):
                c.bulk_parallel_workers = self.custom_workers_spin.value()

            # Bulk Function Analyzer tab settings
            if hasattr(self, 'analyze_workers_spin'):
                c.analyze_parallel_workers = self.analyze_workers_spin.value()
            if hasattr(self, 'analyze_batch_spin'):
                c.analyze_batch_size = self.analyze_batch_spin.value()
            if hasattr(self, 'analyze_cooldown_spin') and (not self.hide_extra_tabs or self.mode == 'analyzer'):
                c.analyze_cooldown = self.analyze_cooldown_spin.value()

            # Bulk Variable Renamer tab settings
            if hasattr(self, 'var_batch_spin'):
                c.var_batch_size = self.var_batch_spin.value()
            if hasattr(self, 'var_workers_spin'):
                c.var_parallel_workers = self.var_workers_spin.value()
            if hasattr(self, 'var_cooldown_spin') and (not self.hide_extra_tabs or self.mode == 'var_renamer'):
                c.var_cooldown = self.var_cooldown_spin.value()
            if hasattr(self, 'var_asm_max_spin'):
                c.var_asm_max = self.var_asm_max_spin.value()
            if hasattr(self, 'var_auto_apply_cb'):
                c.var_auto_apply = self.var_auto_apply_cb.isChecked()
            if hasattr(self, 'var_force_rename_cb'):
                c.var_force_rename = self.var_force_rename_cb.isChecked()

            # Function Rename tab settings
            if hasattr(self, 'disable_prefix_cb'):
                c.use_rename_prefix = not self.disable_prefix_cb.isChecked()
            if hasattr(self, 'func_prefix_edit'):
                c.function_prefix = self.func_prefix_edit.text().strip()
            if hasattr(self, 'rename_append_addr_cb'):
                c.rename_append_address = self.rename_append_addr_cb.isChecked()
            if hasattr(self, 'rename_use_0x_cb'):
                c.rename_use_0x = self.rename_use_0x_cb.isChecked()

            # Deep Summarizer settings
            if hasattr(self, 'deep_batch_spin'):
                c.deep_batch_size = self.deep_batch_spin.value()
                c.deep_parallel_workers = self.deep_workers_spin.value()
                c.deep_cooldown = self.deep_cooldown_spin.value()
                c.deep_max_lines = self.deep_lines_spin.value()

                c.deep_do_var_rename = self.deep_var_rename_cb.isChecked()
                c.deep_do_func_comment = self.deep_func_comment_cb.isChecked()
                c.deep_do_analysis_rename = self.deep_analysis_rename_cb.isChecked()
                c.deep_do_refinement = True
                c.deep_do_bottom_up_rename = self.deep_bottom_up_rename_cb.isChecked()
                c.deep_use_prefix = self.deep_use_prefix_cb.isChecked()
                c.deep_prefix = self.deep_prefix_edit.text().strip() or "da_"
                c.deep_append_address = self.deep_append_addr_cb.isChecked()
                c.deep_use_0x = self.deep_use_0x_cb.isChecked()

            c.save()
            self.accept()

    class PseudoNoteView(idaapi.PluginForm):
        def __init__(self, config):
            super().__init__()
            self.config = config
            self.current_ea = None
            self.last_func_ea = None
            self.parent = None
            self.hooks = None
            self.code_text_area = None
            self.code_save_btn = None
            self.c_convert_btn = None
            self.asm_convert_btn = None
            self.code_status_stack = None
            self.code_status_label = None
            self.c_status_label = None
            self.asm_status_label = None
            self.comments_ai_status_label = None
            self.last_saved_c_code = ""
            self.last_saved_asm_code = ""
            self.note_tab_widget = None
            self.note_stack = None
            self.note_viewer = None
            self.note_editor = None
            self.explanation_viewer = None
            self.note_save_btn = None
            self.note_edit_btn = None
            self.explain_code_btn = None
            self.explain_malware_btn = None
            self.suggest_name_btn = None
            self.gflow_btn = None
            self.last_saved_note = ""
            self.title_label = None
            self.highlighter = None
            self.lang_combo = None
            self.current_lang = "C"
            self.notes_light_mode = True
            self.code_light_mode = False
            self.highlighters = []
            self.code_pages = []
            self.status_pages = []

        def OnCreate(self, form):
            global _view_instance
            self.parent = self.FormToPyQtWidget(form)
            _view_instance = self
            # Reset trackers to avoid dangling references during init
            self.highlighters = []
            self.code_pages = []
            self.status_pages = []
            self.init_ui()
            self.hooks = ScreenHooks(self)
            self.hooks.hook()
            AI = _get_ai()
            if AI: AI.log_provider_info()
            self.refresh_ui(force=True)
            self.check_ai_busy_timer = QtCore.QTimer()
            self.check_ai_busy_timer.timeout.connect(self.update_ai_busy_ui)
            self.check_ai_busy_timer.start(500)

        def update_ai_busy_ui(self):
            """Sync UI state with global AI_BUSY flag."""
            is_busy = _ai_mod.AI_BUSY
            self.set_ai_features_enabled(not is_busy)
            
            # If we are not busy and ref count is still > 0, it might be a dangling dialog 
            # or it might be the transition between preparation and generation.
            # We only force hide if we are CERTAIN we are not in a task.
            if not is_busy:
                # If we were busy and now we're not, reset cancel flag
                _ai_mod.AI_CANCEL_REQUESTED = False

        def set_ai_features_enabled(self, enabled):
            """Disable/Enable all buttons that trigger AI actions."""
            try:
                # Readable Code buttons
                if self.c_convert_btn: self.c_convert_btn.setEnabled(enabled)
                if self.asm_convert_btn: self.asm_convert_btn.setEnabled(enabled)
                if self.get_comments_ai_btn: self.get_comments_ai_btn.setEnabled(enabled)
                
                # Analyst Notes buttons
                if self.explain_code_btn: self.explain_code_btn.setEnabled(enabled)
                if self.explain_malware_btn: self.explain_malware_btn.setEnabled(enabled)
                if self.suggest_name_btn: self.suggest_name_btn.setEnabled(enabled)
                if self.gflow_btn: self.gflow_btn.setEnabled(enabled)
                # Code Toolbar buttons
                if self.manual_edit_btn: self.manual_edit_btn.setEnabled(enabled)
                if self.code_save_btn: self.code_save_btn.setEnabled(enabled)
                if self.lang_combo: self.lang_combo.setEnabled(enabled)

                # Placeholders (Status Labels / Pages)
                if self.c_status_label: self.c_status_label.setEnabled(enabled)
                if self.asm_status_label: self.asm_status_label.setEnabled(enabled)
                if self.comments_ai_status_label: self.comments_ai_status_label.setEnabled(enabled)
                for page in self.status_pages:
                    if page: page.setEnabled(enabled)
            except RuntimeError:
                # Object likely deleted during teardown
                if hasattr(self, 'check_ai_busy_timer') and self.check_ai_busy_timer:
                    self.check_ai_busy_timer.stop()

        def init_ui(self):
            # Also reset in init_ui for safety
            self.highlighters = []
            self.code_pages = []
            self.status_pages = []
            
            layout = QtWidgets.QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            self.splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

            self.show_code_btn = QtWidgets.QPushButton("Show Readable Code")
            self.show_code_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.show_code_btn.clicked.connect(self.on_show_code)
            self.show_code_btn.setVisible(False)
            self.splitter.addWidget(self.show_code_btn)

            self.code_widget = QtWidgets.QWidget()
            code_layout = QtWidgets.QVBoxLayout()
            code_layout.setContentsMargins(0,0,0,0)

            c_header = QtWidgets.QWidget()
            c_header.setStyleSheet("background-color: #2D2D2D; border-bottom: 1px solid #3E3E42;")
            ch_layout = QtWidgets.QHBoxLayout()
            ch_layout.setContentsMargins(10,5,10,5)

            self.toggle_code_btn = QtWidgets.QPushButton("▼")
            self.toggle_code_btn.setFixedSize(20, 20)
            self.toggle_code_btn.clicked.connect(self.on_toggle_code)
            self.toggle_code_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; font-weight: bold; background: transparent; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; }")
            ch_layout.addWidget(self.toggle_code_btn)

            self.title_label = QtWidgets.QLabel("Code")
            self.title_label.setStyleSheet("color: #CCCCCC; font-weight: bold;")
            ch_layout.addWidget(self.title_label)
            ch_layout.addStretch()

            self.code_theme_toggle_btn = QtWidgets.QPushButton("☀")
            self.code_theme_toggle_btn.setFixedSize(24, 24)
            self.code_theme_toggle_btn.setToolTip("Toggle Light/Dark Mode for Code")
            self.code_theme_toggle_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; background: transparent; font-size: 16px; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; } QToolTip { color: #ffffff; background-color: #2D2D2D; border: 1px solid #3E3E42; }")
            self.code_theme_toggle_btn.clicked.connect(self.on_toggle_code_theme)
            ch_layout.addWidget(self.code_theme_toggle_btn)

            self.settings_btn = QtWidgets.QPushButton("⚙")
            self.settings_btn.setFixedSize(24, 24)
            self.settings_btn.setToolTip("Configure AI Provider")
            self.settings_btn.clicked.connect(self.on_settings)
            self.settings_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; background: transparent; font-size: 16px; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; } QToolTip { color: #ffffff; background-color: #2D2D2D; border: 1px solid #3E3E42; }")
            ch_layout.addWidget(self.settings_btn)

            c_header.setLayout(ch_layout)
            code_layout.addWidget(c_header)

            self.code_tab_widget = QtWidgets.QTabWidget()
            self.code_tab_widget.setFocusPolicy(QtCore.Qt.NoFocus)
            self.code_tab_widget.setStyleSheet(self.get_tab_style())

            res_asm = self.create_code_page("ASM")
            self.asm_page_widget = res_asm[0]
            self.asm_convert_btn = res_asm[1]
            self.asm_status_stack = res_asm[2]
            self.asm_code_editor = res_asm[3]
            self.asm_status_label = res_asm[4]
            self.asm_highlighter = res_asm[5]
            self.code_tab_widget.addTab(self.asm_page_widget, "IDA-View")

            res_c = self.create_code_page("C")
            self.c_page_widget = res_c[0]
            self.c_convert_btn = res_c[1]
            self.c_status_stack = res_c[2]
            self.c_code_editor = res_c[3]
            self.c_status_label = res_c[4]
            self.c_highlighter = res_c[5]
            self.code_tab_widget.addTab(self.c_page_widget, "Pseudocode")

            # Code Comments tab
            self.comments_ai_stack = QtWidgets.QStackedWidget()
            cm_status_page = QtWidgets.QWidget()
            cm_status_page.setStyleSheet("background-color: #1E1E1E;")
            cm_sp_layout = QtWidgets.QVBoxLayout()
            cm_sp_layout.setAlignment(QtCore.Qt.AlignCenter)
            self.comments_ai_status_label = QtWidgets.QLabel(START_TEXT)
            self.comments_ai_status_label.setStyleSheet("color: #888888; font-size: 16px; background-color: transparent;")
            cm_sp_layout.addWidget(self.comments_ai_status_label)
            cm_status_page.setLayout(cm_sp_layout)
            self.comments_ai_stack.addWidget(cm_status_page)

            self.comments_ai_editor = self.create_editor(code=True)
            self.comments_ai_highlighter = MultiHighlighter(self.comments_ai_editor.document())
            self.comments_ai_highlighter.update_rules("C")
            self.comments_ai_stack.addWidget(self.comments_ai_editor)

            cm_widget = QtWidgets.QWidget()
            cm_layout = QtWidgets.QVBoxLayout()
            cm_layout.setContentsMargins(0, 5, 0, 0)
            cm_layout.addWidget(self.comments_ai_stack)
            cm_widget.setLayout(cm_layout)
            self.code_tab_widget.addTab(cm_widget, "Code Comments")
            
            self.code_pages.extend([self.asm_page_widget, self.c_page_widget, cm_widget])
            # Assuming status_page in create_code_page is what's added to stacks
            # Extracting status pages from stacks
            self.status_pages.extend([self.asm_status_stack.widget(0), self.c_status_stack.widget(0), cm_status_page])

            # Corner widget for code tabs
            self.corner_widget = QtWidgets.QWidget()
            cw_layout = QtWidgets.QHBoxLayout()
            cw_layout.setContentsMargins(0, 0, 5, 0)

            self.manual_edit_btn = QtWidgets.QPushButton("Edit")
            self.manual_edit_btn.setToolTip("Switch to editor to paste your own code")
            self.manual_edit_btn.setMinimumWidth(60)
            self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.manual_edit_btn.clicked.connect(self.on_manual_edit)
            cw_layout.addWidget(self.manual_edit_btn)

            self.get_comments_ai_btn = QtWidgets.QPushButton("Get Comments (AI)")
            self.get_comments_ai_btn.setToolTip("Rewrite code with section comments")
            self.get_comments_ai_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.get_comments_ai_btn.clicked.connect(self.on_get_comments_ai)
            self.get_comments_ai_btn.setVisible(False)
            cw_layout.addWidget(self.get_comments_ai_btn)

            self.code_save_btn = self.create_save_btn(self.on_save_code)
            cw_layout.addWidget(self.code_save_btn)

            self.lang_combo = QtWidgets.QComboBox()
            self.lang_combo.addItems(["C", "C++", "C#", "Python", "Go", "Rust", "Delphi", "Nim"])
            self.lang_combo.setCurrentText("C")
            self.lang_combo.setFixedWidth(90)
            self.lang_combo.setStyleSheet("""
                QComboBox { background-color: #FFFFFF; color: #333333; border: 1px solid #AAAAAA; border-radius: 4px; padding: 3px 5px; font-weight: bold; }
                QComboBox QAbstractItemView { background-color: #252526; color: #FFFFFF; selection-background-color: #007ACC; selection-color: #FFFFFF; border: 1px solid #3E3E42; outline: none; }
            """)
            self.lang_combo.currentTextChanged.connect(self.on_lang_changed)
            cw_layout.addWidget(self.lang_combo)

            cw_layout.addWidget(self.asm_convert_btn)
            cw_layout.addWidget(self.c_convert_btn)
            self.corner_widget.setLayout(cw_layout)
            self.code_tab_widget.setCornerWidget(self.corner_widget, QtCore.Qt.TopRightCorner)

            self.asm_convert_btn.setVisible(True)
            self.c_convert_btn.setVisible(False)
            self.code_tab_widget.currentChanged.connect(self.on_code_tab_changed)
            code_layout.addWidget(self.code_tab_widget)
            self.code_widget.setLayout(code_layout)
            self.splitter.addWidget(self.code_widget)

            # --- Notes section ---
            self.show_notes_btn = QtWidgets.QPushButton("Show Analyst Notes")
            self.show_notes_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.show_notes_btn.clicked.connect(self.on_show_notes)
            self.show_notes_btn.setVisible(False)
            self.splitter.addWidget(self.show_notes_btn)

            self.note_widget = QtWidgets.QWidget()
            note_layout = QtWidgets.QVBoxLayout()
            note_layout.setContentsMargins(0,0,0,0)

            n_header = QtWidgets.QWidget()
            n_header.setStyleSheet("background-color: #2D2D2D; border-bottom: 1px solid #3E3E42; border-top: 1px solid #3E3E42;")
            nh_layout = QtWidgets.QHBoxLayout()
            nh_layout.setContentsMargins(10,5,10,5)
            self.toggle_notes_btn = QtWidgets.QPushButton("▼")
            self.toggle_notes_btn.setFixedSize(20, 20)
            self.toggle_notes_btn.clicked.connect(self.on_toggle_notes)
            self.toggle_notes_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; font-weight: bold; background: transparent; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; }")
            nh_layout.addWidget(self.toggle_notes_btn)
            self.func_name_label = QtWidgets.QLabel("Analyst notes: None")
            self.func_name_label.setStyleSheet("color: #CCCCCC; font-weight: bold; margin-left: 5px;")
            nh_layout.addWidget(self.func_name_label)
            nh_layout.addStretch()

            self.theme_toggle_btn = QtWidgets.QPushButton("☀")
            self.theme_toggle_btn.setFixedSize(24, 24)
            self.theme_toggle_btn.setToolTip("Toggle Light/Dark Mode for Notes")
            self.theme_toggle_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; background: transparent; font-size: 16px; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; } QToolTip { color: #ffffff; background-color: #2D2D2D; border: 1px solid #3E3E42; }")
            self.theme_toggle_btn.clicked.connect(self.on_toggle_notes_theme)
            nh_layout.addWidget(self.theme_toggle_btn)

            n_header.setLayout(nh_layout)
            note_layout.addWidget(n_header)

            self.note_tab_widget = QtWidgets.QTabWidget()
            self.note_tab_widget.setFocusPolicy(QtCore.Qt.NoFocus)

            # Note corner widget
            self.note_corner_widget = QtWidgets.QWidget()
            nc_layout = QtWidgets.QHBoxLayout()
            nc_layout.setContentsMargins(0, 0, 5, 0)

            self.explain_code_btn = QtWidgets.QPushButton("Code")
            self.explain_code_btn.setToolTip("Analyze logic and control flow")
            self.explain_code_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.explain_code_btn.clicked.connect(functools.partial(self.on_explain_func, context="code"))
            nc_layout.addWidget(self.explain_code_btn)

            self.explain_malware_btn = QtWidgets.QPushButton("Malware")
            self.explain_malware_btn.setToolTip("Analyze for malicious behavior/IOCs")
            self.explain_malware_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.explain_malware_btn.clicked.connect(functools.partial(self.on_explain_func, context="malware"))
            nc_layout.addWidget(self.explain_malware_btn)

            self.suggest_name_btn = QtWidgets.QPushButton("Function Details (AI)")
            self.suggest_name_btn.setToolTip("Ask AI for function names, return value info, and interesting calls")
            self.suggest_name_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.suggest_name_btn.clicked.connect(self.on_suggest_name)
            nc_layout.addWidget(self.suggest_name_btn)

            self.gflow_btn = QtWidgets.QPushButton("Get graph")
            self.gflow_btn.setToolTip("Generate a text-based flow graph of the function")
            self.gflow_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.gflow_btn.clicked.connect(self.on_get_gflow)
            nc_layout.addWidget(self.gflow_btn)

            self.note_edit_btn = QtWidgets.QPushButton("Edit")
            self.note_edit_btn.setFixedWidth(80)
            self.note_edit_btn.setStyleSheet(self.get_btn_style(blue=True))
            self.note_edit_btn.clicked.connect(self.on_edit_note)
            nc_layout.addWidget(self.note_edit_btn)

            self.note_view_btn = QtWidgets.QPushButton("Cancel")
            self.note_view_btn.setFixedWidth(80)
            self.note_view_btn.setStyleSheet(self.get_btn_style(blue=False))
            self.note_view_btn.clicked.connect(lambda: self.toggle_note_mode(edit=False))
            self.note_view_btn.setVisible(False)
            nc_layout.addWidget(self.note_view_btn)

            self.note_save_btn = self.create_save_btn(self.on_save_note)
            nc_layout.addWidget(self.note_save_btn)
            self.note_corner_widget.setLayout(nc_layout)
            self.note_tab_widget.setCornerWidget(self.note_corner_widget, QtCore.Qt.TopRightCorner)
            self.note_tab_widget.setStyleSheet(self.get_tab_style())

            # Markdown Notes tab
            self.note_stack = QtWidgets.QStackedWidget()
            self.note_viewer = QtWidgets.QTextBrowser()
            self.note_viewer.setOpenExternalLinks(True)
            self.note_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.note_viewer.setPlaceholderText("Click 'Edit' button to add notes.")
            self.note_stack.addWidget(self.note_viewer)

            self.note_editor = MarkdownEditor()
            self.note_editor.setFont(QtGui.QFont("Consolas", 10))
            self.note_editor.setStyleSheet("QPlainTextEdit { background-color: #1E1E1E; color: #D4D4D4; border: none; }")
            self.note_editor.textChanged.connect(self.on_note_text_changed)
            self.note_editor.textChanged.connect(self.render_markdown_preview)

            self.note_split_widget = QtWidgets.QWidget()
            split_layout = QtWidgets.QHBoxLayout()
            split_layout.setContentsMargins(0,0,0,0)
            self.note_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
            self.note_splitter.addWidget(self.note_editor)
            self.note_previewer = QtWidgets.QTextBrowser()
            self.note_previewer.setOpenExternalLinks(True)
            self.note_previewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border-left: 1px solid #3E3E42; padding: 10px; font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.note_splitter.addWidget(self.note_previewer)
            self.note_splitter.setStretchFactor(0, 1)
            self.note_splitter.setStretchFactor(1, 1)
            split_layout.addWidget(self.note_splitter)
            self.note_split_widget.setLayout(split_layout)
            self.note_stack.addWidget(self.note_split_widget)

            note_page_widget = QtWidgets.QWidget()
            note_page_layout = QtWidgets.QVBoxLayout()
            note_page_layout.setContentsMargins(0,5,0,0)
            self.markdown_toolbar = self.create_markdown_toolbar(self.note_editor)
            note_page_layout.addWidget(self.markdown_toolbar)
            self.markdown_toolbar.setVisible(False)
            note_page_layout.addWidget(self.note_stack)
            note_page_widget.setLayout(note_page_layout)
            self.note_tab_widget.addTab(note_page_widget, "Markdown Notes")

            # Function Explain tab
            self.explanation_viewer = QtWidgets.QTextBrowser()
            self.explanation_viewer.setOpenExternalLinks(True)
            self.explanation_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.explanation_viewer.setPlaceholderText("Click 'Explain (AI)' to generate an explanation for the current function.")
            ex_widget = QtWidgets.QWidget()
            ex_layout = QtWidgets.QVBoxLayout()
            ex_layout.setContentsMargins(0, 5, 0, 0)
            ex_layout.addWidget(self.explanation_viewer)
            ex_widget.setLayout(ex_layout)
            self.note_tab_widget.addTab(ex_widget, "Function Explain (AI)")

            # Function Graph tab
            self.gflow_viewer = QtWidgets.QTextBrowser()
            self.gflow_viewer.setOpenExternalLinks(True)
            self.gflow_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.gflow_viewer.setPlaceholderText("Click 'Get graph' to generate a text flow graph.")
            gf_widget = QtWidgets.QWidget()
            gf_layout = QtWidgets.QVBoxLayout()
            gf_layout.setContentsMargins(0, 5, 0, 0)
            gf_layout.addWidget(self.gflow_viewer)
            gf_widget.setLayout(gf_layout)
            self.note_tab_widget.addTab(gf_widget, "Tree Graph (AI)")

            # Function Details tab
            self.suggestion_viewer = QtWidgets.QTextBrowser()
            self.suggestion_viewer.setOpenExternalLinks(True)
            self.suggestion_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.suggestion_viewer.setPlaceholderText("Click 'Function Details (AI)' to generate details.")
            sg_widget = QtWidgets.QWidget()
            sg_layout = QtWidgets.QVBoxLayout()
            sg_layout.setContentsMargins(0, 5, 0, 0)
            sg_layout.addWidget(self.suggestion_viewer)
            sg_widget.setLayout(sg_layout)
            self.note_tab_widget.addTab(sg_widget, "Function Details (AI)")

            note_layout.addWidget(self.note_tab_widget)
            self.note_widget.setLayout(note_layout)
            self.splitter.addWidget(self.note_widget)

            layout.addWidget(self.splitter)
            
            # Progress Overlay managed globally
            
            self.parent.setLayout(layout)

            self.note_tab_widget.currentChanged.connect(self.on_note_tab_changed)
            self.toggle_note_mode(edit=False)
            self.on_note_tab_changed(0)
            self.apply_fonts_and_styles()

        # --- Tab change handlers ---
        def on_note_tab_changed(self, index):
            # Reset all buttons to hidden first
            self.note_edit_btn.setVisible(False)
            self.note_save_btn.setVisible(False)
            self.note_view_btn.setVisible(False)
            self.explain_code_btn.setVisible(False)
            self.explain_malware_btn.setVisible(False)
            self.gflow_btn.setVisible(False)
            self.suggest_name_btn.setVisible(False)
            if self.markdown_toolbar: self.markdown_toolbar.setVisible(False)

            is_notes_tab = (index == 0)
            if is_notes_tab:
                # Let toggle_note_mode handle edit/view/save buttons for Notes tab
                is_editing = False
                if self.note_stack and self.note_editor:
                    is_editing = (self.note_stack.currentWidget() == self.note_editor)
                self.toggle_note_mode(edit=is_editing)
            else:
                # Show specific buttons for AI tabs
                if index == 1: # Explain
                    self.explain_code_btn.setVisible(True)
                    self.explain_malware_btn.setVisible(True)
                elif index == 2: # Graph
                    self.gflow_btn.setVisible(True)
                elif index == 3: # Function Details
                    self.suggest_name_btn.setVisible(True)

        def create_editor(self, code=False):
            if code:
                ed = CodeEditor()
                ed.setReadOnly(True)
                fam = self.config.code_font
                size = self.config.code_font_size
            else:
                ed = MarkdownEditor()
                fam = self.config.markdown_font
                size = self.config.markdown_font_size
            ed.setStyleSheet("QPlainTextEdit { background-color: #1E1E1E; color: #D4D4D4; border: none; selection-background-color: #264F78; }")
            font = QtGui.QFont(fam, size)
            if code:
                font.setStyleHint(QtGui.QFont.Monospace)
            ed.setFont(font)
            metrics = QtGui.QFontMetrics(font)
            set_tab_stop_width(ed, 4 * get_text_width(metrics, ' '))
            return ed

        def create_code_page(self, mode):
             page = QtWidgets.QWidget()
             layout = QtWidgets.QVBoxLayout()
             layout.setContentsMargins(0, 5, 0, 0)
             stack = QtWidgets.QStackedWidget()
             status_page = QtWidgets.QWidget()
             sp_layout = QtWidgets.QVBoxLayout()
             sp_layout.setAlignment(QtCore.Qt.AlignCenter)
             status_label = QtWidgets.QLabel(START_TEXT)
             status_label.setStyleSheet("color: #888888; font-size: 14px; font-style: italic; background-color: transparent;")
             sp_layout.addWidget(status_label)
             status_page.setLayout(sp_layout)
             stack.addWidget(status_page)
             editor = self.create_editor(code=True)
             editor.textChanged.connect(self.on_code_text_changed)
             highlighter = None
             if MultiHighlighter:
                 highlighter = MultiHighlighter(editor.document())
                 self.highlighters.append(highlighter)
             stack.addWidget(editor)
             layout.addWidget(stack)
             btn_text = f"Convert to {self.current_lang} (AI)"
             btn = QtWidgets.QPushButton(btn_text)
             btn.setStyleSheet(self.get_btn_style(blue=True))
             btn.setFixedWidth(200)
             btn.clicked.connect(functools.partial(self.on_convert, mode=mode))
             page.setLayout(layout)
             return page, btn, stack, editor, status_label, highlighter

        def on_code_tab_changed(self, index):
            if not getattr(self, "c_code_editor", None) or not getattr(self, "asm_code_editor", None): return

            # Reset checks
            is_asm_tab = (index == 0)
            is_c_tab = (index == 1)
            is_comments_tab = (index == 2)

            # Revert edits if switching away from editable tab
            if is_asm_tab and not self.c_code_editor.isReadOnly():
                self.c_code_editor.setPlainText(self.last_saved_c_code)
                self.c_code_editor.setReadOnly(True)
            elif is_c_tab and not self.asm_code_editor.isReadOnly():
                self.asm_code_editor.setPlainText(self.last_saved_asm_code)
                self.asm_code_editor.setReadOnly(True)
            elif is_comments_tab:
                if not self.asm_code_editor.isReadOnly():
                    self.asm_code_editor.setPlainText(self.last_saved_asm_code)
                    self.asm_code_editor.setReadOnly(True)
                if not self.c_code_editor.isReadOnly():
                    self.c_code_editor.setPlainText(self.last_saved_c_code)
                    self.c_code_editor.setReadOnly(True)

            # Set Button Visibility Explicitly
            self.asm_convert_btn.setVisible(is_asm_tab)
            self.c_convert_btn.setVisible(is_c_tab)
            self.get_comments_ai_btn.setVisible(is_comments_tab)
            
            # Common controls (Edit, Save, Lang) are hidden on Comments tab
            visible_controls = not is_comments_tab
            self.manual_edit_btn.setVisible(visible_controls)
            self.lang_combo.setVisible(visible_controls)
            self.code_save_btn.setVisible(visible_controls)
            
            # Reset Edit Button State
            self.manual_edit_btn.setText("Edit")
            self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))
            
            self.on_code_text_changed()

        def create_save_btn(self, cb):
            btn = QtWidgets.QPushButton("Save")
            btn.setFixedWidth(60)
            btn.clicked.connect(cb)
            btn.setVisible(False)
            return btn

        def get_btn_style(self, variant="primary", blue=None):
             if blue is not None:
                 variant = "primary" if blue else "danger"
             fam = self.config.ui_font
             size = self.config.ui_font_size
             base = f"QPushButton {{ color: #FFFFFF; border-radius: 4px; font-weight: bold; padding: 6px 12px; font-family: '{fam}'; font-size: {size}pt; outline: none; }}"
             if variant == "success":
                 return base + "QPushButton { background-color: #238636; border: 1px solid rgba(255,255,255,0.1); } QPushButton:hover { background-color: #2EA043; } QPushButton:pressed { background-color: #1B5E20; } QPushButton:disabled { background-color: #3E3E42; color: #888888; border: 1px solid #3E3E42; }"
             elif variant == "danger":
                 return base + "QPushButton { background-color: #D32F2F; border: 1px solid #B71C1C; } QPushButton:hover { background-color: #F44336; } QPushButton:pressed { background-color: #B71C1C; } QPushButton:disabled { background-color: #3E3E42; color: #888888; border: 1px solid #3E3E42; }"
             else:
                 return base + "QPushButton { background-color: #007ACC; border: 1px solid #007ACC; } QPushButton:hover { background-color: #0062A3; } QPushButton:pressed { background-color: #004080; } QPushButton:disabled { background-color: #3E3E42; color: #888888; border: 1px solid #3E3E42; }"

        def update_save_btn_state(self, btn, saved=True):
            if saved:
                btn.setVisible(False)
                if btn == self.note_save_btn:
                     self.note_view_btn.setVisible(True)
            else:
                btn.setEnabled(True)
                btn.setStyleSheet(self.get_btn_style(variant="success"))
                btn.setVisible(True)
                if btn == self.note_save_btn:
                     btn.setText("Save"); btn.setFixedWidth(60); btn.setToolTip("Save Notes")
                     self.note_view_btn.setVisible(False)
                else:
                     btn.setText("Save"); btn.setFixedWidth(60); btn.setToolTip("Save Code")

        def create_markdown_toolbar(self, editor):
            tb = QtWidgets.QWidget()
            tb.setStyleSheet("background-color: #252526; border-bottom: 1px solid #3E3E42;")
            layout = QtWidgets.QHBoxLayout()
            layout.setContentsMargins(5, 2, 5, 2)
            layout.setSpacing(4)
            tb.setLayout(layout)
            actions = [
                ("B", "**", "**", "Bold"), ("I", "*", "*", "Italic"),
                ("Code", "`", "`", "Inline Code"), ("Block", "```\n", "\n```", "Code Block"),
                ("Link", "[", "](URL)", "Hyperlink"), ("Img", "![", "](Path/URL)", "Image"),
                ("List", "- ", "", "Bulleted List"), ("Num", "1. ", "", "Numbered List"),
                ("Task", "- [ ] ", "", "Task List"), ("H1", "# ", "", "Heading 1"), ("H2", "## ", "", "Heading 2"),
            ]
            for label, start, end, tooltip in actions:
                btn = QtWidgets.QPushButton(label)
                btn.setToolTip(tooltip)
                width = 40 if len(label) > 2 else 30
                btn.setFixedWidth(width); btn.setFixedHeight(24)
                btn.setStyleSheet("""
                    QPushButton { background-color: #3E3E42; color: #E0E0E0; border: none; border-radius: 3px; font-family: 'Inter', 'Segoe UI'; font-weight: bold; }
                    QPushButton:hover { background-color: #4E4E52; }
                    QPushButton:pressed { background-color: #007ACC; color: white; }
                """)
                btn.clicked.connect(functools.partial(self.insert_markdown, editor, start, end))
                layout.addWidget(btn)
            layout.addStretch()
            return tb

        def insert_markdown(self, editor, start_tag, end_tag):
            cursor = editor.textCursor()
            line_starters = ["- ", "1. ", "- [ ] ", "# ", "## ", "```"]
            if any(start_tag.startswith(s) for s in line_starters):
                 if cursor.positionInBlock() > 0:
                      cursor.insertText("\n")
            if cursor.hasSelection():
                text = cursor.selectedText()
                cursor.insertText(f"{start_tag}{text}{end_tag}")
            else:
                cursor.insertText(f"{start_tag}{end_tag}")
                if end_tag:
                    if start_tag.startswith("```"):
                        cursor.movePosition(QtGui.QTextCursor.Left, QtGui.QTextCursor.MoveAnchor, len(end_tag) - 1 if "\n" in end_tag else len(end_tag))
                    else:
                        cursor.movePosition(QtGui.QTextCursor.Left, QtGui.QTextCursor.MoveAnchor, len(end_tag))
            editor.setFocus()

        def toggle_note_mode(self, edit=True):
            is_notes_tab = (self.note_tab_widget.currentIndex() == 0)
            if edit:
                self.note_stack.setCurrentWidget(self.note_split_widget)
                self.render_markdown_preview()
                if is_notes_tab:
                    self.update_save_btn_state(self.note_save_btn, saved=False)
                    self.note_edit_btn.setVisible(False)
                    if self.markdown_toolbar: self.markdown_toolbar.setVisible(True)
                    self.note_view_btn.setVisible(True)
                else:
                    self.note_save_btn.setVisible(False); self.note_edit_btn.setVisible(False)
                    self.note_view_btn.setVisible(False)
                    if self.markdown_toolbar: self.markdown_toolbar.setVisible(False)
            else:
                self.note_stack.setCurrentWidget(self.note_viewer)
                if is_notes_tab:
                    self.note_save_btn.setVisible(False); self.note_edit_btn.setVisible(True)
                    self.note_view_btn.setVisible(False)
                    if self.markdown_toolbar: self.markdown_toolbar.setVisible(False)
                else:
                    self.note_save_btn.setVisible(False); self.note_edit_btn.setVisible(False)
                    self.note_view_btn.setVisible(False)
                text = self.note_editor.toPlainText()
                self.note_viewer.setMarkdown(text)

        def on_edit_note(self):
            self.toggle_note_mode(edit=True)

        def on_code_text_changed(self):
            if not getattr(self, "c_code_editor", None) or not getattr(self, "asm_code_editor", None): return
            if _ai_mod.AI_BUSY: return
            try:
                index = self.code_tab_widget.currentIndex()
                if index == 2: return # Code Comments tab - ignore updates
                
                if index == 0:
                    if not self.asm_code_editor: return
                    current = self.asm_code_editor.toPlainText(); saved = self.last_saved_asm_code
                else:
                    if not self.c_code_editor: return
                    current = self.c_code_editor.toPlainText(); saved = self.last_saved_c_code
                is_modified = current != saved
                if self.code_save_btn:
                    self.update_save_btn_state(self.code_save_btn, saved=not is_modified)
            except RuntimeError: pass

        def on_note_text_changed(self):
            current_text = self.note_editor.toPlainText()
            is_modified = current_text != self.last_saved_note
            self.update_save_btn_state(self.note_save_btn, saved=not is_modified)

        def on_save_code(self):
             if not self.current_ea: return
             func = idaapi.get_func(self.current_ea)
             if func:
                index = self.code_tab_widget.currentIndex()
                if index == 0:
                     code = self.asm_code_editor.toPlainText()
                     save_to_idb(func.start_ea, code, tag=81)
                     self.last_saved_asm_code = code; target = self.asm_code_editor
                else:
                     code = self.c_code_editor.toPlainText()
                     save_to_idb(func.start_ea, code, tag=0)
                     self.last_saved_c_code = code; target = self.c_code_editor
                self.update_save_btn_state(self.code_save_btn, saved=True)
                target.setReadOnly(True)
                self.manual_edit_btn.setText("Edit")
                self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))
                target.clearFocus()

        def on_lang_changed(self, text):
            self.current_lang = text
            c_text = self.c_convert_btn.text()
            if "Regenerate" in c_text: self.c_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
            elif "Converting" not in c_text: self.c_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
            asm_text = self.asm_convert_btn.text()
            if "Regenerate" in asm_text: self.asm_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
            elif "Converting" not in asm_text: self.asm_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
            if self.c_highlighter: self.c_highlighter.update_rules(self.current_lang)
            if self.asm_highlighter: self.asm_highlighter.update_rules(self.current_lang)

        def render_markdown_preview(self):
            text = self.note_editor.toPlainText()
            self.note_previewer.setMarkdown(text)

        def set_loading(self, active, btn=None, loading_text="Processing..."):
            buttons = [self.asm_convert_btn, self.c_convert_btn, self.explain_code_btn,
                       self.explain_malware_btn, self.suggest_name_btn, self.gflow_btn, self.get_comments_ai_btn]
            if active:
                for b in buttons: 
                    if b: b.setEnabled(False)
                if btn: 
                    btn.original_text = btn.text()
                    btn.setText(loading_text)
            else:
                for b in buttons: 
                    if b: b.setEnabled(True)
                for b in buttons:
                    if b and hasattr(b, 'original_text'):
                        b.setText(b.original_text)
                        delattr(b, 'original_text')

        def on_save_note(self):
             if not self.current_ea: return
             func = idaapi.get_func(self.current_ea)
             if func:
                note = self.note_editor.toPlainText()
                save_to_idb(func.start_ea, note, tag=78)
                self.last_saved_note = note
                self.update_save_btn_state(self.note_save_btn, saved=True)
                self.toggle_note_mode(edit=False)

        def on_toggle_notes(self):
            self.note_widget.setVisible(False); self.show_notes_btn.setVisible(True)
            self.markdown_toolbar.setVisible(False)
        def on_show_notes(self):
            self.show_notes_btn.setVisible(False); self.note_widget.setVisible(True)
            if self.note_stack.currentWidget() == self.note_editor: self.markdown_toolbar.setVisible(True)
        def on_toggle_code(self):
            self.code_widget.setVisible(False); self.show_code_btn.setVisible(True)
        def on_show_code(self):
            self.show_code_btn.setVisible(False); self.code_widget.setVisible(True)

        def on_manual_edit(self):
            index = self.code_tab_widget.currentIndex()
            if index == 2: return # Prevent edits on Comments tab

            editor = self.asm_code_editor if index == 0 else self.c_code_editor
            stack = self.asm_status_stack if index == 0 else self.c_status_stack
            if self.manual_edit_btn.text() == "Edit":
                stack.setCurrentWidget(editor); editor.setReadOnly(False); editor.setFocus()
                self.manual_edit_btn.setText("Cancel"); self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=False))
            else:
                reverted_text = self.last_saved_asm_code if index == 0 else self.last_saved_c_code
                editor.setPlainText(reverted_text)
                if not reverted_text: stack.setCurrentWidget(stack.widget(0))
                else: editor.setReadOnly(True); editor.highlightCurrentLine(); editor.clearFocus()
                self.manual_edit_btn.setText("Edit"); self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))
                self.on_code_text_changed()

        def get_tab_style(self):
            fam = self.config.ui_font; size = self.config.ui_font_size
            return f"""
                QTabWidget::tab-bar {{ alignment: left; }}
                QTabWidget::pane {{ border: 0; }}
                QTabBar::tab {{ background: #2D2D2D; color: #CCCCCC; min-width: 160px; padding: 8px 12px; margin-right: 2px; outline: 0; font-family: '{fam}'; font-size: {size}pt; }}
                QTabBar::tab:selected {{ background: #1E1E1E; color: #FFFFFF; font-weight: bold; border-top: 2px solid #007ACC; }}
                QTabBar::tab:hover {{ background: #3E3E42; }}
                QTabBar::tab:focus {{ outline: none; border: none; }}
            """

        def on_toggle_notes_theme(self):
            self.notes_light_mode = not self.notes_light_mode
            self.theme_toggle_btn.setText("🌙" if self.notes_light_mode else "☀")
            self.apply_fonts_and_styles()

        def on_toggle_code_theme(self):
            self.code_light_mode = not self.code_light_mode
            self.code_theme_toggle_btn.setText("🌙" if self.code_light_mode else "☀")
            self.apply_fonts_and_styles()

        def apply_fonts_and_styles(self):
             c_font = QtGui.QFont(self.config.code_font, self.config.code_font_size)
             c_font.setStyleHint(QtGui.QFont.Monospace)
             if hasattr(self, 'asm_code_editor') and self.asm_code_editor: self.asm_code_editor.setFont(c_font)
             if hasattr(self, 'c_code_editor') and self.c_code_editor: self.c_code_editor.setFont(c_font)
             if hasattr(self, 'comments_ai_editor') and self.comments_ai_editor: self.comments_ai_editor.setFont(c_font)
             # Theme colors for Code
             c_bg = "#FFFFFF" if self.code_light_mode else "#1E1E1E"
             c_fg = "#222222" if self.code_light_mode else "#D4D4D4"
             c_border = "1px solid #DDDDDD" if self.code_light_mode else "none"

             # Theme colors for Notes
             n_bg = "#FFFFFF" if self.notes_light_mode else "#1E1E1E"
             n_fg = "#222222" if self.notes_light_mode else "#D4D4D4"
             n_border = "1px solid #DDDDDD" if self.notes_light_mode else "none"

             c_fam = self.config.code_font
             c_size = self.config.code_font_size
             m_fam = self.config.markdown_font
             m_size = self.config.markdown_font_size

             code_style = f"QPlainTextEdit {{ background-color: {c_bg}; color: {c_fg}; border: {c_border}; font-family: '{c_fam}'; font-size: {c_size}pt; }}"

             def safe_set_light_mode(w, mode):
                 if not w: return
                 try:
                     if hasattr(w, 'set_light_mode'):
                         w.set_light_mode(mode)
                 except RuntimeError:
                     pass

             if hasattr(self, 'asm_code_editor'):
                 try: self.asm_code_editor.setStyleSheet(code_style)
                 except RuntimeError: pass
                 safe_set_light_mode(getattr(self, 'asm_code_editor', None), self.code_light_mode)
                 
             if hasattr(self, 'c_code_editor'):
                 try: self.c_code_editor.setStyleSheet(code_style)
                 except RuntimeError: pass
                 safe_set_light_mode(getattr(self, 'c_code_editor', None), self.code_light_mode)
                 
             if hasattr(self, 'comments_ai_editor'):
                 try: self.comments_ai_editor.setStyleSheet(code_style)
                 except RuntimeError: pass
                 safe_set_light_mode(getattr(self, 'comments_ai_editor', None), self.code_light_mode)
             
             # Filter dead highlighters
             valid_hls = []
             for hl in self.highlighters:
                 try:
                     if hasattr(hl, 'set_light_mode'):
                         hl.set_light_mode(self.code_light_mode)
                     valid_hls.append(hl)
                 except RuntimeError:
                     continue
             self.highlighters = valid_hls

             note_style = f"QPlainTextEdit {{ background-color: {n_bg}; color: {n_fg}; border: {n_border}; font-family: '{m_fam}'; font-size: {m_size}pt; }}"
             if hasattr(self, 'note_editor'):
                 try: self.note_editor.setStyleSheet(note_style)
                 except RuntimeError: pass
                 safe_set_light_mode(getattr(self, 'note_editor', None), self.notes_light_mode)

             note_viewer_style = f"QTextBrowser {{ border: {n_border}; background-color: {n_bg}; color: {n_fg}; padding: 10px; font-family: '{m_fam}'; font-size: {m_size}pt; }}"
             def safe_set_ss(obj, style):
                 if not obj: return
                 try: obj.setStyleSheet(style)
                 except RuntimeError: pass

             safe_set_ss(getattr(self, 'note_viewer', None), note_viewer_style)
             safe_set_ss(getattr(self, 'note_previewer', None), note_viewer_style)
             safe_set_ss(getattr(self, 'explanation_viewer', None), note_viewer_style)
             safe_set_ss(getattr(self, 'suggestion_viewer', None), note_viewer_style)
             safe_set_ss(getattr(self, 'gflow_viewer', None), note_viewer_style)
             ui_fam = self.config.ui_font
             ui_size = self.config.ui_font_size
             if hasattr(self, 'title_label') and self.title_label:
                  self.title_label.setStyleSheet(f"color: #CCCCCC; font-weight: bold; font-family: '{ui_fam}'; font-size: {ui_size}pt; margin-left: 5px;")
             if hasattr(self, 'func_name_label') and self.func_name_label:
                  self.func_name_label.setStyleSheet(f"color: #CCCCCC; font-weight: bold; font-family: '{ui_fam}'; font-size: {ui_size}pt; margin-left: 5px;")
             if hasattr(self, 'c_status_label') and self.c_status_label:
                  self.c_status_label.setStyleSheet(f"color: #888888; font-style: italic; background-color: transparent; font-family: '{ui_fam}'; font-size: {ui_size}pt;")
             if hasattr(self, 'asm_status_label') and self.asm_status_label:
                  self.asm_status_label.setStyleSheet(f"color: #888888; font-style: italic; background-color: transparent; font-family: '{ui_fam}'; font-size: {ui_size}pt;")
             if hasattr(self, 'comments_ai_status_label') and self.comments_ai_status_label:
                  self.comments_ai_status_label.setStyleSheet(f"color: #888888; font-style: italic; background-color: transparent; font-family: '{ui_fam}'; font-size: {ui_size}pt;")

             # Update page backgrounds
             for p in self.code_pages:
                 if p: p.setStyleSheet(f"background-color: {c_bg};")
             for sp in self.status_pages:
                 if sp: sp.setStyleSheet(f"background-color: {c_bg};")

             sheet = self.get_tab_style()
             for tabs in [getattr(self, 'code_tab_widget', None), getattr(self, 'note_tab_widget', None)]:
                 if tabs:
                     tabs.setStyleSheet(sheet)
                     tabs.setUsesScrollButtons(True)
                     bar = tabs.tabBar()
                     if bar:
                         bar.setExpanding(False)
                         bar.setElideMode(QtCore.Qt.ElideNone)
             primary_btns = [
                 self.show_code_btn, self.manual_edit_btn, self.asm_convert_btn, self.c_convert_btn,
                 self.show_notes_btn, self.explain_code_btn, self.explain_malware_btn, self.suggest_name_btn,
                 self.gflow_btn, self.note_edit_btn
             ]
             success_btns = [self.code_save_btn, self.note_save_btn]
             danger_btns = [self.note_view_btn]
             for b in primary_btns:
                 if b: b.setStyleSheet(self.get_btn_style("primary"))
             for b in success_btns:
                 if b: b.setStyleSheet(self.get_btn_style("success"))
             for b in danger_btns:
                 if b: b.setStyleSheet(self.get_btn_style("danger"))
             if hasattr(self, 'code_tab_widget'): self.on_code_tab_changed(self.code_tab_widget.currentIndex())
             if hasattr(self, 'note_stack'): self.toggle_note_mode(edit=(self.note_stack.currentWidget() == self.note_editor))

        def on_settings(self):
            dlg = SettingsDialog(CONFIG, self.parent)
            if dlg.exec_():
                CONFIG.reload()
                _ai_mod.AI_CLIENT = _get_ai()
                self.apply_fonts_and_styles()
                self.on_lang_changed(self.current_lang)
                # Restart timer to catch any new AI client state
                if hasattr(self, 'check_ai_busy_timer'): self.check_ai_busy_timer.start(500)

        def on_convert(self, mode="C"):
            AI_CLIENT = _get_ai()
            if not AI_CLIENT:
                QtWidgets.QMessageBox.warning(self.parent, "PseudoNote", "AI Client not initialized. Please check your settings.")
                return
            if _ai_mod.AI_BUSY: 
                return
            self.set_ai_features_enabled(False)

            ea = self.current_ea or idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return

            if mode == "ASM":
                show_ai_progress("Analyzing Function...", modal=True)
                QtWidgets.QApplication.processEvents()
                
                asm_items = list(idautils.FuncItems(func.start_ea))
                count = len(asm_items)
                
                hide_ai_progress()
                
                msg = f"Converting Assembly to {self.current_lang} requires tokens.\n\n"
                msg += f"Instructions: {count}\n\n"
                
                if count > 2500:
                    msg += "⚠️ WARNING: This function is very large (> 2,500 instructions).\n"
                    msg += "The AI may struggle with logic accuracy or require multiple continuations.\n\n"
                
                msg += "Are you sure you want to proceed?"
                
                reply = QtWidgets.QMessageBox.question(
                    self.parent, f"Confirm ASM to {self.current_lang}",
                    msg,
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No
                )
                if reply == QtWidgets.QMessageBox.No: return
            
            show_ai_progress("Preparing Code Data...", modal=True)
            QtWidgets.QApplication.processEvents()
            
            raw_code = ""
            try:
                if mode == "C":
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            raw_code = str(cfunc).strip()
                    except Exception as e:
                        LOGGER.log(f"Decompilation error: {e}")
                else:
                    items = list(idautils.FuncItems(func.start_ea))
                    total = len(items)
                    lines = []
                    for i, item_ea in enumerate(items):
                        if _ai_mod.AI_CANCEL_REQUESTED: break
                        lines.append(f"{item_ea:X}: {idc.generate_disasm_line(item_ea, 0)}")
                        if i % 50 == 0:
                            update_ai_progress_details(0, f"Gathering instructions: {i}/{total}...")
                            QtWidgets.QApplication.processEvents()
                    raw_code = "\n".join(lines)
            finally:
                # If we fail OR the AI finishes preparation, we must hide the "Preparing" dialog
                # We hide it here if raw_code is empty (early return)
                # If NOT empty, we hide it right before showing the "Generating" dialog
                if not raw_code:
                    hide_ai_progress()
                    return

            # Safety check: Truncate extremely large input that would crash the AI/Client
            if len(raw_code) > 250000: # Approx 50k-100k tokens
                LOGGER.log(f"Truncating massive input code ({len(raw_code)} chars)")
                raw_code = raw_code[:250000] + "\n\n[... CODE TRUNCATED DUE TO SIZE ...]"

            # Transition from Preparation to Generation
            hide_ai_progress()
            show_ai_progress("Generating Readable Code with Comments...")
            update_ai_progress_details(0, "Sending request to AI...")
            
            editor = self.c_code_editor if mode == "C" else self.asm_code_editor
            editor.clear()
            (self.c_status_stack if mode == "C" else self.asm_status_stack).setCurrentWidget(editor)
            
            context = {"mode": mode, "func_ea": func.start_ea, "lang": self.current_lang, "editor": editor, "full_text": ""}
            prompt = self.build_convert_prompt(mode, raw_code)

            def chunk_cb(text):
                context["full_text"] += text
                update_ai_progress_details(len(context["full_text"]))
                # Use moveCursor directly on the editor for atomic append
                editor.moveCursor(QtGui.QTextCursor.End)
                editor.insertPlainText(text)
                editor.ensureCursorVisible()

            def fin_cb(response, finish_reason="stop", **kwargs):
                self.handle_ai_response_callback(response, func.start_ea, mode, finish_reason, context)

            AI_CLIENT.query_model_async(prompt, fin_cb, on_chunk=chunk_cb, on_status=update_ai_progress_details, additional_options={"max_completion_tokens": 16384})

        def build_convert_prompt(self, mode, raw_code):
            comment_style = "#" if self.current_lang in ["Python", "Nim"] else "//"
            if mode == "C":
                return (
                    f"Analyze the following C function and rewrite it into high-level, readable {self.current_lang} code.\n"
                    "CRITICAL RULES:\n"
                    f"1. Use idiomatic {self.current_lang} control structures (if/else, loops). Do NOT use `goto` even if present in the C source.\n"
                    "2. Rename Variables/functions descriptively.\n"
                    f"3. Add concise inline comments ({comment_style} style). NO long separator lines.\n"
                    f"4. The FIRST LINE of output MUST be a comment indicating the language, e.g.: {comment_style} Converted language: {self.current_lang}. Do not add any other comments.\n"
                    "5. NO introspection, NO summary, NO markdown wrapper text.\n"
                    "6. NO #include headers or library imports.\n"
                    "7. Return ONLY the code inside a markdown code block.\n\n"
                    f"{raw_code}"
                )
            else:
                comment_prefix = "#" if self.current_lang in ["Nim", "Python"] else "//"
                idiom_instruction = ""
                if self.current_lang == "Rust": idiom_instruction = "Use idiomatic Rust (match expressions, Option/Result, slice patterns)."
                elif self.current_lang == "Go": idiom_instruction = "Use idiomatic Go (multiple return values, defer, `for` loops only)."
                elif self.current_lang == "Delphi": idiom_instruction = "Use Object Pascal syntax (begin/end blocks, `:=` assignment, PascalCase)."
                elif self.current_lang == "Nim": idiom_instruction = "Use Nim syntax (indentation-based, `proc`, `let`/`var`, `result` variable)."
                elif self.current_lang == "Python": idiom_instruction = "Use idiomatic Python (snake_case, list comprehensions, indentation-based)."
                elif self.current_lang == "C#": idiom_instruction = "Use idiomatic C# (PascalCase methods, LINQ, strong typing)."
                return (
                    f"Analyze the following Assembly Code and reverse-engineer it into high-level, readable {self.current_lang} code.\n"
                    "CRITICAL RULES:\n"
                    "1. ABSTRACT AWAY LOW-LEVEL DETAILS: Completely IGNORE function prologue/epilogue (push ebp, mov esp...), stack cookies/canaries, and direct register saving/restoring. Focus purely on the logic.\n"
                    f"2. RECONSTRUCT CONTROL FLOW: Convert assembly jumps and labels into proper native {self.current_lang} control structures (`if`, `loops`). Do NOT use `goto`.\n"
                    f"3. INFER TYPES: Use standard {self.current_lang} types based on context. {idiom_instruction} Do NOT use `DWORD`, `QWORD`, or register names (`rax`,`rbx`,`rcx`, `rdx`, `rdi`, `rsi`, `rbp`, `rsp`) in the output.\n"
                    f"4. The FIRST LINE of output MUST be a comment indicating the language, e.g.: {comment_prefix} Converted language: {self.current_lang}\n"
                    "5. Rename local variables descriptively (e.g., `counter`, `buffer`) instead of `var_4`, `arg_0`.\n"
                    "6. Output the FULL code. Do not stop halfway.\n"
                    "7. NO introspection, NO summary. Return ONLY the code inside a markdown code block.\n\n"
                    f"{raw_code}"
                )

        def handle_ai_response_callback(self, response, func_ea, mode="C", finish_reason="stop", context=None, **kwargs):
            try:
                if not response: 
                    return
                if finish_reason == "length" and not _ai_mod.AI_CANCEL_REQUESTED:
                    # Continue logic
                    show_ai_progress(f"Continuing {mode} (Part {len(response)//8000 + 1})...", modal=True)
                    # Improve continuation prompt to avoid repetition and ensure logical flow
                    last_chars = response[-800:].strip()
                    prompt = (
                        f"This is a continuation of the previous reverse-engineering task into {self.current_lang}. "
                        f"The last part of the code you generated was:\n\n```\n{last_chars}\n```\n\n"
                        "Please CONTINUE the code from exactly that point. "
                        "Do NOT repeat the code above. Do NOT add new headers or explanations. "
                        "Return ONLY the remaining code inside a markdown code block."
                    )
                    AI = _get_ai()
                    
                    def c_chunk(t):
                        context["full_text"] += t
                        update_ai_progress_details(len(context["full_text"]))
                        context["editor"].moveCursor(QtGui.QTextCursor.End)
                        context["editor"].insertPlainText(t)
                        context["editor"].ensureCursorVisible()
                    
                    prev_resp = response
                    def c_fin(response, finish_reason="stop", **kwargs): 
                        full_resp = prev_resp + (response or "")
                        self.handle_ai_response_callback(full_resp, func_ea, mode, finish_reason, context)
                    AI.query_model_async(prompt, c_fin, on_chunk=c_chunk, on_status=update_ai_progress_details, additional_options={"max_completion_tokens": 16384})
                    return

                code = response.strip()
                if "```" in code:
                    parts = code.split("```")
                    code_parts = []
                    # Robust extraction: items at odd indices are inside code blocks
                    for i in range(1, len(parts), 2):
                        p = parts[i].strip()
                        if p:
                            lines = p.split('\n')
                            if lines:
                                first = lines[0].strip().lower()
                                # Common language identifiers to skip on the first line of a block
                                if first in ["python", "c", "cpp", "rust", "go", "nim", "asm", "javascript", "typescript", "csharp", "delphi", "pascal", "objectivec", "swift"]:
                                    p = "\n".join(lines[1:]).strip()
                            if p:
                                code_parts.append(p)
                    
                    if code_parts:
                        code = "\n".join(code_parts)
                    elif len(parts) >= 2:
                        # Fallback for malformed blocks (e.g. only one ``` at start)
                        code = parts[1].strip()
                
                # If cleanup resulted in MUCH smaller code than the raw response, something is wrong
                # We should prefer keeping the raw response over an empty/tiny cleaned version
                if len(code) < 10 and len(response.strip()) > 50:
                    code = response.strip()
                
                tag = 0 if mode == "C" else 81
                save_to_idb(func_ea, code.strip(), tag=tag)
                if func_ea == self.last_func_ea:
                    if mode == "C": self.last_saved_c_code = code.strip()
                    else: self.last_saved_asm_code = code.strip()
                    if context and "editor" in context:
                        # Clean up editor content only if it differs from the raw stream (markdown symbols removal)
                        if context["editor"].toPlainText().strip() != code.strip():
                            # Save scroll position if possible, but setPlainText usually resets it
                            context["editor"].setPlainText(code.strip())
                    self.update_save_btn_state(self.code_save_btn, saved=True)
            except Exception as e: LOGGER.log(f"AI Response Callback Error: {e}")
            finally: hide_ai_progress()

        def on_explain_func(self, context="code"):
            AI_CLIENT = _get_ai()
            if not AI_CLIENT or _ai_mod.AI_BUSY: return
            ea = self.current_ea or idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return
            
            decompiled = ""
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc: decompiled = str(cfunc)
            except: pass

            if not decompiled:
                # Fallback to disassembly if no pseudocode
                items = list(idautils.FuncItems(func.start_ea))
                decompiled = "\n".join([f"{item_ea:X}: {idc.generate_disasm_line(item_ea, 0)}" for item_ea in items[:500]])
            
            if not decompiled: return

            show_ai_progress(f"Explaining {context}...")
            update_ai_progress_details(0, "Gathering context...")
            
            func_ctx = gather_function_context(func.start_ea)
            context_text = format_context_for_prompt(func_ctx)
            display_text = format_context_for_display(func_ctx)

            update_ai_progress_details(0, "Sending request...")
            
            base_prompt = (
                f"Analyze the following function logic {'specifically for malware behavior' if context == 'malware' else ''}.\n\n"
                f"## Source Code\n```c\n{decompiled}\n```\n\n"
            )
            if context_text:
                base_prompt += f"{context_text}\n\n"

            if context == "malware":
                prompt = base_prompt + (
                    "Return the output in Markdown format with the following structure:\n\n"
                    "## Summary\nA brief paragraph describing what the code is doing overall. "
                    "If the function appears BENIGN, clearly and strictly state that.\n\n"
                    "## Detailed Explanation\nProvide a numbered or bullet-point explanation of the logic and behavior.\n\n"
                    "Incorporate information from callers/callees/strings if they reveal malicious intent."
                )
            else:
                prompt = base_prompt + (
                    "Return the output in Markdown format using the structure below:\n\n"
                    "## Summary\nProvide a brief paragraph describing what the code is doing overall.\n\n"
                    "## Detailed Explanation\nProvide a numbered or bullet-point explanation of the function logic.\n\n"
                    "Use the provided context (callers, callees, strings) to better understand the function purpose."
                )
            
            total_chars = [0]
            def chunk_cb(t):
                total_chars[0] += len(t)
                update_ai_progress_details(total_chars[0])

            AI_CLIENT.query_model_async(
                prompt, 
                functools.partial(self.handle_explain_response_callback, func_ea=func.start_ea), 
                on_chunk=chunk_cb, 
                on_status=update_ai_progress_details
            )

        def handle_explain_response_callback(self, response, func_ea, **kwargs):
            try:
                if func_ea == self.last_func_ea and response:
                    full_content = response.strip()
                    self.explanation_viewer.setMarkdown(full_content)
                    save_to_idb(func_ea, full_content, tag=79)
            finally: hide_ai_progress()



        def on_suggest_name(self):
            AI_CLIENT = _get_ai()
            ea = self.current_ea
            if not ea or ea == idaapi.BADADDR: ea = idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                QtWidgets.QMessageBox.warning(self.parent, "PseudoNote", "No function found."); return
            decompiled = ""
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc: decompiled = str(cfunc)
            except: pass
            if not decompiled:
                QtWidgets.QMessageBox.warning(self.parent, "PseudoNote", "No pseudocode available to suggest names (Hex-Rays Decompiler required)."); return
            
            show_ai_progress("Analyzing Function Details...")
            update_ai_progress_details(0, "Gathering context...")
            
            context = gather_function_context(func.start_ea)
            if decompiled:
                found_literals = re.findall(r'"((?:[^"\\]|\\.)*)"', decompiled)
                for s in found_literals:
                    try: s_clean = s.encode('utf-8').decode('unicode_escape')
                    except: s_clean = s
                    if s_clean and s_clean not in context["strings"]:
                        context["strings"].append(s_clean)
            context_text = format_context_for_prompt(context)
            display_text = format_context_for_display(context)
            
            prompt = (
                "Analyze the following C function together with its surrounding context "
                "(callers, callees, and string references).\n\n"
                "## Pseudocode\n"
                f"```c\n{decompiled}\n```\n\n"
            )
            if context_text: prompt += f"{context_text}\n\n"
            prompt += (
                "Based on ALL the above information (pseudocode, callers, callees, and strings), provide:\n"
                "- 3 best and accurate function names based strictly on the code.\n"
                "- 3 descriptive function names based on its behavior.\n"
                "- A short explanation of what the return value represents.\n"
                "- Analyze the function arguments/parameters (Name, Type, Purpose).\n"
                "- Identify subfunctions or called functions or APIs call or callback functions that are interesting for further analysis.\n"
                "- Identify global variables modified or read (Side Effects).\n"
                "- Identify key local variables (especially large buffers or state variables).\n\n"
                "Return the output in Markdown format using this structure:\n\n"
                "## Accurate Function Names\n1. Name\n2. Name\n3. Name\n\n"
                "## Descriptive Function Names\n1. Name\n2. Name\n3. Name\n\n"
                "## Arguments\n- ArgName (Type): Description of usage\n\n"
                "## Interesting Calls\n- FunctionName – short reason\n\n"
                "## Interesting APIs functions \n- API FunctionName – short reason\n\n"
                "## String References\n- \"string content\" - purpose/usage\n\n"
                "## Return Value\n- Brief explanation.\n\n"
                "## Key Global Variables\n- `g_VarName`: Read/Written - purpose\n\n"
                "## Key Local Variables\n- `vX` (Type/Size): Purpose (e.g. buffer, index, etc.)\n\n"
                "Do not include extra commentary outside these sections."
            )
            ctx_summary = (f"{len(context['callers'])} callers, "
                          f"{len(context['callees_api']) + len(context['callees_internal'])} callees, "
                          f"{len(context['strings'])} strings")
            LOGGER.log(f"Starting function details for {hex(func.start_ea)} (deep context: {ctx_summary})...")
            
            update_ai_progress_details(0, "Sending request...")
            total_chars = [0]
            def chunk_cb(t):
                total_chars[0] += len(t)
                update_ai_progress_details(total_chars[0])

            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_suggest_name_callback, func_ea=func.start_ea, context_text=display_text),
                on_chunk=chunk_cb,
                on_status=update_ai_progress_details,
                additional_options={"max_completion_tokens": 16384}
            )

        def handle_suggest_name_callback(self, response, func_ea, context_text="", **kwargs):
            try:
                if func_ea == self.last_func_ea and response:
                    full_content = response.strip()
                    if context_text:
                        full_content = context_text + "\n\n---\n\n" + full_content
                    self.suggestion_viewer.setMarkdown(full_content)
                    save_to_idb(func_ea, full_content, tag=80)
            finally: hide_ai_progress()

        def on_get_gflow(self):
            AI_CLIENT = _get_ai()
            if not AI_CLIENT or _ai_mod.AI_BUSY: return
            ea = self.current_ea or idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return
            
            show_ai_progress("Preparing Context for GFlow...")
            QtWidgets.QApplication.processEvents()
            
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                raw = str(cfunc) if cfunc else ""
            except: raw = ""
            if not raw: 
                hide_ai_progress()
                return

            # Transition from Preparation to Generation
            hide_ai_progress()
            show_ai_progress("Generating Text Flow Graph...")
            update_ai_progress_details(0, "Sending request...")
            
            prompt = (
                "Provide a structured, readable, high-level logical execution map for the following C function.\n"
                "Focus strictly on semantic stages and major decision points.\n"
                "Do NOT replicate low-level branch instructions, labels, or variable-level mechanics.\n\n"
                "FORMAT REQUIREMENTS (STRICT):\n"
                "1. The entire response MUST be enclosed inside a single Markdown code block using triple backticks.\n"
                "2. Do NOT include any text, titles, explanations, or commentary outside the code block.\n"
                "3. Do NOT include additional Markdown headers (no ## sections).\n"
                "4. Use clear indentation and branching symbols (e.g., ├─, └─, →).\n"
                "5. Keep the structure clean, readable, and logically staged.\n\n"
                "The output must represent logical flow only.\n\n"
                f"{raw}"
            )
            total_chars = [0]
            def chunk_cb(t):
                total_chars[0] += len(t)
                update_ai_progress_details(total_chars[0])

            AI_CLIENT.query_model_async(prompt, functools.partial(self.handle_gflow_response_callback, func_ea=func.start_ea), on_chunk=chunk_cb, on_status=update_ai_progress_details)

        def handle_gflow_response_callback(self, response, func_ea, **kwargs):
            try:
                if func_ea == self.last_func_ea and response:
                    self.gflow_viewer.setMarkdown(response.strip())
                    save_to_idb(func_ea, response.strip(), tag=82)
            finally: hide_ai_progress()

        def on_get_comments_ai(self):
            AI_CLIENT = _get_ai()
            if not AI_CLIENT or _ai_mod.AI_BUSY: return
            self.set_ai_features_enabled(False)
            ea = self.current_ea or idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return
            
            show_ai_progress("Preparing Code for Comments Analysis...", modal=True)
            QtWidgets.QApplication.processEvents()
            
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                raw = str(cfunc) if cfunc else ""
            except: raw = ""
            if not raw: 
                hide_ai_progress()
                return

            # Transition from Preparation to Generation
            hide_ai_progress()
            show_ai_progress("Generating Readable Code with Comments...")
            update_ai_progress_details(0, "Sending request...")
            
            self.comments_ai_editor.clear()
            self.comments_ai_stack.setCurrentWidget(self.comments_ai_editor)
            
            prompt = (
                "You are an expert reverse engineer.\n\n"
                "Rewrite the following C function exactly as-is (same logic, names, and structure), "
                "but add concise comments ONLY at major logical blocks.\n\n"
                f"{raw}\n\n"
                "Rules:\n"
                "- Do NOT comment every line.\n"
                "- Add comments only above major blocks.\n"
                "- Do NOT modify code.\n"
                "- Return ONLY the C code inside ```c markdown block."
            )
            
            context = {"full_text": "", "editor": self.comments_ai_editor}
            def chunk_cb(text):
                context["full_text"] += text
                update_ai_progress_details(len(context["full_text"]))
                self.comments_ai_editor.moveCursor(QtGui.QTextCursor.End)
                self.comments_ai_editor.insertPlainText(text)
                self.comments_ai_editor.ensureCursorVisible()

            def fin_cb(response, finish_reason="stop", **kwargs):
                self.handle_get_comments_callback(response, func.start_ea, context, finish_reason=finish_reason)

            AI_CLIENT.query_model_async(prompt, fin_cb, on_chunk=chunk_cb, on_status=update_ai_progress_details, additional_options={"max_completion_tokens": 16384})

        def handle_get_comments_callback(self, response, func_ea, context, finish_reason="stop", **kwargs):
            try:
                if not response: 
                    hide_ai_progress()
                    return
                
                if finish_reason == "length" and not _ai_mod.AI_CANCEL_REQUESTED:
                    show_ai_progress(f"Continuing Comments (Part {len(response)//8000 + 1})...", modal=True)
                    last_chars = response[-800:].strip()
                    prompt = (
                        f"This is a continuation of adding comments to C code. "
                        f"The last part you generated was:\n\n```\n{last_chars}\n```\n\n"
                        "Please CONTINUE the code and comments from exactly that point. "
                        "Do NOT repeat the code above. Return ONLY the remaining code inside a markdown code block."
                    )
                    AI = _get_ai()
                    
                    def c_chunk(t):
                        context["full_text"] += t
                        update_ai_progress_details(len(context["full_text"]))
                        context["editor"].moveCursor(QtGui.QTextCursor.End)
                        context["editor"].insertPlainText(t)
                        context["editor"].ensureCursorVisible()
                    
                    prev_resp = response
                    def c_fin(response, finish_reason="stop", **kwargs):
                        full_resp = prev_resp + (response or "")
                        self.handle_get_comments_callback(full_resp, func_ea, context, finish_reason)
                    AI.query_model_async(prompt, c_fin, on_chunk=c_chunk, on_status=update_ai_progress_details, additional_options={"max_completion_tokens": 16384})
                    return

                code = response.strip()
                if "```" in code:
                    parts = code.split("```")
                    code_parts = []
                    for i in range(1, len(parts), 2):
                        p = parts[i].strip()
                        if p:
                            lines = p.split('\n')
                            if lines:
                                first = lines[0].strip().lower()
                                if first in ["python", "c", "cpp", "rust", "go", "nim", "asm", "javascript", "typescript", "csharp", "delphi", "pascal"]:
                                    p = "\n".join(lines[1:]).strip()
                            if p:
                                code_parts.append(p)
                    
                    if code_parts:
                        code = "\n".join(code_parts)
                    elif len(parts) >= 2:
                        code = parts[1].strip()
                
                if len(code) < 10 and len(response.strip()) > 50:
                    code = response.strip()
                
                save_to_idb(func_ea, code.strip(), tag=83)
                if func_ea == self.last_func_ea:
                    self.comments_ai_editor.setPlainText(code.strip())
                    self.update_save_btn_state(self.code_save_btn, saved=True)
            finally: hide_ai_progress()

        def show_ai_progress(self, status):
            show_ai_progress(status)

        def update_ai_progress_details(self, tokens):
            update_ai_progress_details(tokens)

        def refresh_ui(self, force=False):
            if not QtWidgets: return
            try: ea = idaapi.get_screen_ea()
            except: ea = idaapi.BADADDR
            if ea == idaapi.BADADDR: return
            func = idaapi.get_func(ea)
            if not func:
                self.current_ea = None
                if self.title_label: self.title_label.setText("No Function Selected")
                if self.c_status_label:
                    self.c_status_label.setText(START_TEXT)
                    if self.c_status_stack: self.c_status_stack.setCurrentWidget(self.c_status_stack.widget(0))
                if self.c_convert_btn: self.c_convert_btn.setEnabled(False)
                if self.asm_status_label:
                    self.asm_status_label.setText(START_TEXT)
                    if self.asm_status_stack: self.asm_status_stack.setCurrentWidget(self.asm_status_stack.widget(0))
                if self.asm_convert_btn: self.asm_convert_btn.setEnabled(False)
                if self.comments_ai_status_label:
                    self.comments_ai_status_label.setText(START_TEXT)
                    if self.comments_ai_stack: self.comments_ai_stack.setCurrentIndex(0)
                return
            
            self.current_ea = ea
            func_ea = func.start_ea
            if not force and self.last_func_ea == func_ea: return
            self.last_func_ea = func_ea
            name = idc.get_func_name(func_ea)
            accent = "#569CD6"
            if self.title_label: self.title_label.setText(f'Readable code: <span style="color: {accent};">{name}</span>')
            if getattr(self, "func_name_label", None):
                self.func_name_label.setText(f'Analyst notes: <span style="color: {accent};">{name}</span>')
            try: self.SetTitle(f"PseudoNote: {name}")
            except:
                if self.parent: self.parent.setWindowTitle(f"PseudoNote: {name}")
            
            if self.c_code_editor: self.c_code_editor.setReadOnly(True)
            if self.asm_code_editor: self.asm_code_editor.setReadOnly(True)
            if self.manual_edit_btn:
                self.manual_edit_btn.setText("Edit")
                self.manual_edit_btn.setEnabled(True)
                self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))

            code_c = load_from_idb(func_ea, tag=0)
            if self.c_code_editor:
                self.c_code_editor.blockSignals(True)
                if code_c:
                    self.last_saved_c_code = code_c
                    if self.c_convert_btn: self.c_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
                    self.c_code_editor.setPlainText(code_c)
                    if self.c_status_stack: self.c_status_stack.setCurrentWidget(self.c_code_editor)
                    if self.code_tab_widget: self.code_tab_widget.setTabText(1, "Pseudocode converted")
                else:
                    self.last_saved_c_code = ""
                    if self.c_convert_btn: self.c_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
                    self.c_code_editor.setPlainText("")
                    if self.c_status_stack: self.c_status_stack.setCurrentWidget(self.c_status_stack.widget(0))
                    if self.c_status_label: self.c_status_label.setText(START_TEXT)
                    if self.code_tab_widget: self.code_tab_widget.setTabText(1, "Pseudocode")
                self.c_code_editor.blockSignals(False)

            code_asm = load_from_idb(func_ea, tag=81)
            if self.asm_code_editor:
                self.asm_code_editor.blockSignals(True)
                if code_asm:
                    self.last_saved_asm_code = code_asm
                    if self.asm_convert_btn: self.asm_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
                    self.asm_code_editor.setPlainText(code_asm)
                    if self.asm_status_stack: self.asm_status_stack.setCurrentWidget(self.asm_code_editor)
                    if self.code_tab_widget: self.code_tab_widget.setTabText(0, "IDA-View converted")
                else:
                    self.last_saved_asm_code = ""
                    if self.asm_convert_btn: self.asm_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
                    self.asm_code_editor.setPlainText("")
                    if self.asm_status_stack: self.asm_status_stack.setCurrentWidget(self.asm_status_stack.widget(0))
                    if self.asm_status_label: self.asm_status_label.setText(START_TEXT)
                    if self.code_tab_widget: self.code_tab_widget.setTabText(0, "IDA-View")
                self.asm_code_editor.blockSignals(False)

            self.on_code_text_changed()
            if self.code_tab_widget: self.on_code_tab_changed(self.code_tab_widget.currentIndex())
            if self.c_convert_btn: self.c_convert_btn.setEnabled(True)
            if self.asm_convert_btn: self.asm_convert_btn.setEnabled(True)

            note = load_from_idb(func_ea, tag=78)
            if self.note_editor:
                self.last_saved_note = note if note else ""
                self.note_editor.blockSignals(True)
                self.note_editor.setPlainText(self.last_saved_note)
                self.note_editor.blockSignals(False)
                if self.note_save_btn: self.update_save_btn_state(self.note_save_btn, saved=True)
                self.toggle_note_mode(edit=False)
                if not self.last_saved_note and self.note_viewer:
                    self.note_viewer.setText("")

            explanation = load_from_idb(func_ea, tag=79)
            if self.explanation_viewer:
                if explanation: self.explanation_viewer.setMarkdown(explanation)
                else:
                    self.explanation_viewer.setPlaceholderText("Click 'Explain (AI)' to generate an explanation for the current function.")
                    self.explanation_viewer.setText("")

            gflow = load_from_idb(func_ea, tag=82)
            if self.gflow_viewer:
                if gflow: self.gflow_viewer.setMarkdown(gflow)
                else:
                    self.gflow_viewer.setPlaceholderText("Click 'Get graph' to generate a text flow graph.")
                    self.gflow_viewer.setText("")

            suggestions = load_from_idb(func_ea, tag=80)
            if self.suggestion_viewer:
                if suggestions: self.suggestion_viewer.setMarkdown(suggestions)
                else:
                    self.suggestion_viewer.setPlaceholderText("Click 'Function Details (AI)' to generate details.")
                    self.suggestion_viewer.setText("")

            comments = load_from_idb(func_ea, tag=83)
            if self.comments_ai_editor:
                if comments:
                    code = comments.strip()
                    if "```" in code:
                        matches = re.findall(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL)
                        if matches: code = matches[0]
                        else:
                            parts = code.split("```")
                            if len(parts) >= 3: code = parts[1]
                    self.comments_ai_editor.setPlainText(code.strip())
                    if self.comments_ai_stack: self.comments_ai_stack.setCurrentIndex(1)
                else:
                    if self.comments_ai_status_label: self.comments_ai_status_label.setText(START_TEXT)
                    if self.comments_ai_stack: self.comments_ai_stack.setCurrentIndex(0)
                    self.comments_ai_editor.setPlainText("")

        def OnClose(self, form):
            global _view_instance
            if hasattr(self, 'check_ai_busy_timer') and self.check_ai_busy_timer:
                self.check_ai_busy_timer.stop()
            if self.hooks: self.hooks.unhook()
            _view_instance = None


class ScreenHooks(idaapi.UI_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view
    def screen_ea_changed(self, ea, prev_ea):
        if self.view:
            self.view.refresh_ui()


def show_view():
    """Helper to show the view, primarily for manual invocation."""
    if plugin_instance:
        plugin_instance.open_view()



class PseudoNoteHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        if plugin_instance:
            plugin_instance.open_view()
        else:
            print("PseudoNote plugin instance not found.")
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = idaapi.get_widget_type(widget)
        if wtype not in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASMS]:
            return

        idaapi.attach_action_to_popup(widget, popup, "pseudonote:action", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:list", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:settings", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_variables", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_function", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_function_malware", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:ask_chat", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:deep_summarizer", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:bulk_rename", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:bulk_var_rename", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:bulk_analyze", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
        idaapi.attach_action_to_popup(widget, popup, "pseudonote:suggest_function_signature", "PseudoNote/")

        if wtype == idaapi.BWN_PSEUDOCODE:
            # Pseudocode-specific actions
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:analyze_struct", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:add_comments", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:delete_comments", "PseudoNote/")
        elif wtype in [idaapi.BWN_DISASM, idaapi.BWN_DISASMS]:
            # IDA View (disassembly) specific actions
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:add_asm_comments", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:delete_asm_comments", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:shellcode_analyst", "PseudoNote/")

        idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
        if wtype == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:highlight_on", "PseudoNote/Call Highlight/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:highlight_off", "PseudoNote/Call Highlight/")
        elif wtype in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:disasm_highlight_on", "PseudoNote/Call Highlight/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:disasm_highlight_off", "PseudoNote/Call Highlight/")


class ShellcodeAnalystDialog(QtWidgets.QDialog):
    """A standalone dialog for manual shellcode analysis (Static analysis context)."""
    def __init__(self, hex_data="", asm_data="", parent=None):
        super().__init__(parent or QtWidgets.QApplication.activeWindow())
        self.setWindowTitle("PseudoNote Shellcode Analysis (Static)")
        self.resize(1100, 800)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowMaximizeButtonHint)
        self.setStyleSheet("""
            QDialog {
                font-family: 'Inter', 'Segoe UI', sans-serif;
            }
            QLabel {
                font-family: 'Inter', 'Segoe UI', sans-serif;
            }
            QPushButton {
                font-family: 'Inter', 'Segoe UI', sans-serif;
            }
            QComboBox {
                font-family: 'Inter', 'Segoe UI', sans-serif;
            }
        """)
        
        main_layout = QtWidgets.QVBoxLayout(self)
        
        # Splitter for Input/Output
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        # Top part: Input and Controls
        top_widget = QtWidgets.QWidget()
        top_layout = QtWidgets.QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # Label & Header
        header_layout = QtWidgets.QHBoxLayout()
        header_layout.addWidget(QtWidgets.QLabel("<b>Input: Paste Hex Bytes or Assembly Instructions</b>"))
        header_layout.addStretch()
        
        header_layout.addWidget(QtWidgets.QLabel("Architecture:"))
        self.arch_combo = QtWidgets.QComboBox()
        self.arch_combo.addItems(["Auto-Detect", "x86 (32-bit)", "x64 (64-bit)", "ARM (32-bit)", "ARM64 (64-bit)", "MIPS", "PowerPC"])
        # Attempt to set default based on current IDB
        if idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF:
            self.arch_combo.setCurrentText("x64 (64-bit)")
        else:
            self.arch_combo.setCurrentText("x86 (32-bit)")
        header_layout.addWidget(self.arch_combo)
        
        self.analyze_btn = QtWidgets.QPushButton("Analyze Shellcode")
        self.analyze_btn.setMinimumHeight(35)
        self.analyze_btn.setStyleSheet("background-color: #007AFF; color: white; font-weight: bold; border-radius: 4px; padding: 5px;")
        self.analyze_btn.clicked.connect(self.on_analyze)
        header_layout.addWidget(self.analyze_btn)
        
        top_layout.addLayout(header_layout)
        
        # Input Editor
        self.input_edit = QtWidgets.QPlainTextEdit()
        self.input_edit.setPlaceholderText("Example: 55 89 E5 ... or push ebp; mov ebp, esp; ...")
        # Prefer ASM data if available, else hex
        if asm_data:
            self.input_edit.setPlainText(asm_data)
        elif hex_data:
            self.input_edit.setPlainText(hex_data)
        
        self.input_edit.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
                font-size: 12pt;
                border: 1px solid #333;
                border-radius: 4px;
            }
        """)
        top_layout.addWidget(self.input_edit)
        
        splitter.addWidget(top_widget)
        
        # Bottom part: Result Viewer
        bottom_widget = QtWidgets.QWidget()
        bottom_layout = QtWidgets.QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        bottom_layout.addWidget(QtWidgets.QLabel("<b>Analysis Report:</b>"))
        self.result_viewer = QtWidgets.QTextBrowser()
        self.result_viewer.setOpenExternalLinks(True)
        self.result_viewer.setStyleSheet("""
            QTextBrowser {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Inter', 'Segoe UI', Tahoma, sans-serif;
                font-size: 11pt;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        bottom_layout.addWidget(self.result_viewer)
        
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(2)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        bottom_layout.addWidget(self.progress_bar)
        
        splitter.addWidget(bottom_widget)
        splitter.setSizes([300, 700])
        main_layout.addWidget(splitter)

    def on_analyze(self):
        input_content = self.input_edit.toPlainText().strip()
        if not input_content:
            return
        
        arch = self.arch_combo.currentText()
        AI_CLIENT = _get_ai()
        if not AI_CLIENT:
            idaapi.info("AI Client not initialized."); return
        
        self.analyze_btn.setEnabled(False)
        self.progress_bar.show()
        self.result_viewer.clear()
        self.result_viewer.setPlaceholderText("AI is processing static analysis... please wait.")
        
        prompt = (
        f"You are an expert shellcode reverse engineer. Target architecture: {arch}.\n\n"

        "ANALYSIS PRIORITY (STRICT ORDER):\n"
        "1) Execution structure\n"
        "2) Decoder/transform logic\n"
        "3) Capability evidence\n"
        "4) Intent inference (ONLY if supported by evidence)\n\n"

        f"INPUT:\n```\n{input_content}\n```\n\n"

        "NORMALIZATION:\n"
        "- Hex bytes → convert to assembly internally. Do NOT print disassembly.\n"
        "- Assume code may be incomplete or one stage of a multi-stage chain.\n\n"

        "ANTI-HALLUCINATION:\n"
        "- Do NOT guess APIs, networking, persistence, or OS unless directly evidenced.\n"
        "- If uncertain → 'insufficient evidence'.\n"
        "- Flag every assumption with [ASSUMED].\n\n"

        "OUTPUT FORMAT:\n"
        "## [Label]\n"
        "[1-2 sentence observation]\n"
        "- [Important explaination 1]\n"
        "- [Important explaination 2]\n"
        "- [Continue important explainations]\n"
        "Skip sections with no evidence. No filler. No repetition.\n\n"

        "FINDINGS TO COVER:\n"
        "## Summary\n"
        "## Decoder / Encoding Layer\n"
        "## PEB Walking / API Resolving\n"
        "## API Calls\n"
        "## Capability / Behavior\n"
        "## Suspicious Constants\n"
        "## Extractable IOCs\n"
        "## Confidence\n"
        "Confidence → [score]/100 — one sentence justification.\n"
        "## Unknowns & Gaps\n"
        "## Other important findings\n"
        "## Conclusion\n"
        "Conclusion → 2-3 sentences: what it is, what it does, what analyst should do next.\n"
        "## Readable Pseudocode\n"
        "Pseudocode → Full readable C-style code, unlimited lines, inline comments on every section\n"
        )
        
        self.current_response = ""
        
        def chunk_cb(t):
            self.current_response += t
            # Periodically set markdown might be slow, so append or only set at end
            # For UX, we append to plain text and show
            self.result_viewer.moveCursor(QtGui.QTextCursor.End)
            self.result_viewer.insertPlainText(t)
            self.result_viewer.ensureCursorVisible()

        def fin_cb(response, **kwargs):
            self.progress_bar.hide()
            self.analyze_btn.setEnabled(True)
            if response:
                self.result_viewer.setMarkdown(response.strip())
            else:
                self.result_viewer.setPlainText("Error: No response from AI.")

        AI_CLIENT.query_model_async(prompt, fin_cb, on_chunk=chunk_cb)

