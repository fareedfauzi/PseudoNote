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

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui, get_text_width, set_tab_stop_width
from pseudonote.config import CONFIG, LOGGER
from pseudonote.syntax import MultiHighlighter
from pseudonote.editors import CodeEditor, MarkdownEditor
from pseudonote.idb_storage import (
    get_netnode, save_to_idb, load_from_idb,
    gather_function_context, format_context_for_prompt, format_context_for_display,
)
import pseudonote.ai_client as _ai_mod

def _get_ai():
    return _ai_mod.AI_CLIENT

_view_instance = None
START_TEXT = "Select a function to convert"
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
    class SettingsDialog(QtWidgets.QDialog):
        def __init__(self, config, parent=None):
            super().__init__(parent)
            self.config = config
            self.setWindowTitle("PseudoNote Settings")
            self.resize(500, 400)
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
            main_layout = QtWidgets.QVBoxLayout()
            self.tabs = QtWidgets.QTabWidget()
            self.provider_tab = QtWidgets.QWidget()
            self.init_provider_tab()
            self.tabs.addTab(self.provider_tab, "AI Providers")
            self.appearance_tab = QtWidgets.QWidget()
            self.init_appearance_tab()
            self.tabs.addTab(self.appearance_tab, "Appearance")
            self.log_tab = QtWidgets.QWidget()
            self.init_log_tab()
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
            layout.addStretch()
            self.provider_tab.setLayout(layout)
            self.load_fields(self.current_provider)

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
                else: font_combo.setCurrentText("Segoe UI" if key=="ui" else "Consolas")
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

        def on_provider_changed(self, text):
            self.save_fields_to_temp(self.current_provider)
            self.current_provider = text
            self.load_fields(text)

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
            fw = self.font_widgets
            c.ui_font = fw["ui"][0].currentText(); c.ui_font_size = fw["ui"][1].value()
            c.code_font = fw["code"][0].currentText(); c.code_font_size = fw["code"][1].value()
            c.markdown_font = fw["md"][0].currentText(); c.markdown_font_size = fw["md"][1].value()
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
            self.last_saved_c_code = ""
            self.last_saved_asm_code = ""
            self.note_tab_widget = None
            self.note_stack = None
            self.note_viewer = None
            self.note_editor = None
            self.explanation_viewer = None
            self.note_save_btn = None
            self.note_edit_btn = None
            self.note_save_btn = None
            self.note_edit_btn = None
            self.explain_code_btn = None
            self.explain_malware_btn = None
            self.suggest_name_btn = None
            self.explain_malware_btn = None
            self.suggest_name_btn = None
            self.gflow_btn = None
            self.last_saved_note = ""
            self.title_label = None
            self.highlighter = None
            self.lang_combo = None
            self.current_lang = "C"

        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            self.init_ui()
            self.hooks = ScreenHooks(self)
            self.hooks.hook()
            AI = _get_ai()
            if AI: AI.log_provider_info()
            self.refresh_ui(force=True)

        def init_ui(self):
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

            self.settings_btn = QtWidgets.QPushButton("⚙")
            self.settings_btn.setFixedSize(24, 24)
            self.settings_btn.setToolTip("Configure AI Provider")
            self.settings_btn.clicked.connect(self.on_settings)
            self.settings_btn.setStyleSheet("QPushButton { border: none; color: #CCCCCC; background: transparent; font-size: 16px; } QPushButton:hover { color: #FFFFFF; background-color: #3E3E42; border-radius: 3px; }")
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
            self.comments_ai_status_label.setStyleSheet("color: #888888; font-size: 14px; font-style: italic; background-color: transparent;")
            cm_sp_layout.addWidget(self.comments_ai_status_label)
            cm_status_page.setLayout(cm_sp_layout)
            self.comments_ai_stack.addWidget(cm_status_page)

            self.comments_ai_editor = self.create_editor(code=True)
            self.comments_ai_highlighter = MultiHighlighter(self.comments_ai_editor.document())
            self.comments_ai_highlighter.update_rules("C")
            self.comments_ai_stack.addWidget(self.comments_ai_editor)

            cm_widget = QtWidgets.QWidget()
            cm_widget.setStyleSheet("background-color: #1E1E1E;")
            cm_layout = QtWidgets.QVBoxLayout()
            cm_layout.setContentsMargins(0, 5, 0, 0)
            cm_layout.addWidget(self.comments_ai_stack)
            cm_widget.setLayout(cm_layout)
            self.code_tab_widget.addTab(cm_widget, "Code Comments")

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
            self.note_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.note_viewer.setPlaceholderText("Click 'Edit' button to add notes.")
            self.note_stack.addWidget(self.note_viewer)
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
            self.note_previewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border-left: 1px solid #3E3E42; padding: 10px; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }")
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
            self.explanation_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }")
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
            self.gflow_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }")
            self.gflow_viewer.setPlaceholderText("Click 'Get graph' to generate a text flow graph.")
            gf_widget = QtWidgets.QWidget()
            gf_layout = QtWidgets.QVBoxLayout()
            gf_layout.setContentsMargins(0, 5, 0, 0)
            gf_layout.addWidget(self.gflow_viewer)
            gf_widget.setLayout(gf_layout)
            self.note_tab_widget.addTab(gf_widget, "Function Graph (AI)")

            # Function Details tab
            self.suggestion_viewer = QtWidgets.QTextBrowser()
            self.suggestion_viewer.setOpenExternalLinks(True)
            self.suggestion_viewer.setStyleSheet("QTextBrowser { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }")
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
             page.setStyleSheet("background-color: #1E1E1E;")
             layout = QtWidgets.QVBoxLayout()
             layout.setContentsMargins(0, 5, 0, 0)
             stack = QtWidgets.QStackedWidget()
             status_page = QtWidgets.QWidget()
             status_page.setStyleSheet("background-color: #1E1E1E;")
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
                    QPushButton { background-color: #3E3E42; color: #E0E0E0; border: none; border-radius: 3px; font-family: 'Segoe UI'; font-weight: bold; }
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
                for b in buttons: b.setEnabled(False)
                if btn: btn.original_text = btn.text(); btn.setText(loading_text)
            else:
                for b in buttons: b.setEnabled(True)
                if btn and hasattr(btn, 'original_text'): pass

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
                QTabWidget::pane {{ border: 0; }}
                QTabBar::tab {{ background: #2D2D2D; color: #CCCCCC; min-width: 160px; padding: 8px 12px; margin-right: 2px; outline: 0; font-family: '{fam}'; font-size: {size}pt; }}
                QTabBar::tab:selected {{ background: #1E1E1E; color: #FFFFFF; font-weight: bold; border-top: 2px solid #007ACC; }}
                QTabBar::tab:hover {{ background: #3E3E42; }}
                QTabBar::tab:focus {{ outline: none; border: none; }}
            """

        def apply_fonts_and_styles(self):
             c_font = QtGui.QFont(self.config.code_font, self.config.code_font_size)
             c_font.setStyleHint(QtGui.QFont.Monospace)
             if hasattr(self, 'asm_code_editor') and self.asm_code_editor: self.asm_code_editor.setFont(c_font)
             if hasattr(self, 'c_code_editor') and self.c_code_editor: self.c_code_editor.setFont(c_font)
             if hasattr(self, 'comments_ai_editor') and self.comments_ai_editor: self.comments_ai_editor.setFont(c_font)
             m_fam = self.config.markdown_font
             m_size = self.config.markdown_font_size
             editor_style = f"QPlainTextEdit {{ background-color: #1E1E1E; color: #D4D4D4; border: none; font-family: '{m_fam}'; font-size: {m_size}pt; }}"
             if hasattr(self, 'note_editor') and self.note_editor:
                 self.note_editor.setStyleSheet(editor_style)
             viewer_style = f"QTextBrowser {{ border: none; background-color: #1E1E1E; color: #D4D4D4; padding: 10px; font-family: '{m_fam}'; font-size: {m_size}pt; }}"
             if hasattr(self, 'note_viewer') and self.note_viewer: self.note_viewer.setStyleSheet(viewer_style)
             if hasattr(self, 'note_previewer') and self.note_previewer: self.note_previewer.setStyleSheet(viewer_style)
             if hasattr(self, 'explanation_viewer') and self.explanation_viewer: self.explanation_viewer.setStyleSheet(viewer_style)
             if hasattr(self, 'suggestion_viewer') and self.suggestion_viewer: self.suggestion_viewer.setStyleSheet(viewer_style)
             if hasattr(self, 'gflow_viewer') and self.gflow_viewer: self.gflow_viewer.setStyleSheet(viewer_style)
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
            from pseudonote.ai_client import SimpleAI as _SimpleAI
            dlg = SettingsDialog(self.config, self.parent)
            if dlg.exec_():
                _ai_mod.AI_CLIENT = _SimpleAI(self.config)
                AI = _get_ai()
                if AI: AI.log_provider_info()
                self.apply_fonts_and_styles()
                self.on_lang_changed(self.current_lang)

        def on_convert(self, mode="C"):
            AI_CLIENT = _get_ai()
            if mode == "ASM":
                reply = QtWidgets.QMessageBox.question(
                    self.parent, f"Confirm ASM to {self.current_lang}",
                    f"Converting Assembly to {self.current_lang} requires significantly more tokens than Decompiled C.\n\nAre you sure you want to proceed?",
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No
                )
                if reply == QtWidgets.QMessageBox.No: return
            ea = self.current_ea
            if not ea or ea == idaapi.BADADDR: ea = idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return
            raw_code = ""
            if mode == "C":
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        raw_code = str(cfunc)
                        raw_code = re.sub(r'\([a-zA-Z0-9_\s\*]+\)', '', raw_code)
                        raw_code = re.sub(r'\s+', ' ', raw_code).strip()
                except: pass
                if not raw_code:
                    print("[PseudoNote] Failed to decompile."); return
            else:
                lines = []
                for item_ea in idautils.FuncItems(func.start_ea):
                    lines.append(f"{item_ea:X}: {idc.GetDisasm(item_ea)}")
                raw_code = "\n".join(lines)
                if not raw_code:
                    print("[PseudoNote] Failed to get assembly."); return

            self.set_loading(True, self.c_convert_btn if mode == "C" else self.asm_convert_btn, "Converting...")
            if mode == "C":
                status_label = self.c_status_label; status_stack = self.c_status_stack; editor = self.c_code_editor
            else:
                status_label = self.asm_status_label; status_stack = self.asm_status_stack; editor = self.asm_code_editor
            status_label.setText(f"Asking AI to convert ({mode} -> {self.current_lang})... please wait.")
            status_stack.setCurrentWidget(status_stack.widget(0))
            editor.setReadOnly(True)
            self.manual_edit_btn.setText("Edit"); self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))

            if mode == "C":
                comment_style = "#" if self.current_lang in ["Python", "Nim"] else "//"
                prompt = (
                    f"Rewrite the following decompiled C code into clean, readable, idiomatic {self.current_lang}.\n"
                    "rules:\n"
                    "1. Output the FULL code. Do not stop halfway.\n"
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
                prompt = (
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

            LOGGER.log(f"Starting conversion to {mode} for function {hex(func.start_ea)}...")
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_ai_response_callback, func_ea=func.start_ea, mode=mode),
                additional_options={"max_completion_tokens": 16384}
            )

        def handle_ai_response_callback(self, response, func_ea, mode="C"):
            try:
                if func_ea != self.last_func_ea:
                    if response:
                        code = response
                        if "```" in code:
                            matches = re.findall(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL)
                            if matches: code = matches[0]
                            else:
                                parts = code.split("```")
                                if len(parts) >= 3: code = parts[1]
                        tag = 0 if mode == "C" else 81
                        save_to_idb(func_ea, code.strip(), tag=tag)
                        print(f"[PseudoNote] Background conversion for {hex(func_ea)} ({mode}) completed and saved.")
                    return

                if mode == "C":
                    status_label = self.c_status_label; status_stack = self.c_status_stack; editor = self.c_code_editor
                else:
                    status_label = self.asm_status_label; status_stack = self.asm_status_stack; editor = self.asm_code_editor

                if not response:
                    status_label.setText("API Error. Check debug logs")
                    status_stack.setCurrentWidget(status_stack.widget(0))
                else:
                    code = response
                    if "```" in code:
                        matches = re.findall(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL)
                        if matches: code = matches[0]
                        else:
                            parts = code.split("```")
                            if len(parts) >= 3: code = parts[1]
                    editor.setPlainText(code.strip())
                    status_stack.setCurrentWidget(editor)
                    if mode == "C": self.last_saved_c_code = code.strip()
                    else: self.last_saved_asm_code = code.strip()
                    tag = 0 if mode == "C" else 81
                    save_to_idb(func_ea, code.strip(), tag=tag)
                    self.update_save_btn_state(self.code_save_btn, saved=True)
                    if mode == "ASM": self.code_tab_widget.setTabText(0, "IDA-View converted")
                    else: self.code_tab_widget.setTabText(1, "Pseudocode converted")
            except Exception as e:
                LOGGER.log(f"Handle AI Response Error: {e}")
                if func_ea == self.last_func_ea:
                    QtWidgets.QMessageBox.warning(self.parent, "PseudoNote API Error", f"An error occurred during conversion:\n\n{str(e)}")
                    if mode == "C":
                         self.c_status_label.setText(f"Error: {e}"); self.c_status_stack.setCurrentWidget(self.c_status_stack.widget(0))
                    else:
                         self.asm_status_label.setText(f"Error: {e}"); self.asm_status_stack.setCurrentWidget(self.asm_status_stack.widget(0))
            finally:
                self.set_loading(False)
                if func_ea == self.last_func_ea:
                    c_text = f"Regenerate {self.current_lang} (AI)" if self.last_saved_c_code else f"Convert to {self.current_lang} (AI)"
                    self.c_convert_btn.setText(c_text)
                    asm_text = f"Regenerate {self.current_lang} (AI)" if self.last_saved_asm_code else f"Convert to {self.current_lang} (AI)"
                    self.asm_convert_btn.setText(asm_text)
                    self.manual_edit_btn.setEnabled(True)

        def on_explain_func(self, context="code"):
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
                QtWidgets.QMessageBox.warning(self.parent, "PseudoNote", "No pseudocode available to explain (Hex-Rays Decompiler required)."); return
            if context == "malware":
                self.set_loading(True, self.explain_malware_btn, "Analyzing...")
                prompt = (
                    "Analyze the following C/Assembly function SPECIFICALLY for MALWARE context.\n\n"
                    "Return the output in Markdown format with the following structure:\n\n"
                    "## Summary\nA brief paragraph describing what the code is doing overall. "
                    "If the function appears BENIGN, clearly and strictly state that.\n\n"
                    "## Detailed Explanation\nProvide a numbered or bullet-point explanation of the logic and behavior.\n\n"
                    f"{decompiled}"
                )
            else:
                self.set_loading(True, self.explain_code_btn, "Asking...")
                prompt = (
                    "Analyze the following C function to explain its PROGRAMMING LOGIC.\n\n"
                    "Return the output in Markdown format using the structure below:\n\n"
                    "## Summary\nProvide a brief paragraph describing what the code is doing overall.\n\n"
                    "## Detailed Explanation\nProvide a numbered or bullet-point explanation of the function logic.\n\n"
                    f"{decompiled}"
                )
            if context == "malware": LOGGER.log(f"Starting malware analysis for function {hex(func.start_ea)}...")
            else: LOGGER.log(f"Starting logic explanation for function {hex(func.start_ea)}...")
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_explain_response_callback, func_ea=func.start_ea),
                additional_options={"max_completion_tokens": 4096}
            )

        def handle_explain_response_callback(self, response, func_ea):
            try:
                if func_ea != self.last_func_ea:
                    if response:
                        save_to_idb(func_ea, response.strip(), tag=79)
                        LOGGER.log(f"Background explanation for {hex(func_ea)} completed and saved.")
                    return
                if not response:
                     LOGGER.log("AI Explain returned empty.")
                     self.explanation_viewer.setText("API Error. Check debug logs")
                else:
                    explanation = response.strip()
                    self.explanation_viewer.setMarkdown(explanation)
                    save_to_idb(func_ea, explanation, tag=79)
                    self.note_tab_widget.setTabText(1, "Function Explain (AI)")
                    self.note_tab_widget.setCurrentIndex(1)
            except Exception as e:
                LOGGER.log(f"Explain Error: {e}")
                if func_ea == self.last_func_ea:
                    QtWidgets.QMessageBox.warning(self.parent, "PseudoNote API Error", f"An error occurred during explanation:\n\n{str(e)}")
                    self.explanation_viewer.setText(f"Error: {str(e)}")
                    self.note_tab_widget.setCurrentIndex(1)
            finally:
                self.set_loading(False)
                if func_ea == self.last_func_ea:
                    self.explain_malware_btn.setText("Malware")
                    self.explain_code_btn.setText("Code")

        def on_get_gflow(self):
            AI_CLIENT = _get_ai()
            ea = self.current_ea
            if not ea or ea == idaapi.BADADDR: ea = idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func: return
            decompiled = ""
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc: decompiled = str(cfunc)
            except: pass
            if not decompiled:
                QtWidgets.QMessageBox.warning(self.parent, "Decompile error", "Could not decompile function for analysis."); return
            self.set_loading(True, self.gflow_btn, "Generating...")
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
                f"{decompiled}"
            )
            LOGGER.log(f"Starting Graph Flow generation for function {hex(func.start_ea)}...")
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_gflow_response_callback, func_ea=func.start_ea),
                additional_options={"max_completion_tokens": 4096}
            )

        def handle_gflow_response_callback(self, response, func_ea):
            try:
                if func_ea != self.last_func_ea:
                    if response:
                        save_to_idb(func_ea, response.strip(), tag=82)
                        LOGGER.log(f"Background Graph Flow for {hex(func_ea)} completed and saved.")
                    return
                if not response:
                     LOGGER.log("AI Graph Flow returned empty.")
                     self.gflow_viewer.setText("API Error. Check debug logs")
                else:
                    gflow = response.strip()
                    gflow = f"Function start\n\n{gflow}"
                    self.gflow_viewer.setMarkdown(gflow)
                    save_to_idb(func_ea, gflow, tag=82)
                    self.note_tab_widget.setCurrentIndex(2)
            except Exception as e:
                LOGGER.log(f"Graph Flow Error: {e}")
                if func_ea == self.last_func_ea:
                    QtWidgets.QMessageBox.warning(self.parent, "PseudoNote API Error", f"An error occurred during Graph Flow generation:\n\n{str(e)}")
                    self.gflow_viewer.setText(f"Error: {str(e)}")
                    self.note_tab_widget.setCurrentIndex(2)
            finally:
                self.set_loading(False)
                if func_ea == self.last_func_ea:
                    self.gflow_btn.setText("Get graph")

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
            self.set_loading(True, self.suggest_name_btn, "Gathering context...")
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
            self.suggest_name_btn.setText("Analyzing...")
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
                "## Return Value\n- Brief explanation.\n\n"
                "## Key Global Variables\n- `g_VarName`: Read/Written - purpose\n\n"
                "## Key Local Variables\n- `vX` (Type/Size): Purpose (e.g. buffer, index, etc.)\n\n"
                "Do not include extra commentary outside these sections."
            )
            ctx_summary = (f"{len(context['callers'])} callers, "
                          f"{len(context['callees_api']) + len(context['callees_internal'])} callees, "
                          f"{len(context['strings'])} strings")
            LOGGER.log(f"Starting function details for {hex(func.start_ea)} (deep context: {ctx_summary})...")
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_suggest_name_callback, func_ea=func.start_ea, context_text=display_text),
                additional_options={"max_completion_tokens": 16384}
            )

        def handle_suggest_name_callback(self, response, func_ea, context_text=""):
            try:
                if func_ea != self.last_func_ea:
                    if response:
                        full_output = response
                        if context_text: full_output += f"\n\n{context_text}"
                        save_to_idb(func_ea, full_output, tag=80)
                        LOGGER.log(f"Background details for {hex(func_ea)} completed and saved.")
                    return
                if not response:
                     self.suggestion_viewer.setText("API Error. Check debug logs")
                else:
                    full_output = response
                    if context_text: full_output += f"\n\n{context_text}"
                    self.suggestion_viewer.setMarkdown(full_output)
                    save_to_idb(func_ea, full_output, tag=80)
                    self.note_tab_widget.setTabText(3, "Function Details (AI)")
                    self.note_tab_widget.setCurrentIndex(3)
            except Exception as e:
                LOGGER.log(f"Details Error: {e}")
                if func_ea == self.last_func_ea:
                    QtWidgets.QMessageBox.warning(self.parent, "PseudoNote API Error", f"An error occurred getting details:\n\n{str(e)}")
                    self.suggestion_viewer.setText(f"Error: {str(e)}")
            finally:
                self.set_loading(False)
                if func_ea == self.last_func_ea:
                    self.suggest_name_btn.setText("Function Details (AI)")

        def on_get_comments_ai(self):
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
                QtWidgets.QMessageBox.warning(self.parent, "PseudoNote", "No pseudocode available (Hex-Rays Decompiler required)."); return
            if not AI_CLIENT:
                LOGGER.log("AI client not initialised."); return
            self.set_loading(True, self.get_comments_ai_btn, "Commenting...")
            self.comments_ai_status_label.setText("AI is analyzing and rewriting code with comments... please wait.")
            self.comments_ai_stack.setCurrentIndex(0)
            prompt = (
                "You are an expert reverse engineer.\n\n"
                "Rewrite the following C function exactly as-is (same logic, names, and structure), "
                "but add concise comments ONLY at major logical blocks.\n\n"
                f"{decompiled}\n\n"
                "Rules:\n"
                "- Do NOT comment every line.\n"
                "- Add comments only above major blocks.\n"
                "- Do NOT modify code.\n"
                "- Return ONLY the C code inside ```c markdown block."
            )
            LOGGER.log(f"Starting AI comment generation for function {hex(func.start_ea)}...")
            AI_CLIENT.query_model_async(
                prompt,
                functools.partial(self.handle_get_comments_callback, func_ea=func.start_ea),
                additional_options={"max_completion_tokens": 16384}
            )

        def handle_get_comments_callback(self, response, func_ea):
            try:
                if func_ea != self.last_func_ea:
                    if response:
                        save_to_idb(func_ea, response.strip(), tag=83)
                        LOGGER.log(f"Background comments for {hex(func_ea)} completed and saved.")
                    return
                if not response:
                    self.comments_ai_status_label.setText("API Error. Check debug logs.")
                    self.comments_ai_stack.setCurrentIndex(0)
                else:
                    code = response.strip()
                    if "```" in code:
                        matches = re.findall(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL)
                        if matches: code = matches[0]
                        else:
                            parts = code.split("```")
                            if len(parts) >= 3: code = parts[1]
                    self.comments_ai_editor.setPlainText(code.strip())
                    save_to_idb(func_ea, response.strip(), tag=83)
                    self.comments_ai_stack.setCurrentIndex(1)
                    self.code_tab_widget.setCurrentIndex(2)
            except Exception as e:
                LOGGER.log(f"Comments AI Error: {e}")
                if func_ea == self.last_func_ea:
                    self.comments_ai_status_label.setText(f"Error: {e}")
                    self.comments_ai_stack.setCurrentIndex(0)
            finally:
                self.set_loading(False)
                if func_ea == self.last_func_ea:
                    self.get_comments_ai_btn.setText("Get Comments (AI)")

        def refresh_ui(self, force=False):
            if not QtWidgets: return
            try: ea = idaapi.get_screen_ea()
            except: ea = idaapi.BADADDR
            if ea == idaapi.BADADDR: return
            func = idaapi.get_func(ea)
            if not func:
                self.current_ea = None
                self.title_label.setText("No Function Selected")
                self.c_status_label.setText(START_TEXT)
                self.c_status_stack.setCurrentWidget(self.c_status_stack.widget(0))
                self.c_convert_btn.setEnabled(False)
                self.asm_status_label.setText(START_TEXT)
                self.asm_status_stack.setCurrentWidget(self.asm_status_stack.widget(0))
                self.asm_convert_btn.setEnabled(False)
                self.comments_ai_status_label.setText(START_TEXT)
                self.comments_ai_stack.setCurrentIndex(0)
                return
            self.current_ea = ea
            func_ea = func.start_ea
            if not force and self.last_func_ea == func_ea: return
            self.last_func_ea = func_ea
            name = idc.get_func_name(func_ea)
            accent = "#569CD6"
            self.title_label.setText(f'Readable code: <span style="color: {accent};">{name}</span>')
            if getattr(self, "func_name_label", None):
                self.func_name_label.setText(f'Analyst notes: <span style="color: {accent};">{name}</span>')
            try: self.SetTitle(f"PseudoNote: {name}")
            except:
                if self.parent: self.parent.setWindowTitle(f"PseudoNote: {name}")
            self.c_code_editor.setReadOnly(True)
            self.asm_code_editor.setReadOnly(True)
            self.manual_edit_btn.setText("Edit")
            self.manual_edit_btn.setEnabled(True)
            self.manual_edit_btn.setStyleSheet(self.get_btn_style(blue=True))

            code_c = load_from_idb(func_ea, tag=0)
            self.c_code_editor.blockSignals(True)
            if code_c:
                self.last_saved_c_code = code_c
                self.c_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
                self.c_code_editor.setPlainText(code_c)
                self.c_status_stack.setCurrentWidget(self.c_code_editor)
                self.code_tab_widget.setTabText(1, "Pseudocode converted")
            else:
                self.last_saved_c_code = ""
                self.c_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
                self.c_code_editor.setPlainText("")
                self.c_status_stack.setCurrentWidget(self.c_status_stack.widget(0))
                self.c_status_label.setText(START_TEXT)
                self.code_tab_widget.setTabText(1, "Pseudocode")
            self.c_code_editor.blockSignals(False)

            code_asm = load_from_idb(func_ea, tag=81)
            self.asm_code_editor.blockSignals(True)
            if code_asm:
                self.last_saved_asm_code = code_asm
                self.asm_convert_btn.setText(f"Regenerate {self.current_lang} (AI)")
                self.asm_code_editor.setPlainText(code_asm)
                self.asm_status_stack.setCurrentWidget(self.asm_code_editor)
                self.code_tab_widget.setTabText(0, "IDA-View converted")
            else:
                self.last_saved_asm_code = ""
                self.asm_convert_btn.setText(f"Convert to {self.current_lang} (AI)")
                self.asm_code_editor.setPlainText("")
                self.asm_status_stack.setCurrentWidget(self.asm_status_stack.widget(0))
                self.asm_status_label.setText(START_TEXT)
                self.code_tab_widget.setTabText(0, "IDA-View")
            self.asm_code_editor.blockSignals(False)

            self.on_code_text_changed()
            self.on_code_tab_changed(self.code_tab_widget.currentIndex())
            self.c_convert_btn.setEnabled(True)
            self.asm_convert_btn.setEnabled(True)

            note = load_from_idb(func_ea, tag=78)
            self.last_saved_note = note if note else ""
            self.note_editor.blockSignals(True)
            self.note_editor.setPlainText(self.last_saved_note)
            self.note_editor.blockSignals(False)
            self.update_save_btn_state(self.note_save_btn, saved=True)
            self.toggle_note_mode(edit=False)
            if not self.last_saved_note:
                self.note_viewer.setText("")

            explanation = load_from_idb(func_ea, tag=79)
            if explanation: self.explanation_viewer.setMarkdown(explanation)
            else:
                self.explanation_viewer.setPlaceholderText("Click 'Explain (AI)' to generate an explanation for the current function.")
                self.explanation_viewer.setText("")

            gflow = load_from_idb(func_ea, tag=82)
            if gflow: self.gflow_viewer.setMarkdown(gflow)
            else:
                self.gflow_viewer.setPlaceholderText("Click 'Get graph' to generate a text flow graph.")
                self.gflow_viewer.setText("")

            suggestions = load_from_idb(func_ea, tag=80)
            if suggestions: self.suggestion_viewer.setMarkdown(suggestions)
            else:
                self.suggestion_viewer.setPlaceholderText("Click 'Function Details (AI)' to generate details.")
                self.suggestion_viewer.setText("")

            comments = load_from_idb(func_ea, tag=83)
            if comments:
                code = comments.strip()
                if "```" in code:
                    matches = re.findall(r"```(?:\w+)?\n(.*?)```", code, re.DOTALL)
                    if matches: code = matches[0]
                    else:
                        parts = code.split("```")
                        if len(parts) >= 3: code = parts[1]
                self.comments_ai_editor.setPlainText(code.strip())
                self.comments_ai_stack.setCurrentIndex(1)
            else:
                self.comments_ai_status_label.setText(START_TEXT)
                self.comments_ai_stack.setCurrentIndex(0)
                self.comments_ai_editor.setPlainText("")

        def OnClose(self, form):
            global _view_instance
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
        if idaapi.get_widget_type(widget) in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASMS]:
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:action", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:list", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "-", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_variables", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_function", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:rename_function_malware", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:suggest_function_signature", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:analyze_struct", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:bulk_rename", "PseudoNote/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:add_comments", "PseudoNote/Comments/")
            idaapi.attach_action_to_popup(widget, popup, "pseudonote:delete_comments", "PseudoNote/Comments/")
            if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                idaapi.attach_action_to_popup(widget, popup, "pseudonote:highlight_on", "PseudoNote/Call Highlight/")
                idaapi.attach_action_to_popup(widget, popup, "pseudonote:highlight_off", "PseudoNote/Call Highlight/")
            elif idaapi.get_widget_type(widget) in [idaapi.BWN_DISASMS, idaapi.BWN_DISASM]:
                idaapi.attach_action_to_popup(widget, popup, "pseudonote:disasm_highlight_on", "PseudoNote/Call Highlight/")
                idaapi.attach_action_to_popup(widget, popup, "pseudonote:disasm_highlight_off", "PseudoNote/Call Highlight/")
