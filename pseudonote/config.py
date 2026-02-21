# -*- coding: utf-8 -*-
"""
Configuration management and logging for PseudoNote.
"""

import os
import datetime
import configparser

from pseudonote.qt_compat import QtCore, Signal


class Config:
    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        # Location in the plugin directory (might be read-only if in Program Files)
        self.plugin_config_path = os.path.join(self.plugin_dir, "PseudoNote.ini")
        # Writable fallback in user home directory
        self.user_config_path = os.path.join(os.path.expanduser("~"), ".pseudonote.ini")
        
        # Determine the primary path to use (prefer the one that exists or the user one for writing)
        if os.path.exists(self.user_config_path):
            self.config_path = self.user_config_path
        else:
            self.config_path = self.plugin_config_path

        self.model = "gpt-4"
        self.proxy = ""

        self.openai_key = ""
        self.openai_url = "https://api.openai.com/v1"

        self.deepseek_key = ""
        self.deepseek_url = "https://api.deepseek.com/v1"

        self.anthropic_key = ""
        self.anthropic_url = "https://api.anthropic.com"

        self.gemini_key = ""

        self.ollama_host = "http://localhost:11434/v1"
        self.ollama_model = "llama3"

        self.lmstudio_url = "http://localhost:1234/v1"
        self.lmstudio_key = "lm-studio"

        self.custom_key = ""
        self.custom_url = ""
        self.custom_model = ""

        self.active_provider = "openai"
        self.openai_model = "gpt-4"
        self.deepseek_model = "deepseek-coder"
        self.anthropic_model = "claude-3-opus-20240229"
        self.gemini_model = "gemini-1.5-pro"
        self.lmstudio_model = "local-model"

        self.ui_font = "Segoe UI"
        self.ui_font_size = 9
        self.code_font = "Consolas"
        self.code_font_size = 10
        self.markdown_font = "Consolas"
        self.markdown_font_size = 10

        # Analysis Defaults
        self.batch_size = 10
        self.parallel_workers = 1
        self.min_func_size = 10
        self.max_xrefs = 100
        self.filter_system = True
        self.filter_empty = True

        self.load()

    def load(self):
        self.openai_key = os.environ.get("PSEUDONOTE_OPENAI_API_KEY", "")
        self.deepseek_key = os.environ.get("PSEUDONOTE_DEEPSEEK_API_KEY", "")
        self.anthropic_key = os.environ.get("PSEUDONOTE_ANTHROPIC_API_KEY", "")
        self.gemini_key = os.environ.get("PSEUDONOTE_GEMINI_API_KEY", "")

        parser = configparser.ConfigParser()
        # Read from both. User config overrides plugin config if both exist.
        configs_to_read = []
        if os.path.exists(self.plugin_config_path):
            configs_to_read.append(self.plugin_config_path)
        if os.path.exists(self.user_config_path):
            configs_to_read.append(self.user_config_path)
        
        if not configs_to_read:
            return

        parser.read(configs_to_read, encoding="utf-8")

        if parser.has_section("PseudoNote"):
            if parser.has_option("PseudoNote", "MODEL"):
                self.model = parser.get("PseudoNote", "MODEL")
            if parser.has_option("PseudoNote", "PROXY"):
                self.proxy = parser.get("PseudoNote", "PROXY")
            if parser.has_option("PseudoNote", "PROVIDER"):
                self.active_provider = parser.get("PseudoNote", "PROVIDER")

        if parser.has_section("OpenAI"):
            if parser.has_option("OpenAI", "API_KEY"):
                k = parser.get("OpenAI", "API_KEY")
                if k: self.openai_key = k
            if parser.has_option("OpenAI", "BASE_URL"):
                u = parser.get("OpenAI", "BASE_URL")
                if u: self.openai_url = u
            if parser.has_option("OpenAI", "MODEL"):
                m = parser.get("OpenAI", "MODEL")
                if m: self.openai_model = m

        if parser.has_section("DeepSeek"):
            if parser.has_option("DeepSeek", "API_KEY"):
                k = parser.get("DeepSeek", "API_KEY")
                if k: self.deepseek_key = k
            if parser.has_option("DeepSeek", "BASE_URL"):
                u = parser.get("DeepSeek", "BASE_URL")
                if u: self.deepseek_url = u
            if parser.has_option("DeepSeek", "MODEL"):
                m = parser.get("DeepSeek", "MODEL")
                if m: self.deepseek_model = m

        if parser.has_section("Anthropic"):
            if parser.has_option("Anthropic", "API_KEY"):
                k = parser.get("Anthropic", "API_KEY")
                if k: self.anthropic_key = k
            if parser.has_option("Anthropic", "BASE_URL"):
                u = parser.get("Anthropic", "BASE_URL")
                if u: self.anthropic_url = u
            if parser.has_option("Anthropic", "MODEL"):
                m = parser.get("Anthropic", "MODEL")
                if m: self.anthropic_model = m

        if parser.has_section("Gemini"):
            if parser.has_option("Gemini", "API_KEY"):
                k = parser.get("Gemini", "API_KEY")
                if k: self.gemini_key = k
            if parser.has_option("Gemini", "MODEL"):
                m = parser.get("Gemini", "MODEL")
                if m: self.gemini_model = m

        if parser.has_section("Ollama"):
             if parser.has_option("Ollama", "HOST"):
                h = parser.get("Ollama", "HOST")
                if h: self.ollama_host = h.rstrip('/')
                if not self.ollama_host.endswith("/v1"): self.ollama_host += "/v1"
             if parser.has_option("Ollama", "MODEL"):
                m = parser.get("Ollama", "MODEL")
                if m: self.ollama_model = m

        if parser.has_section("LMStudio"):
            if parser.has_option("LMStudio", "BASE_URL"):
                u = parser.get("LMStudio", "BASE_URL")
                if u: self.lmstudio_url = u
            if parser.has_option("LMStudio", "API_KEY"):
                k = parser.get("LMStudio", "API_KEY")
                if k: self.lmstudio_key = k
            if parser.has_option("LMStudio", "MODEL"):
                m = parser.get("LMStudio", "MODEL")
                if m: self.lmstudio_model = m

        if parser.has_section("OpenAICompatible"):
            self.custom_key = parser.get("OpenAICompatible", "API_KEY", fallback="")
            self.custom_url = parser.get("OpenAICompatible", "BASE_URL", fallback="")
            self.custom_model = parser.get("OpenAICompatible", "MODEL_NAME", fallback="")

        if parser.has_section("Fonts"):
            self.ui_font = parser.get("Fonts", "UI_FONT", fallback="Segoe UI")
            self.ui_font_size = parser.getint("Fonts", "UI_SIZE", fallback=9)
            self.code_font = parser.get("Fonts", "CODE_FONT", fallback="Consolas")
            self.code_font_size = parser.getint("Fonts", "CODE_SIZE", fallback=10)
            self.markdown_font = parser.get("Fonts", "MD_FONT", fallback="Consolas")
            self.markdown_font_size = parser.getint("Fonts", "MD_SIZE", fallback=10)

        if parser.has_section("Analysis"):
            self.batch_size = parser.getint("Analysis", "BATCH_SIZE", fallback=10)
            self.parallel_workers = parser.getint("Analysis", "WORKERS", fallback=1)
            self.min_func_size = parser.getint("Analysis", "MIN_SIZE", fallback=10)
            self.max_xrefs = parser.getint("Analysis", "MAX_XREFS", fallback=100)
            self.filter_system = parser.getboolean("Analysis", "FILTER_SYS", fallback=True)
            self.filter_empty = parser.getboolean("Analysis", "FILTER_EMPTY", fallback=True)

    def save(self):
        parser = configparser.ConfigParser()
        parser.optionxform = str

        if os.path.exists(self.config_path):
            parser.read(self.config_path, encoding="utf-8")

        if not parser.has_section("PseudoNote"): parser.add_section("PseudoNote")
        parser.set("PseudoNote", "MODEL", self.model)
        parser.set("PseudoNote", "PROXY", self.proxy)
        parser.set("PseudoNote", "PROVIDER", self.active_provider)

        if not parser.has_section("OpenAI"): parser.add_section("OpenAI")
        parser.set("OpenAI", "API_KEY", self.openai_key)
        parser.set("OpenAI", "BASE_URL", self.openai_url)
        parser.set("OpenAI", "MODEL", self.openai_model)

        if not parser.has_section("DeepSeek"): parser.add_section("DeepSeek")
        parser.set("DeepSeek", "API_KEY", self.deepseek_key)
        parser.set("DeepSeek", "BASE_URL", self.deepseek_url)
        parser.set("DeepSeek", "MODEL", self.deepseek_model)

        if not parser.has_section("Anthropic"): parser.add_section("Anthropic")
        parser.set("Anthropic", "API_KEY", self.anthropic_key)
        parser.set("Anthropic", "BASE_URL", self.anthropic_url)
        parser.set("Anthropic", "MODEL", self.anthropic_model)

        if not parser.has_section("Gemini"): parser.add_section("Gemini")
        parser.set("Gemini", "API_KEY", self.gemini_key)
        parser.set("Gemini", "MODEL", self.gemini_model)

        if not parser.has_section("Ollama"): parser.add_section("Ollama")
        parser.set("Ollama", "HOST", self.ollama_host)
        parser.set("Ollama", "MODEL", self.ollama_model)

        if not parser.has_section("LMStudio"): parser.add_section("LMStudio")
        parser.set("LMStudio", "BASE_URL", self.lmstudio_url)
        parser.set("LMStudio", "API_KEY", self.lmstudio_key)
        parser.set("LMStudio", "MODEL", self.lmstudio_model)

        if not parser.has_section("OpenAICompatible"): parser.add_section("OpenAICompatible")
        parser.set("OpenAICompatible", "API_KEY", self.custom_key)
        parser.set("OpenAICompatible", "BASE_URL", self.custom_url)
        parser.set("OpenAICompatible", "MODEL_NAME", self.custom_model)

        if not parser.has_section("Fonts"): parser.add_section("Fonts")
        parser.set("Fonts", "UI_FONT", self.ui_font)
        parser.set("Fonts", "UI_SIZE", str(self.ui_font_size))
        parser.set("Fonts", "CODE_FONT", self.code_font)
        parser.set("Fonts", "CODE_SIZE", str(self.code_font_size))
        parser.set("Fonts", "MD_FONT", self.markdown_font)
        parser.set("Fonts", "MD_SIZE", str(self.markdown_font_size))

        if not parser.has_section("Analysis"): parser.add_section("Analysis")
        parser.set("Analysis", "BATCH_SIZE", str(self.batch_size))
        parser.set("Analysis", "WORKERS", str(self.parallel_workers))
        parser.set("Analysis", "MIN_SIZE", str(self.min_func_size))
        parser.set("Analysis", "MAX_XREFS", str(self.max_xrefs))
        parser.set("Analysis", "FILTER_SYS", str(self.filter_system))
        parser.set("Analysis", "FILTER_EMPTY", str(self.filter_empty))

        # Try saving. Handle Permission Denied (e.g. Program Files) by falling back to user home.
        success = False
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                parser.write(f)
            LOGGER.log(f"Configuration saved to {self.config_path}")
            success = True
        except (IOError, OSError) as e:
            if self.config_path != self.user_config_path:
                LOGGER.log(f"Permission denied writing to {self.config_path}. Falling back to user home...")
                self.config_path = self.user_config_path
                try:
                    with open(self.config_path, 'w', encoding='utf-8') as f:
                        parser.write(f)
                    LOGGER.log(f"Configuration saved to {self.config_path}")
                    success = True
                except Exception as e2:
                    LOGGER.log(f"Failed to save to user home: {e2}")
            else:
                LOGGER.log(f"Error saving config: {e}")

        if not success:
             LOGGER.log("CRITICAL: Could not save configuration to any location.")


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
class PseudoLogger(QtCore.QObject):
    if Signal:
        log_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.logs = []

    def log(self, message):
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            entry = f"[{timestamp}] {message}"
            self.logs.append(entry)

            if hasattr(self, 'log_signal'):
                self.log_signal.emit(entry)
        except:
            print(message)


# Module singletons
LOGGER = PseudoLogger()
CONFIG = Config()
