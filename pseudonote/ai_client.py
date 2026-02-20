# -*- coding: utf-8 -*-
"""
AI client for PseudoNote - handles communication with AI providers.
"""

import threading
import functools

import ida_kernwin

from pseudonote.qt_compat import openai, httpx, anthropic, genai
from pseudonote.config import CONFIG, LOGGER


class SimpleAI:
    def __init__(self, config):
        self.config = config
        self.provider = "openai"
        self.client = None
        self.async_func = None

        self.determine_provider()
        self.init_client()

    def determine_provider(self):

        if self.config.active_provider and self.config.active_provider != "auto":
            p = self.config.active_provider.lower()
            if p == "openaicompatible": self.provider = "custom"
            else: self.provider = p
            return


        m = self.config.model.lower()
        if "claude" in m: self.provider = "anthropic"
        elif "gemini" in m: self.provider = "gemini"
        elif "deepseek" in m: self.provider = "deepseek"
        elif "ollama" in m: self.provider = "ollama"
        elif "lmstudio" in m or "local" in m: self.provider = "lmstudio"
        elif self.config.custom_url: self.provider = "custom"
        else: self.provider = "openai"

    def init_client(self):
        http_client = httpx.Client(proxy=self.config.proxy) if self.config.proxy else None

        if self.provider == "openai":
            if not openai or not self.config.openai_key: return
            self.client = openai.OpenAI(api_key=self.config.openai_key, base_url=self.config.openai_url, http_client=http_client)

        elif self.provider == "deepseek":
            if not openai or not self.config.deepseek_key: return
            self.client = openai.OpenAI(api_key=self.config.deepseek_key, base_url=self.config.deepseek_url, http_client=http_client)

        elif self.provider == "ollama":
            if not openai: return
            self.client = openai.OpenAI(api_key="ollama", base_url=self.config.ollama_host, http_client=http_client)

        elif self.provider == "lmstudio":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.config.lmstudio_key, base_url=self.config.lmstudio_url, http_client=http_client)

        elif self.provider == "custom":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.config.custom_key, base_url=self.config.custom_url, http_client=http_client)

        elif self.provider == "anthropic":
            if not anthropic or not self.config.anthropic_key:
                LOGGER.log("Anthropic library or Key missing.")
                return
            self.client = anthropic.Anthropic(api_key=self.config.anthropic_key, base_url=self.config.anthropic_url, http_client=http_client)

        elif self.provider == "gemini":
            if not genai or not self.config.gemini_key:
                LOGGER.log("Google GenAI library or Key missing.")
                return
            genai.configure(api_key=self.config.gemini_key)
            self.client = "gemini_configured"

    def log_provider_info(self):

        pass

    def query_model_async(self, prompt, callback, additional_options=None):
        if additional_options is None: additional_options = {}

        def thread_target():
            content = ""
            try:
                LOGGER.log(f"Sending request to {self.provider}...")

                if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                    if not self.client: raise ValueError(f"Client for {self.provider} not initialized.")

                    messages = [{"role": "user", "content": prompt}]
                    model = self.config.model
                    if self.provider == "ollama" and self.config.ollama_model: model = self.config.ollama_model
                    if self.provider == "custom" and self.config.custom_model: model = self.config.custom_model

                    valid_args = {"model": model, "messages": messages}
                    is_reasoning = any(x in model.lower() for x in ["o1", "o3", "gpt-5"])
                    
                    if "max_completion_tokens" in additional_options:
                         if is_reasoning:
                             valid_args["max_completion_tokens"] = additional_options["max_completion_tokens"]
                         else:
                             valid_args["max_tokens"] = additional_options["max_completion_tokens"]
                    
                    # Also copy any other additional options
                    for k, v in additional_options.items():
                        if k == "max_completion_tokens": continue
                        # Reasoning models don't support temperature or top_p usually, or keep them default
                        if is_reasoning and k in ["temperature", "top_p", "response_format"]:
                            # Skip these for reasoning if they might cause 400s
                            continue
                        valid_args[k] = v

                    response = self.client.chat.completions.create(**valid_args)
                    if response.choices and response.choices[0].message.content:
                        content = response.choices[0].message.content
                    else:
                        LOGGER.log(f"Warning: No content in response: {response}")
                        content = ""

                elif self.provider == "anthropic":
                     if not self.client: raise ValueError("Anthropic client not initialized.")
                     message = self.client.messages.create(
                        model=self.config.model,
                        max_tokens=4096,
                        messages=[{"role": "user", "content": prompt}]
                     )
                     content = message.content[0].text

                elif self.provider == "gemini":
                     if not self.client: raise ValueError("Gemini not configured.")
                     model = genai.GenerativeModel(CONFIG.model)
                     response = model.generate_content(prompt)
                     content = response.text

                LOGGER.log(f"Received response from {self.provider} ({len(content)} chars).")

                ida_kernwin.execute_sync(
                    functools.partial(callback, response=content),
                    ida_kernwin.MFF_WRITE
                )
            except Exception as e:
                LOGGER.log(f"AI Error ({self.provider}): {e}")

                ida_kernwin.execute_sync(
                    functools.partial(callback, response=None),
                    ida_kernwin.MFF_WRITE
                )

        threading.Thread(target=thread_target).start()


# Module-level singleton
AI_CLIENT = None
