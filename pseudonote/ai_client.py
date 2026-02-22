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
        ap = getattr(self.config, 'active_provider', None)
        LOGGER.log(f"Determining AI provider. config.active_provider='{ap}'")
        
        if ap and ap.lower() != "auto":
            p = ap.lower()
            if p in ["openaicompatible", "custom"]: self.provider = "custom"
            else: self.provider = p
            LOGGER.log(f"AI Provider explicitly set to: {self.provider}")
            return

        m = self.config.model.lower()
        if "claude" in m: self.provider = "anthropic"
        elif "gemini" in m: self.provider = "gemini"
        elif "deepseek" in m: self.provider = "deepseek"
        elif "ollama" in m: self.provider = "ollama"
        elif "lmstudio" in m or "local" in m: self.provider = "lmstudio"
        elif getattr(self.config, 'custom_url', None): self.provider = "custom"
        else: self.provider = "openai"
        LOGGER.log(f"AI Provider auto-detected as: {self.provider}")

    def log_provider_info(self):
        info = f"Active AI Provider: {self.provider}"
        if self.provider == "custom":
            info += f" (OAI-Compatible, URL: {self.config.custom_url})"
        elif self.provider == "openai":
            info += f" (URL: {self.config.openai_url})"
        # Add more as needed
        LOGGER.log(info)

    def init_client(self):
        http_client = httpx.Client(proxy=self.config.proxy) if self.config.proxy else None

        # Helper to clean URLs
        def clean_url(u):
            if not u: return u
            u = u.strip()
            if u.endswith('/'): u = u[:-1]
            return u

        if self.provider == "openai":
            if not openai or not self.config.openai_key: return
            self.client = openai.OpenAI(api_key=self.config.openai_key, base_url=clean_url(self.config.openai_url), http_client=http_client)

        elif self.provider == "deepseek":
            if not openai or not self.config.deepseek_key: return
            self.client = openai.OpenAI(api_key=self.config.deepseek_key, base_url=clean_url(self.config.deepseek_url), http_client=http_client)

        elif self.provider == "ollama":
            if not openai: return
            self.client = openai.OpenAI(api_key="ollama", base_url=clean_url(self.config.ollama_host), http_client=http_client)

        elif self.provider == "lmstudio":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.config.lmstudio_key, base_url=clean_url(self.config.lmstudio_url), http_client=http_client)

        elif self.provider == "custom":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.config.custom_key, base_url=clean_url(self.config.custom_url), http_client=http_client)

        elif self.provider == "anthropic":
            if not anthropic or not self.config.anthropic_key:
                LOGGER.log("Anthropic library or Key missing.")
                return
            self.client = anthropic.Anthropic(api_key=self.config.anthropic_key, base_url=clean_url(self.config.anthropic_url), http_client=http_client)

        elif self.provider == "gemini":
            if not genai or not self.config.gemini_key:
                LOGGER.log("Google GenAI library or Key missing.")
                return
            genai.configure(api_key=self.config.gemini_key)
            self.client = "gemini_configured"

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
                    # Reasoning models (OpenAI o1/o3, DeepSeek R1/Reasoner, some Qwen/Llama variants)
                    is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                    
                    if "max_completion_tokens" in additional_options:
                         if is_reasoning:
                             valid_args["max_completion_tokens"] = additional_options["max_completion_tokens"]
                         else:
                             valid_args["max_tokens"] = additional_options["max_completion_tokens"]
                    
                    for k, v in additional_options.items():
                        if k == "max_completion_tokens": continue
                        if is_reasoning and k in ["temperature", "top_p", "response_format"]:
                            continue
                        valid_args[k] = v

                    response = self.client.chat.completions.create(**valid_args)
                    msg = response.choices[0].message if response.choices else None
                    if msg:
                        # 1. Try standard content attribute
                        content = getattr(msg, 'content', "") or ""
                        
                        # 2. Try reasoning fields
                        reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                        if not content.strip() and reasoning.strip():
                            content = reasoning
                        
                        # 3. Fallback for legacy or non-standard provider responses (text attribute)
                        if not content.strip():
                            content = getattr(msg, 'text', "") or ""
                        
                        # 4. Dictionary-style access fallback
                        if not content.strip():
                            try:
                                if isinstance(msg, dict):
                                    content = msg.get('content') or msg.get('text') or msg.get('reasoning_content') or ""
                                elif hasattr(msg, 'get'):
                                    content = msg.get('content', "") or msg.get('text', "") or ""
                            except: pass

                        # Check for refusal
                        refusal = getattr(msg, 'refusal', None)
                        if refusal:
                            LOGGER.log(f"Model refused request: {refusal}")
                            if not content:
                                content = f"Error: Model refused request. {refusal}"
                    else:
                        LOGGER.log(f"Warning: No choices in response: {response}")
                        content = ""

                elif self.provider == "anthropic":
                     if not self.client: raise ValueError("Anthropic client not initialized.")
                     message = self.client.messages.create(
                        model=self.config.model,
                        max_tokens=4096,
                        messages=[{"role": "user", "content": prompt}]
                     )
                     content = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])

                elif self.provider == "gemini":
                     if not self.client: raise ValueError("Gemini not configured.")
                     model = genai.GenerativeModel(self.config.model)
                     response = model.generate_content(prompt)
                     content = response.text

                LOGGER.log(f"Received response from {self.provider} ({len(content)} chars).")

                if not content.strip():
                    LOGGER.log(f"DEBUG: Empty response from {self.provider}. Response object: {response}")

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

    def test_connection(self):
        prompt = "test connection. please reply with the word 'pong' so I know you are active."
        try:
            if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                if not self.client: return False, "Client not initialized."
                
                model = self.config.model
                if self.provider == "ollama" and self.config.ollama_model: model = self.config.ollama_model
                if self.provider == "custom" and self.config.custom_model: model = self.config.custom_model

                is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "reasoner", "reasoning", "thought"])
                valid_args = {"model": model, "messages": [{"role": "user", "content": prompt}]}
                
                if is_reasoning:
                    valid_args["max_completion_tokens"] = 30 
                else:
                    valid_args["max_tokens"] = 30
                    valid_args["temperature"] = 0

                response = self.client.chat.completions.create(**valid_args)
                
                if not response.choices:
                    LOGGER.log(f"Test Connection: No choices. Full response: {response}")
                    return False, f"Connected but API returned no choices. (Model: {model})"

                msg = response.choices[0].message
                content = getattr(msg, 'content', "") or getattr(msg, 'text', "") or ""
                reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                refusal = getattr(msg, 'refusal', None)
                
                # Check for content in message dictionary (fallback)
                if not content and not reasoning:
                    try:
                        if hasattr(msg, 'get'):
                            content = msg.get('content', "") or msg.get('text', "") or msg.get('reasoning_content', "") or ""
                    except: pass

                if content.strip() or reasoning.strip():
                    return True, "Connection successful!"
                    
                if refusal:
                    return False, f"Connected but model refused request: {refusal}"
                
                LOGGER.log(f"Test Connection: Empty content. Full message object: {msg}")
                return False, f"Connected to {self.provider} but received empty response content for model '{model}'. check Debug Logs for details."

            elif self.provider == "anthropic":
                if not self.client: return False, "Anthropic client not initialized."
                message = self.client.messages.create(
                    model=self.config.anthropic_model if self.config.anthropic_model else self.config.model,
                    max_tokens=10,
                    messages=[{"role": "user", "content": prompt}]
                )
                return True, f"Connection successful!"

            elif self.provider == "gemini":
                if not self.client: return False, "Gemini not configured."
                model_name = self.config.gemini_model if self.config.gemini_model else self.config.model
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                return True, f"Connection successful!"

            return False, f"Unknown provider: {self.provider}"
        except Exception as e:
            return False, f"Connection Failed: {str(e)}"


# Module-level singleton
AI_CLIENT = None
