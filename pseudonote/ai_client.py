# -*- coding: utf-8 -*-
"""
AI client for PseudoNote - handles communication with AI providers.
"""

import threading
import functools
import time

import ida_kernwin

from pseudonote.qt_compat import openai, httpx, anthropic, genai
from pseudonote.config import CONFIG, LOGGER


# Global state for UI to check
_ai_busy_count = 0
AI_CANCEL_REQUESTED = False

class AIBusyStatus:
    def __bool__(self):
        return _ai_busy_count > 0
    def __int__(self):
        return _ai_busy_count
    def __repr__(self):
        return str(_ai_busy_count > 0)
    def __eq__(self, other):
        if isinstance(other, bool):
            return (_ai_busy_count > 0) == other
        return super().__eq__(other)

AI_BUSY = AIBusyStatus()

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
        timeout = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)
        http_client = httpx.Client(proxy=self.config.proxy, timeout=timeout) if self.config.proxy else httpx.Client(timeout=timeout)

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

    def query_model_async(self, prompt, callback, additional_options=None, on_chunk=None, on_status=None):
        """
        Query AI model asynchronously. 
        on_chunk(text) is called for each streamed part if streaming is supported.
        on_status(count, text) is called for status updates.
        callback(response, finish_reason) is called when finished.
        """
        global AI_BUSY, AI_CANCEL_REQUESTED
        if additional_options is None: additional_options = {}

        def thread_target():
            global _ai_busy_count, AI_CANCEL_REQUESTED
            _ai_busy_count += 1
            AI_CANCEL_REQUESTED = False
            full_content = ""
            finish_reason = "stop"
            
            try:
                LOGGER.log(f"Sending request to {self.provider} (Streaming: {on_chunk is not None})...")
                
                # Update UI that we are sending the request
                if on_status:
                    try:
                        ida_kernwin.execute_sync(lambda: on_status(0, "Sending request..."), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                    except: pass

                if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                    if not self.client: raise ValueError(f"Client for {self.provider} not initialized.")

                    if isinstance(prompt, list):
                        messages = prompt
                    else:
                        messages = [{"role": "user", "content": prompt}]
                    model = self.config.model
                    if self.provider == "ollama" and self.config.ollama_model: model = self.config.ollama_model
                    if self.provider == "custom" and self.config.custom_model: model = self.config.custom_model

                    valid_args = {"model": model, "messages": messages}
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

                    if on_chunk:
                        valid_args["stream"] = True
                        stream = self.client.chat.completions.create(**valid_args)
                        
                        buffer = ""
                        last_update = time.time()
                        
                        for chunk in stream:
                            if AI_CANCEL_REQUESTED: 
                                finish_reason = "cancelled"
                                break
                            
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if not delta: continue
                            
                            content = getattr(delta, 'content', "") or ""
                            # Reasoning fallback for stream
                            reasoning = getattr(delta, 'reasoning_content', "") or getattr(delta, 'reasoning', "") or ""
                            if not content and reasoning: content = reasoning
                            
                            if content:
                                full_content += content
                                buffer += content
                                # Buffer updates to keep IDA thread responsive
                                if time.time() - last_update > 0.05 or len(buffer) > 100:
                                    def _do_update(txt): on_chunk(txt)
                                    ida_kernwin.execute_sync(functools.partial(_do_update, buffer), ida_kernwin.MFF_WRITE)
                                    buffer = ""
                                    last_update = time.time()
                            
                            fin = getattr(chunk.choices[0], 'finish_reason', None)
                            if fin: finish_reason = fin
                        
                        # Flush remaining
                        if buffer:
                            ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                    else:
                        response = self.client.chat.completions.create(**valid_args)
                        msg = response.choices[0].message if response.choices else None
                        if msg:
                            full_content = getattr(msg, 'content', "") or ""
                            reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                            if not full_content.strip() and reasoning.strip(): full_content = reasoning
                            finish_reason = getattr(response.choices[0], 'finish_reason', 'stop')
                        else:
                            full_content = ""

                elif self.provider == "anthropic":
                     if not self.client: raise ValueError("Anthropic client not initialized.")
                     
                     if isinstance(prompt, list):
                         messages = prompt
                     else:
                         messages = [{"role": "user", "content": prompt}]
                         
                     max_toks = additional_options.get("max_completion_tokens", 4096)
                     if on_chunk:
                         with self.client.messages.stream(
                             model=self.config.model,
                             max_tokens=max_toks,
                             messages=messages
                         ) as stream:
                             buffer = ""
                             last_update = time.time()
                             for text in stream.text_stream:
                                 if AI_CANCEL_REQUESTED:
                                     finish_reason = "cancelled"
                                     break
                                 full_content += text
                                 buffer += text
                                 if time.time() - last_update > 0.05 or len(buffer) > 100:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                                     buffer = ""
                                     last_update = time.time()
                             if buffer:
                                 ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                             
                             msg = stream.get_final_message()
                             finish_reason = getattr(msg, 'stop_reason', 'stop')
                             if finish_reason == 'max_tokens': finish_reason = 'length'
                     else:
                        message = self.client.messages.create(
                            model=self.config.model,
                            max_tokens=max_toks,
                            messages=messages
                        )
                        full_content = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])
                        finish_reason = getattr(message, 'stop_reason', 'stop')
                        if finish_reason == 'max_tokens': finish_reason = 'length'

                elif self.provider == "gemini":
                     if not self.client: raise ValueError("Gemini not configured.")
                     model = genai.GenerativeModel(self.config.model)
                     
                     generation_config = {}
                     if "max_completion_tokens" in additional_options:
                         generation_config["max_output_tokens"] = additional_options["max_completion_tokens"]
                     if "temperature" in additional_options:
                         generation_config["temperature"] = additional_options["temperature"]
                     if "top_p" in additional_options:
                         generation_config["top_p"] = additional_options["top_p"]

                     if isinstance(prompt, list):
                         history = []
                         for m in prompt:
                             role = m.get("role", "user")
                             if role == "assistant": role = "model"
                             if role == "system": continue 
                             history.append({"role": role, "parts": [m.get("content", "")]})
                         
                         chat = model.start_chat(history=history[:-1])
                         if on_chunk:
                             response_stream = chat.send_message(history[-1]["parts"][0], stream=True, generation_config=generation_config)
                             buffer = ""
                             last_update = time.time()
                             for chunk in response_stream:
                                 if AI_CANCEL_REQUESTED:
                                     finish_reason = "cancelled"
                                     break
                                 full_content += chunk.text
                                 buffer += chunk.text
                                 if time.time() - last_update > 0.05 or len(buffer) > 100:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                                     buffer = ""
                                     last_update = time.time()
                             if buffer:
                                 ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                             
                             # Gemini finish reason
                             try:
                                 fr = response_stream.last.candidates[0].finish_reason
                                 if fr == 2: finish_reason = "length" # 2 is MAX_TOKENS in some versions of the SDK
                                 else: finish_reason = "stop"
                             except: finish_reason = "stop"
                         else:
                            response = chat.send_message(history[-1]["parts"][0], generation_config=generation_config)
                            full_content = response.text
                            try:
                                fr = response.candidates[0].finish_reason
                                if fr == 2: finish_reason = "length"
                                else: finish_reason = "stop"
                            except: finish_reason = "stop"
                     else:
                         if on_chunk:
                             response_stream = model.generate_content(prompt, stream=True, generation_config=generation_config)
                             buffer = ""
                             last_update = time.time()
                             for chunk in response_stream:
                                 if AI_CANCEL_REQUESTED:
                                     finish_reason = "cancelled"
                                     break
                                 full_content += chunk.text
                                 buffer += chunk.text
                                 if time.time() - last_update > 0.05 or len(buffer) > 100:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                                     buffer = ""
                                     last_update = time.time()
                             if buffer:
                                 ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_WRITE)
                             
                             try:
                                 fr = response_stream.last.candidates[0].finish_reason
                                 if fr == 2: finish_reason = "length"
                                 else: finish_reason = "stop"
                             except: finish_reason = "stop"
                         else:
                             response = model.generate_content(prompt, generation_config=generation_config)
                             full_content = response.text
                             try:
                                 fr = response.candidates[0].finish_reason
                                 if fr == 2: finish_reason = "length"
                                 else: finish_reason = "stop"
                             except: finish_reason = "stop"


                LOGGER.log(f"Received response from {self.provider} ({len(full_content)} chars, reason: {finish_reason}).")

                # Wrap callback to ensure we pass response AND finish_reason
                def wrapped_callback(resp, reason):
                    import inspect
                    try:
                        # Extract the actual function if it's a partial
                        base_func = callback.func if isinstance(callback, functools.partial) else callback
                        sig = inspect.signature(base_func)
                        
                        # Check if it accepts finish_reason or **kwargs
                        has_reason = "finish_reason" in sig.parameters
                        has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                        
                        if has_reason or has_kwargs:
                            callback(response=resp, finish_reason=reason)
                        else:
                            callback(response=resp)
                    except Exception:
                        # Fallback for objects that don't support inspection
                        try: callback(response=resp, finish_reason=reason)
                        except: callback(response=resp)

                ida_kernwin.execute_sync(
                    functools.partial(wrapped_callback, resp=full_content, reason=finish_reason),
                    ida_kernwin.MFF_WRITE
                )
            except Exception as e:
                LOGGER.log(f"AI Error ({self.provider}): {e}")
                ida_kernwin.execute_sync(
                    functools.partial(callback, response=None),
                    ida_kernwin.MFF_WRITE
                )
            finally:
                _ai_busy_count -= 1

        threading.Thread(target=thread_target).start()

    def test_connection(self):
        prompt = "Reply with exactly: pong"
        try:
            if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                if not self.client: return False, "Client not initialized."
                
                model = self.config.model
                if self.provider == "ollama" and self.config.ollama_model: model = self.config.ollama_model
                if self.provider == "custom" and self.config.custom_model: model = self.config.custom_model

                is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                valid_args = {"model": model, "messages": [{"role": "user", "content": prompt}]}
                
                if is_reasoning:
                    valid_args["max_completion_tokens"] = 128
                else:
                    valid_args["max_tokens"] = 30
                    valid_args["temperature"] = 0

                response = self.client.chat.completions.create(**valid_args)
                
                if not response.choices:
                    LOGGER.log(f"Test Connection: No choices. Full response: {response}")
                    return False, f"Connected but API returned no choices. (Model: {model})"

                msg = response.choices[0].message
                content = getattr(msg, 'content', "") or ""
                reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                refusal = getattr(msg, 'refusal', None)

                # Any valid response with choices = connection works.
                # Empty content can be a model quirk (e.g. some o1/o3 variants) — still counts as success.
                if refusal:
                    return False, f"Connected but model refused request: {refusal}"

                finish_reason = getattr(response.choices[0], 'finish_reason', None)
                if content.strip() or reasoning.strip():
                    return True, f"Connection successful! Model: {model}"

                # Got a valid response object but empty content — still a live connection
                LOGGER.log(f"Test Connection: Got valid response with empty content (finish_reason={finish_reason}). "
                           f"Full message: {msg}")
                return True, (f"Connection successful! (Model '{model}' replied with empty content — "
                              f"this is normal for some reasoning models. finish_reason={finish_reason})")

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
