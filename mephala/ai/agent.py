"""
mephala.ai.agent
----------------
Thin, reusable wrapper around the OpenAI chat completions API.

Key points
~~~~~~~~~~
• Singleton: every call to Agent() returns the same object – the HTTP
  connection pool is shared and rate-limits are respected globally.
• Session isolation:  Agent.new_session() clears message history so
  different callers do not bleed context into one another.
• Zero outward dependencies on the rest of Mephala except for the
  StructuredParseError defined in core.exceptions.

Environment / config resolution order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Explicit kwargs when instantiating Agent(model=…, api_key=…)
2. Environment variables
      OPENAI_API_KEY
      OPENAI_MODEL
3. JSON file “.gpt-conf” sitting next to this agent.py
      { "API_KEY": "...", "MODEL": "gpt-4o-mini" }
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from openai import OpenAI

from mephala.core.exceptions import StructuredParseError

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler()) 


# ════════════════════════════════════════════════════════════════════════
#                               SINGLETON
# ════════════════════════════════════════════════════════════════════════
class _SingletonMeta(type):
    _instance: "Agent | None" = None

    def __call__(cls, *args, **kwargs) -> "Agent":  # type: ignore
        if cls._instance is None:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


# ════════════════════════════════════════════════════════════════════════
#                                AGENT
# ════════════════════════════════════════════════════════════════════════
class Agent(metaclass=_SingletonMeta):
    # ------------------------------------------------------------------ init
    def __init__(
        self,
        *,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        conf_path: str = ".gpt-conf",
    ) -> None:
        if getattr(self, "_init_done", False):       # second call – ignore
            return

        self._load_config(conf_path, model, api_key)
        self.client = OpenAI(api_key=self.api_key)
        self._messages: List[Dict[str, str]] = []
        self._init_done = True
        log.debug("OpenAI Agent initialised with model %s", self.model)

    # ---------------------------------------------------------------- public
    # ---- session control
    def new_session(self) -> None:
        """Clear the running message chain so the next `ask` starts fresh."""
        self._messages.clear()

    # ---- main API
    def ask(
        self,
        prompt: str,
        *,
        pattern: Optional[str] = None,
        output_format: Optional[str] = None,
        return_key: str | None = None,
        temperature: float = 0.5,
    ) -> Any:
        """
        • If `output_format` is given, the answer is expected to be
          YAML/JSON and is parsed + type-coerced.
        • Otherwise, optionally extract a ```<pattern> fenced code block.
        """
        self._make_request(prompt, temperature=temperature)

        # structured-answer path
        if output_format:
            parsed = self._format_completion(output_format)
            return parsed if return_key is None else parsed.get(return_key)

        # free-form answer, maybe fenced code extraction
        return self._filter_output(pattern)

    # ---------------------------------------------------------------- internals
    # ---- configuration
    def _load_config(self, conf_path: str, model: str | None, api_key: str | None):
        home = Path(__file__).resolve().parent
        conf_file = home / conf_path
        conf_json = {}
        if conf_file.exists():
            with open(conf_file, "r") as fp:
                conf_json = json.load(fp)

        self.model = (
            model
            or os.getenv("OPENAI_MODEL")
            or conf_json.get("MODEL")
            or "gpt-4o"
        )
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or conf_json.get("API_KEY")
        if not self.api_key:
            raise RuntimeError("OpenAI API key not provided (env or .gpt-conf)")

    # ---- chat plumbing
    def _make_request(self, prompt: str, *, temperature: float = 0.5) -> str:
        log.info("[Agent] Prompting model %s (len=%d)", self.model, len(prompt))
        self._messages.append({"role": "user", "content": prompt})
        resp = self.client.chat.completions.create(
            model=self.model, messages=self._messages, temperature=temperature
        )
        msg = resp.choices[-1].message
        self._messages.append({"role": msg.role, "content": msg.content})
        return msg.content

    # ---- structured answer helpers
    def _format_completion(self, output_format: str):
        # ask for explicit YAML re-statement
        self._make_request(
            "Please convert your previous answer to *strict YAML* "
            "(quote every string) with the following schema:\n"
            f"{output_format}"
        )
        raw = self._extract_code_block(self._messages[-1]["content"])

        # try JSON, then YAML, then YAML with auto-quoting
        for loader in (json.loads, yaml.safe_load, lambda t: yaml.safe_load(self._auto_quote_scalars(t))):
            try:
                data = loader(raw)
                return self._coerce_numbers(data)
            except Exception:  # noqa: BLE001
                continue

        log.error("Structured parse failed:\n%s", raw)
        raise StructuredParseError("Could not parse model response as YAML/JSON")

    # ---- misc helpers
    @staticmethod
    def _coerce_numbers(obj):
        if isinstance(obj, dict):
            return {k: Agent._coerce_numbers(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [Agent._coerce_numbers(v) for v in obj]
        if isinstance(obj, str) and obj.isdigit():
            return int(obj)
        return obj

    @staticmethod
    def _extract_code_block(text: str, langs: str = "yaml|json") -> str:
        m = re.search(rf"```(?:{langs})\n(.*?)\n```", text, re.DOTALL)
        if not m:
            raise StructuredParseError("No fenced YAML/JSON block found")
        return m.group(1).strip()

    @staticmethod
    def _auto_quote_scalars(block: str) -> str:
        block = re.sub(r"\[([^\]]*@[^\]]*)\]", lambda m: f'["{m.group(1)}"]', block)
        block = re.sub(r":\s*(@[^\s#]+)", r': "\1"', block)
        return block

    # ---- free-form output helpers
    def _filter_output(self, pattern: Optional[str]):
        last = self._messages[-1]["content"]
        log.info("Model response: %s", last)
        if pattern:
            return self._extract_code_block(last, langs=pattern)
        return last
