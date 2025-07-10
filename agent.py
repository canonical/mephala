#!/usr/bin/python3
import json
import yaml
import re
import os
import logging
from openai import OpenAI

from exceptions import StructuredParseError

logging.basicConfig(level=logging.INFO)

class Agent:
  def __init__(self, conf_path=".gpt-conf", model_override=None):
    self.home_dir = os.path.dirname(os.path.abspath(__file__))
    self.ctx_dir = os.getcwd()

    with open(f"{self.home_dir}/{conf_path}", "r") as f:
      conf = json.load(f)
      self.model = model_override or conf["MODEL"]
      self.api_key = conf["API_KEY"]

    self.client = OpenAI(api_key=self.api_key)
    self.chain = []

  def ask(self, prompt, pattern=None, output_format=None, return_key=None):
    self._make_request(prompt)
    if output_format:
      parsed = self.format_completion(output_format)
      return parsed if return_key is None else parsed.get(return_key)
    return self._filter_output(pattern)

  def format_completion(self, output_format):
    """
    Ask the model to restate its previous answer strictly in YAML.
    Tries JSON first, then YAML, then YAML with auto-quoting of
    bare scalars (fixes @parser-style tokens).
    """
    self._make_request(
      "Please convert your answer to the following YAML format. "
      "Quote every string:\n"
      f"{output_format}"
    )
    raw = self._extract_block(self.chain[-1]["content"])

    # 1. JSON fast path
    try:
      return json.loads(raw)
    except json.JSONDecodeError:
      pass

    # 2. YAML
    try:
      data = yaml.safe_load(raw)
      return self._coerce_numbers(data)
    except yaml.YAMLError:
      logging.warning("First YAML parse failed, trying auto-quote …")
      fixed = self._auto_quote_scalars(raw)
      try:
        data = yaml.safe_load(fixed)
        return self._coerce_numbers(data)
      except yaml.YAMLError as err:
        logging.error(f"Structured parse failed:\n{raw}\n{err}")
        raise StructuredParseError from err

  def _coerce_numbers(self, obj):
    """
    Recursively convert strings that are purely digits into ints.
    """
    if isinstance(obj, dict):
      return {k: self._coerce_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
      return [self._coerce_numbers(v) for v in obj]
    if isinstance(obj, str) and obj.isdigit():
      return int(obj)
    return obj

  def _make_request(self, prompt):
    logging.info("Prompting")
    self.chain.append(Message(prompt).to_dict())
    resp = self.client.chat.completions.create(
      model=self.model,
      messages=self.chain,
      temperature=0.5,
    )
    msg = resp.choices[-1].message
    self.chain.append(Message(msg.content, role=msg.role).to_dict())
    return msg.content

  def _extract_block(self, text, langs="yaml|json"):
    """
    Return first ```yaml ...``` or ```json ...``` fenced block.
    """
    m = re.search(rf"```(?:{langs})\n(.*?)\n```", text, re.DOTALL)
    if not m:
      raise StructuredParseError("No fenced YAML/JSON block found")
    return m.group(1).strip()

  def _auto_quote_scalars(self, block: str) -> str:
    """
    Quote tokens that start with @ or contain spaces / colons so that
    YAML stops treating them as bare scalars.
    """
    # inside flow seq [...]
    block = re.sub(r"\[([^\]]*@[^\]]*)\]", lambda m: f'[\"{m.group(1)}\"]', block)
    # mapping scalars
    block = re.sub(r":\s*(@[^\s#]+)", r': "\1"', block)
    return block

  def _filter_output(self, pattern):
    last_resp = self.chain[-1]["content"]
    logging.info(f"Response: {last_resp}")
    if pattern:
      return self._extract_text(last_resp, pattern)
    return last_resp

  def _extract_text(self, text, pattern):
    regex = fr"```{pattern}\n(.*?)\n```"
    m = re.search(regex, text, re.DOTALL)
    if not m:
      raise ValueError(f"Pattern {pattern} not found in text.")
    return m.group(1)


class Message:
  def __init__(self, content, role="user"):
    self.role = role
    self.content = content

  def to_dict(self):
    return {"role": self.role, "content": self.content}

