#!/usr/bin/python3

import json
from openai import OpenAI
import asyncio
import tiktoken
import yaml
import os

class Agent:

  def __init__(self, conf_path=".gpt-conf", model_override=None):

    self.home_dir = os.path.dirname(os.path.abspath(__file__))
    self.ctx_dir  = os.getcwd()

    with open(f"{self.home_dir}/{conf_path}", 'r') as f:
      conf = json.load(f)
      self.model = model_override or conf['MODEL']
      self.api_key = conf['API_KEY']

    self.client = OpenAI(api_key=self.api_key)
    self.chain = []

  def raw_ask(self, prompt, new_chain=False):
    if new_chain:
      self.clear_chain()

    self.chain.append(Message(prompt).out())

    completion = self.client.chat.completions.create(model=self.model, messages=self.chain)

    response = completion.choices[-1].message
    self.chain.append(Message(response.content, role=response.role).out())    

    return self.chain[-1]['content']

  def ask(self, prompt, format_str, new_chain=False, repeat=True):
    self.raw_ask(prompt, new_chain=new_chain)
    if repeat:
      self.correct()
    return self.yaml_string_to_dict(self.yaml_clamp(format_str))

  def clear_chain(self):
    self.chain = []

  def yaml_clamp(self, format_str):
    # Load format file as a string
    #with open(format_file_path, 'r') as f:
    #    format_string = f.read()

    last_message = self.chain[-1]['content']

    # Prompt GPT to rewrite the last_message in format_string
    formatted_output = self.raw_ask(f"I need structured output! Please have the contents of your last message match the following YAML format: \n\n{format_str}\n\nDon't say anything else so I can parse predictably!", new_chain=False)

    return formatted_output

  def strip(self):
    return self.raw_ask(f"Please respond with only the structured data and nothing else. Do not include ```yaml or the like.")

  def scold(self):
    return self.raw_ask(f"That wasn't what I asked for. Do it again.")

  def correct(self):
    return self.raw_ask(f"Your first answer may contain inaccuracies. Please repeat the exercise.")

  def yaml_file_to_dict(self, file_path):
    with open(file_path, 'r') as stream:
      try:
        return yaml.safe_load(stream)
      except yaml.YAMLError as err:
        raise err

  def yaml_string_to_dict(self, yaml_string, retries=0):
    try:
      return yaml.safe_load(yaml_string)
    except Exception as e:
      if retries == 0:
        self.strip()
        self.yaml_string_to_dict(yaml_string, retries=1)
      elif retries == 1:
        self.scold()
        self.yaml_string_to_dict(yaml_string, retries=2)
      else:
        print("Error parsing YAML string: ", e)

class Message:

  def __init__(self, content, role='user'):
    self.role = role
    self.content = content

  def out(self):
    return { 'role': self.role, 'content': self.content }

