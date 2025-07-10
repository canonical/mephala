#!/usr/bin/python3
import json
import os
from agent import Agent
import yaml

class ContextManager(Agent):

  def __init__(self, driver_conf="metadata.yaml", env_conf=".env-conf", mode='w'):
    Agent.__init__(self)
    self.driver_conf_path = os.path.join(self.ctx_dir, driver_conf)
    self.stored_metadata = self.load_metadata()
    self.mode = mode

    with open(os.path.join(self.home_dir, env_conf), 'r') as f:
      conf = json.load(f)
      self.supported_releases = conf['release_list']
      self.package_workspace  = conf['package_workspace']
      self.uct                = conf['ubuntu-cve-tracker']

    # Declare the getters programmatically
    for key in self.stored_metadata.keys():
      self.declare_getter(key)

  def load_metadata(self):
    with open(self.driver_conf_path, 'r') as stream:
      try:
        return yaml.safe_load(stream)
      except yaml.YAMLError as err:
        raise err
      
  def save(self, key, value):
    if self.mode == 'r':
      raise Exception('*slaps hand away*')
    self.stored_metadata[key] = value
    self.save_metadata()

  def save_metadata(self):
    with open(self.driver_conf_path, 'w') as f:
      yaml.dump(self.stored_metadata, f)

  def declare_getter(self, key):
    def getter(self):
      # Reload the contents of the file before returning a value
      self.stored_metadata = self.load_metadata()
      return self.stored_metadata.get(key)
        
    # Set the method to the class
    setattr(self.__class__, 'get_{}'.format(key), getter)

  def value_exists(self, key):
    return key in self.stored_metadata

  def values_exist(self, *keys):
    return all([key in self.stored_metadata for key in keys])

def main():
  mgr = ContextManager()
  for obj in mgr.stored_metadata:
    for k,v in obj.items():
      print(k,v)
  print(mgr.supported_releases)
  print(mgr.package_workspace)

if __name__=='__main__':
  main()
