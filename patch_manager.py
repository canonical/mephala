#!/usr/bin/python3

from common import Patch, HunkState
from agent import Agent
import os
import glob
import json

# Control over representations of patches, staging and applying them. 
# Needs information about what package to apply a patch to, or to triage
# a patch for. 
class PatchManager(Agent):

  PATCHES_DIR = 'patches'

  def __init__(self, context):
    Agent.__init__(self)
    self.ctx = context

    assert self.ctx.value_exists('patch_links')
    links = self.ctx.get_patch_links()
    self.patch_dir = os.path.join(self.ctx_dir, self.PATCHES_DIR)
    self.patch_files = glob.glob(os.path.join(self.patch_dir, '*.patch')) 
    self.patches = [Patch(pf, links[os.path.basename(pf)]) for pf in self.patch_files] 

    assert self.ctx.value_exists('package_homes')
    self.test()
    #print("State before patch:")
    #self.scan_packages(HunkState.INITIAL)
    #print("State after patch:")
    #self.scan_packages(HunkState.FINAL)

  def test(self):
    assert self.ctx.value_exists('cve_descriptions')
    descs = self.ctx.get_cve_descriptions()

    clinks = self.ctx.get_candidate_links() if self.ctx.value_exists('candidate_links') else {}

    for patch in self.patches:
      print('~~~', patch.patch_file, '~~~')
      for release, package_home in self.ctx.get_package_homes().items():
        print(release)
        if release =='xenial':
          patch.fit(package_home, descs[patch.cve], metadata=clinks.get(release, {}).get(os.path.basename(patch.patch_file), {}))
        #break # bionic test

  def scan_packages(self, hunk_state):
    for patch in self.patches:
      print('~~~', patch.patch_file, '~~~')
      for hunk in patch.hunks:
        print('#', hunk.filename, '#')
        print(hunk.state(hunk_state)) 
        for release, package_home in self.ctx.get_package_homes().items():
          print(release)
          candidates = hunk.compare_to(package_home, hunk_state)
          for c in candidates:
            print(f"### Candidate {c.id} ###")
            print('Matched')
            for p in c.patterns:
              print(p.locations, f"\t{p.match_text}")
            print('~~~')
            print(f"Earliest hit: {c.earliest_hit}", f"Latest hit: {c.latest_hit}", f"Hit score: {c.score}", '\n~~~\n', '\n'.join(c.context), '\n~~~\n')
            print('######')
          break # bionic test

def main():
  patcher = Patcher()
  for patch in patcher.patches:
    print(patch.patch_file)
    for hunk in patch.hunks:
      print(hunk.filename)
      print(''.join(hunk.delta))

if __name__=='__main__':
  main() 
