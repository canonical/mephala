#!/usr/bin/python3

from common import Patch, HunkState, CVERecord
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

    assert self.ctx.values_exist('patch_links', 'package_homes', 'cve_descriptions')
    links = self.ctx.get_patch_links()
    descs = self.ctx.get_cve_descriptions()

    self.patch_dir = os.path.join(self.ctx_dir, self.PATCHES_DIR)
    self.patch_files = glob.glob(os.path.join(self.patch_dir, '*.patch')) 
    self.patches = []
    for patch_file in self.patch_files:
      cve_id = links[os.path.basename(patch_file)]
      self.patches.append(Patch(CVERecord(cve_id, descs[cve_id]), 'upstream', path_to=patch_file))

    self.test()

  def test(self):

    clinks = self.ctx.get_candidate_links() if self.ctx.value_exists('candidate_links') else {}

    for patch in self.patches:
      print('~~~', patch.path_to, '~~~')
      for release, package_home in self.ctx.get_package_homes().items():
        print(release)
        if release =='xenial':
          adjusted_patch = Patch(patch.cve_record, 
                                 release, 
                                 fit_to=patch.with_metadata(clinks.get(release, {}).get(os.path.basename(patch.path_to), {})))
          print(adjusted_patch)
          #patch.fit(package_home, descs[patch.cve], metadata=clinks.get(release, {}).get(os.path.basename(patch.patch_file), {}))
        #break # bionic test


def main():
  patcher = Patcher()
  for patch in patcher.patches:
    print(patch.patch_file)
    for hunk in patch.hunks:
      print(hunk.filename)
      print(''.join(hunk.delta))

if __name__=='__main__':
  main() 
