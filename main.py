#!/usr/bin/python3
from patch_manager import PatchManager
from package_manager import PackageManager
from context import ContextManager
from candidate_finder import CandidateFinder
from exceptions import GarbageCandidateError

import os
import typer
from rich.console import Console
from rich.prompt import Prompt
import asyncio
import questionary
from agent import Agent
from pathlib import Path
from enum import Enum, auto
import re
import sys

"""
Pipeline:
Per patch,
per hunk,
1. Static Code Analysis
2. AI Draft
3. Diff Generation
4. Action Translation
5. Action Pruning
6. Alignment Generataion
7. Thread Translation
8. Code Weave
9. Post Process
"""

MDIR        = '.metadata'
mephala_app = typer.Typer()
console     = Console()
ctx         = ContextManager()
pkg_mgr     = PackageManager(ctx)
pch_mgr     = PatchManager(ctx)

class HunkApplyStatus(Enum):
  SUCCESS = auto()
  FUZZ = auto()
  NO_FILE = auto()
  FAIL = auto()

class SaveTree:
  def __init__(self, overwrite=False):
    self.walk = [ctx.ctx_dir, MDIR]
    self.overwrite = overwrite

  def to_path(self):
    return os.path.join(*self.walk)

  def step_up(self):
    return self.walk.pop()

  def drilldown(self, into):
    self.walk.append(into)
    os.makedirs(self.to_path(), exist_ok=True)

  def dir_is_empty(self):
    try:
      return not os.listdir(self.to_path())
    except FileNotFoundError:
      return True

  def save_hunk(self, hunk, name="auto.patch"):
    self._safe_save(name, f"{str(hunk)}\n")

  def save_choices(self, candidate_dict, name="choices.txt"):
    content = ""
    for i, c in enumerate(sorted(candidate_dict.values(), key=lambda c: -c.score)):
      content += f"Candidate {i+1} (score {c.score}):\n"
      content += f"path: {c.path_to}\n"
      content += '\n'.join(c.lines)
      content += "\n---\n"
    self._safe_save(name, content)

  def mark_unresolved(self, reason="", name="unresolved.txt"):
    self._safe_save(name, reason)

  def _safe_save(self, filename, content):
    path = os.path.join(self.to_path(), filename)
    if os.path.exists(path) and not self.overwrite:
      print(f"[savetree] SKIP: Would overwrite {path}")
      return
    with open(path, "w") as f:
      f.write(content)
    return path

saver = SaveTree()

def picker(title, options):
  console.print(title)
  for idx, option in enumerate(options, start=1):
    console.print(f"{idx}.{option}")
  choice = Prompt.ask("Pick", choices=[str(i) for i in range(1, len(options) + 1)])
  return options[int(choice) - 1]

def confirm_action():
  return questionary.select(
    "Proceed with this generation?",
    choices=["Yes", "No"]
  ).ask()

##############################################
#               AUTO WIZARD                  #
##############################################
@mephala_app.command("auto_wizard")
def auto_wizard():
  #                        #
  # === (1) User input === #
  #                        #
  upstream_patches = {patch.path_to: patch for patch in pch_mgr.patches}
  patch_path = picker("Pick a patch", list(upstream_patches.keys()))

  saver.drilldown(os.path.splitext(os.path.basename(patch_path))[0])

  applicable_releases = ctx.get_package_homes()
  release = picker("Pick a release", list(applicable_releases.keys()))

  saver.drilldown(release)

  patch = upstream_patches[patch_path]
 
  #                           #
  # === (2) Initial State === #
  #                           #
  # === (a) Patch Parse ===   #
  hunk_dict = {f'{hunk_id}h': hunk for hunk_id, hunk in enumerate(patch.parse_patch_file(), 1)}
  # === (b) Quilt Test ===    #
  patch_apply_result = asyncio.run(pkg_mgr.apply_patch_to(release, patch_path, dry_run=True))
  # === (c) Results Parse === #
  per_hunk_results = parse_quilt_output_by_hunk(patch_apply_result)

  #                          #
  # === (3) Hunk Sorting === #
  #                          #
  for idx, (hunk_id, hunk) in enumerate(hunk_dict.items()):
    result_status, attempted_lineno = per_hunk_results[idx]
    console.print(f"[bold yellow]Hunk {hunk_id}: {result_status.name} (attempted at line {attempted_lineno})[/bold yellow]")
    saver.drilldown(hunk_id)


    if not saver.dir_is_empty():
      console.print(f"[bold yellow]Skipping {hunk_id}[/bold yellow]")
      saver.step_up()
      continue

  
    if result_status == HunkApplyStatus.SUCCESS:
      saver.save_hunk(hunk)
  
    elif result_status == HunkApplyStatus.FUZZ:
      file_path = os.path.join(applicable_releases[release], hunk.filename)
      candidate = CandidateFinder.candidate_from_file_region(
        file_path=file_path,
        start_line=attempted_lineno,
        length=len(hunk.to_b())
      )
      if candidate:
        fuzzed_hunk = fix_hunk_fuzz(hunk, candidate)
        saver.save_hunk(fuzzed_hunk)
      else:
        saver.mark_unresolved(reason="Could not extract candidate for fuzz correction")
 
    elif result_status in (HunkApplyStatus.FAIL, HunkApplyStatus.NO_FILE):
      single = (result_status == HunkApplyStatus.FAIL)
      candidate_dict = CandidateFinder.generate_candidate_dictionary(
        hunk, applicable_releases[release], single=single)
      if candidate_dict:
        best_candidate = max(candidate_dict.values(), key=lambda c: c.score)

        if best_candidate.score < 3:
          saver.mark_unresolved(reason="No high-confidence candidate")
        else:
          try:
            proposal_hunk = apply_backport(hunk, best_candidate, release, patch, applicable_releases)
            saver.save_hunk(proposal_hunk)
            saver.save_choices(candidate_dict)
          except GarbageCandidateError:
            saver.mark_unresolved(reason="Bad candidate selected: resulting patch would be garbage")
      else:
        saver.mark_unresolved(reason="No candidate found for hunk.")

    saver.step_up()
 
  print("AUTO backport completed!")

########################################
#             HELPERS                  #
########################################

def parse_quilt_output_by_hunk(patch_apply_output):
  """
  Returns [(HunkApplyStatus, line_number), ...] in patch hunk order.
  For not-found hunks, line_number = -1
  """
  status_list = []
  import re

  hunk_fail_re = re.compile(r'Hunk #\d+ FAILED at (\d+)\.')
  hunk_fuzz_re = re.compile(r'Hunk #\d+ succeeded at (\d+) with fuzz')
  hunk_success_re = re.compile(r'Hunk #\d+ succeeded at (\d+)')
  no_file_re = re.compile(r'No file to patch.  Skipping patch.')
  hunks_ignored_re = re.compile(r'(\d+) out of (\d+) hunks? ignored')

  lines = patch_apply_output.splitlines()
  idx = 0
  while idx < len(lines):
    line = lines[idx]
    m_fail = hunk_fail_re.search(line)
    m_fuzz = hunk_fuzz_re.search(line)
    m_succ = hunk_success_re.search(line)
    if m_fail:
      status_list.append((HunkApplyStatus.FAIL, int(m_fail.group(1))))
    elif m_fuzz:
      status_list.append((HunkApplyStatus.FUZZ, int(m_fuzz.group(1))))
    elif m_succ:
      status_list.append((HunkApplyStatus.SUCCESS, int(m_succ.group(1))))
    elif no_file_re.search(line):
      # The "N out of N hunks ignored" line comes right after.
      found = False
      lookahead = 0
      while (idx + lookahead < len(lines)) and (lookahead < 3):
        m = hunks_ignored_re.search(lines[idx+lookahead])
        if m:
          n_hunks = int(m.group(1))
          status_list.extend([(HunkApplyStatus.NO_FILE, -1)] * n_hunks)
          found = True
          break
        lookahead += 1
      if not found:
        status_list.append((HunkApplyStatus.NO_FILE, -1))
    idx += 1

  return status_list

def fix_hunk_fuzz(hunk, candidate, fuzz=3):
  """
  Replace the top/bottom 'fuzz' context lines in hunk.to_b() with those from candidate.lines.
  Returns a new Hunk with updated delta.
  """
  from common import DiffLine
  from enums import LineType
  from hunk import Hunk

  hunk_b = hunk.to_b()    # List of DiffLine objects: intended "after" lines
  cand_lines = candidate.lines  # List of strings from the actual file

  n = min(fuzz, len(hunk_b) // 2, len(cand_lines) // 2)

  # Safety: if there's not enough context in candidate, just use what there is
  # Create new DiffLine objects for the context lines
  fixed_lines = []

  # Top context from candidate
  fixed_lines.extend([DiffLine(text, LineType.NOCHANGE) for text in cand_lines[:n]])

  # Middle lines from hunk's own new content (skipping n from top/bottom)
  fixed_lines.extend(
    hunk_b[n:len(hunk_b)-n if n else None]
  )

  # Bottom context from candidate
  if n > 0:
    fixed_lines.extend([DiffLine(text, LineType.NOCHANGE) for text in cand_lines[-n:]])

  # Rebuild Hunk (with the same filename, and replaced delta)
  new_hunk = Hunk(hunk.filename)
  new_hunk.delta = fixed_lines
  new_hunk.top = hunk.top

  return new_hunk

def apply_backport(hunk, candidate, release, patch, applicable_releases):
  agent = Agent()
  draft = draft_backport(agent, hunk, candidate, patch.cve_record)
  return hunk.create_backport(
    candidate,
    draft,
    os.path.relpath(candidate.path_to, applicable_releases[release])
  )

#################################
#################################
#################################

@mephala_app.command()
def wizard():
  # Patch Selection
  upstream_patches = {patch.path_to: patch for patch in pch_mgr.patches}
  patch_path = picker("Pick a patch", list(upstream_patches.keys()))

  saver.drilldown(os.path.splitext(os.path.basename(patch_path))[0])

  # Release Selection
  applicable_releases = ctx.get_package_homes()
  release = picker("Pick a release", list(applicable_releases.keys()))

  saver.drilldown(release)

  breakout_condition = True
  while breakout_condition:
    patch = upstream_patches[patch_path]
    hunk_dict = {f'{hunk_id}h': hunk for hunk_id, hunk in enumerate(patch.parse_patch_file(), 1)}

    console.print(asyncio.run(pkg_mgr.apply_patch_to(release, patch_path, dry_run=True)))
    hunk_id = picker("Pick a hunk", list(hunk_dict.keys()))

    saver.drilldown(hunk_id)

    hunk = hunk_dict[hunk_id]

    # Candidate Selection #
    candidate_dict = CandidateFinder.generate_candidate_dictionary(hunk, applicable_releases[release])

    console.print('=== Original Hunk Code ===')
    for line in hunk.delta:
      console.print(line)
    console.print('======')
    cids = questionary.checkbox("Pick the best candidate or candidates",
                                choices=list(candidate_dict.keys())
                               ).ask()
    for cid in cids:
      candidate = candidate_dict[cid]
      agent = Agent()
      console.print(candidate.path_to)
      satisfied = False

      while not satisfied:
        draft = draft_backport(agent, hunk, candidate, patch.cve_record)
        while True:
          console.print(draft)
          if confirm_action() == "Yes":
            break

          rationale = questionary.text("What's wrong with it?").ask()
          draft = draft_backport(agent,
                                 hunk,
                                 candidate,
                                 patch.cve_record,
                                 revision=rationale)

        proposal_hunk = hunk.create_backport(candidate, 
                                             draft, 
                                             os.path.relpath(candidate.path_to, applicable_releases[release]))

        console.print('\n[bold cyan]=== Proposal Backport Hunk ===[/bold cyan]')
        console.print(str(proposal_hunk))

        backport_path = os.path.join(saver.to_path(), cid)
        with open(backport_path, "w") as f:
          f.write(f"{str(proposal_hunk)}\n")
        console.print(f"[green]Backport saved to {backport_path}[/green]")
        satisfied = True
        
        # Test patch application immediately
        console.print("[yellow]Testing patch application with apply_patch_to...[/yellow]")
        result = asyncio.run(pkg_mgr.apply_patch_to(release, backport_path, dry_run=True))
        console.print(f"[cyan]Patch application test result:[/cyan]\n{result}")

#        if questionary.confirm(
#          "Are you satisfied with this proposal and want to save it?"
#        ).ask():
#          backport_path = os.path.join(saver.to_path(), cid)
#          with open(backport_path, "w") as f:
#            f.write(str(proposal_hunk))
#          console.print(f"[green]Backport saved to {backport_path}[/green]")
#          satisfied = True
#        else:
#          console.print("[yellow]Regenerating proposal...[/yellow]")

    break

def extension_to_language(extension):
  # Dictionary mapping file extensions to programming languages
  ext_to_lang = {
    '.py': 'python',
    '.rb': 'ruby',
    '.js': 'javascript',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'c++',
    '.cs': 'c#',
    '.php': 'php',
    '.html': 'html',
    '.css': 'css',
    '.rs': 'rust',
    '.go': 'go',
    '.kt': 'kotlin',
    '.swift': 'swift',
    '.sh': 'shell script',
    '.ts': 'typescript',
    '.pl': 'perl',
    '.r': 'r',
    '.scala': 'scala',
    '.hs': 'haskell',
    '.lua': 'lua',
    '.ml': 'ocaml',
    '.jl': 'julia',
    # Add more file extensions and corresponding languages as needed
  }
  
  # Convert the extension to a language name
  return ext_to_lang.get(extension.lower(), 'unknown or unsupported language')

def draft_backport(agent, hunk, candidate, cve_record, revision=None):
  pattern = extension_to_language(Path(candidate.path_to).suffix)

  if revision:
    prompt = f'Can you revise your draft considering the following?\n{revision}'
    return agent.ask(prompt, pattern=pattern)

  return agent.ask(f'''
  Imagine you had a hunk of a patch, in unified diff format. 
  It was generated against version X of a package. 
  The hunk looks like this:
  {hunk}
  
  Imagine this patch hunk was intended to resolve the following CVE:
  {cve_record.cve}:
  {cve_record.desc}
  
  Now, imagine you need to backport this hunk to a different version of the package. 
  But you don't know exactly where the code should go! 
  After a brief static code analysis, you uncover several places the patch
  code could apply if it were modified. 
  This is one of those places to potentially apply the patch:
  {candidate.path_to}:
  {candidate.code_str()}
  Now, imagine we assumed this was the correct place to apply the patch. 
  Your role is simply to determine what the code would look like
  if the patch were applied here. In other words, draft a backport of the patch
  fitting this version.

  Make sure whitespace and indentation match the code we're backporting TO. 
  Don't left-justify. 
  ''', pattern=pattern)


def main():
  console.print("Welcome!")
  mephala_app()
    
if __name__=='__main__':
  main()
