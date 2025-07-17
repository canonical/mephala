from enums import HunkState, LineType, ActionType
from agent import Agent
from common import Pattern, Candidate, DiffLine, Action
from exceptions import GarbageCandidateError, ProcessingException

from intervaltree import IntervalTree
from fuzzywuzzy import fuzz

import logging
import os
import sys
import textwrap
import difflib

logging.basicConfig(level=logging.INFO)

def dict_str(d):
  return '\n'.join([f'{k}:\n{v}' for k,v in d.items()])

class Hunk:

  KILL_THRESHOLD = 4
  MARGIN = 3

  # This is set heuristically. 
  PARTIAL_MATCH_SCORE = 30
  NEAR_MATCH_SCORE    = 90
  PERFECT_MATCH_SCORE = 100 

  def __init__(self, filename, delta=[]):
    self.filename = filename
    self.delta = []
    self.top = None
    #self.raw_delta = delta
    #self.delta = self.parse_delta()

  def __str__(self):
    start = self.top if self.top else ''
    filename = self.filename if self.filename else 'unknown'
    a_file = f"a/{filename}"
    b_file = f"b/{filename}"
    file_header = f"--- {a_file}\n+++ {b_file}"
    header = f"@@ -{start},{len(self.to_a())} +{start},{len(self.to_b())} @@"
    body = '\n'.join([str(line) for line in self.delta])
    return f"{file_header}\n{header}\n{body}"

  @classmethod
  def from_diff_lines(cls, lines, filename=None):
    delta = []
    auto_filename = filename
  
    for line in lines:
      # Optionally parse filename from diff headers
      if line.startswith('---') or line.startswith('+++'):
        if not auto_filename:
          try:
            auto_filename = '/'.join(line.split(' ')[1].split('/')[1:]).strip()
          except Exception:
            auto_filename = None
        continue
      elif line.startswith('@@'):
        # Normally header, could extract top line number if needed
        continue
      elif line.startswith('+'):
        delta.append(DiffLine(line[1:], LineType.INSERTION))
      elif line.startswith('-'):
        delta.append(DiffLine(line[1:], LineType.DELETION))
      else:
        # Context or unchanged line (may start with space or something else)
        ltext = line
        if line and (line[0] == ' '):
          ltext = line[1:]
        delta.append(DiffLine(ltext, LineType.NOCHANGE))
  
    if not auto_filename:
      auto_filename = "<unknown>"
  
    h = cls(auto_filename)
    h.delta = delta
    return h

  def parse_delta(self):
    return [
      DiffLine(
        line[1:],
        LineType.INSERTION if line and line.startswith('+') 
        else LineType.DELETION if line and line.startswith('-') 
        else LineType.NOCHANGE
      ) 
      for line in self.raw_delta.split('\n')
    ]

  def trim_delta(self):

    first = next( (i for i, dl in enumerate(self.delta) if dl.line_type != LineType.NOCHANGE), None)
    last  = next( (len(self.delta) - 1 - i for i, dl in enumerate(reversed(self.delta)) if dl.line_type != LineType.NOCHANGE), None) 

    if first is None or last is None:
      raise GarbageCandidateError("Delta contains only NOCHANGE lines; likely an irrelevant candidate region")

    lhs_offset = first - self.MARGIN
    self.delta = self.delta[lhs_offset:last + self.MARGIN + 1]
    self.top += lhs_offset

  def to_a(self):
    return [line for line in self.delta if line.line_type in [LineType.NOCHANGE, LineType.DELETION]]

  def to_b(self):
    return [line for line in self.delta if line.line_type in [LineType.NOCHANGE, LineType.INSERTION]]

  def state(self, during: HunkState):
    if not isinstance(during, HunkState):
      raise TypeError("during should be type 'HunkState'")

    return getattr(self, 'to_a' if during == HunkState.INITIAL else 'to_b')()

  def create_backport(self, candidate, draft, rectified_filename):
  
    # 1. Diff Generation
    logging.info('=== Diff Generation ===')
  
    candidate_lines = candidate.lines  
    min_indent = min((len(line) - len(line.lstrip()) for line in candidate_lines if line.strip()), default=0)
    draft_lines = textwrap.indent(
      textwrap.dedent(draft),
      ' ' * min_indent
    ).splitlines()
  
    diff_lines = list(difflib.unified_diff(candidate_lines, draft_lines))
    logging.info('\n'.join(diff_lines))
  
    # 2. Action Translation
    logging.info('=== Action Translation ===')
    #backported_hunk = Hunk.from_diff_lines(diff_lines, filename=candidate.path_to)
    backported_hunk = Hunk.from_diff_lines(diff_lines, filename=rectified_filename)
    actions = backported_hunk.generate_actions()
    logging.info(f"Actions: {actions}")
  
    # 3. Action Pruning
    logging.info('=== Action Pruning ===')
    action_template = self.generate_actions()
    prune_tpl = {f't.{i}': action for i, action in enumerate(action_template)}
    action_dict = {f'0-{i}': action for i, action in enumerate(actions)}
    delete_list = self.prune_actions(prune_tpl, action_dict)
    for delete_id in delete_list:
      _, idx = delete_id.split('-')
      idx = int(idx)
      if idx < len(actions):
        actions[idx] = None
    pruned_actions = [action for action in actions if action is not None]
  
    # 4. Alignment Generation
    logging.info('=== Alignment Generation ===')
    alignments = self.create_alignments(
      {f'{i}a': action for i, action in enumerate(pruned_actions)},
      candidate
    )
    logging.info(alignments)
  
    # 5. Thread Translation
    logging.info('=== Thread Translation ===')
    thread = sorted(
      [
        {'action': action, 'interval': alignments[f'{i}a']}
        for i, action in enumerate(pruned_actions)
        if f'{i}a' in alignments
      ],
      key=lambda thread: thread['interval'][0]
    )
    logging.info(thread)
  
    # 6. Code Weave
    logging.info('=== Code Weave ===')
    backported_hunk.weave(candidate, thread)
    #result_hunk = self.weave(candidate, thread)
  
    # 7. Post Process and Return
    logging.info('=== Post Process and Return ===')
    logging.info(f'Returning new backport proposal hunk for candidate {candidate.path_to}')
    return backported_hunk

  def draft_backport(self, candidate, cve_record):
    agent = Agent()
    response = agent.ask(f'''
Imagine you had a hunk of a patch, in unified diff format, that was generated against version X of a package. 
The hunk looks like this:
{hunk}

Imagine this patch hunk was intended to resolve the following CVE:
{cve_record.cve}:
{cve_record.desc}

Now, imagine you need to backport this hunk to a different version of the package. But you don't know
exactly where the code should go! After a brief static code analysis, you uncover several places the patch
code could apply if it were modified. 
This is one of those places to potentially apply the patch:
{candidate.path_to}:
{candidate.code_str()}
Now, imagine we assumed this was the correct place to apply the patch. Your role is simply to determine what the code would look like
if the patch were applied. Maybe it will look like trash. That's ok. Be creative!
''', pattern=extension_to_language(Path(candidate.path_to).suffix))
    return agent

  def generate_actions(self):
    actions, current = [], None
    for dl in self.delta:
      if dl.line_type != LineType.NOCHANGE:
        atype = ActionType.INSERTION if dl.line_type == LineType.INSERTION else ActionType.DELETION
        if not current or current.action_type != atype:
          if current: actions.append(current)
          current = Action(atype, dl)
        else:
          current += dl
      elif current:
        actions.append(current)
        current = None
    if current: actions.append(current)
    self.actions = actions
    return actions

  def prune_actions(self, action_tpl, action_dict):
    agent = Agent()
    response = agent.ask(f"""
  You are reviewing two patch action sequences, each represented as an ordered dictionary:
  - The *template sequence* (original patch actions): {dict_str(action_tpl)}
  - The *target sequence* (actions generated by attempting to backport): {dict_str(action_dict)}
  
  For each action in the target sequence, compare it to all template actions, and answer:
  - Is this target action 'irrelevant', 'opposites', or 'identical' to any template action?
  - Does the set of affected variables in the target differ from those in any template action?
  - If there is no good match, return 'template_match: ~'.
  
  For each target action, return:
    target_id:
      template_match: <template_id or ~>
      label: <irrelevant|opposites|identical|other>
      tpl_vars: [list of variables from matched template action, or empty list]
      tgt_vars: [list of variables from target action, or empty list]
  
  Format your answer as strict YAML, one dictionary under a key 'metadata'.
  
  Only include actions in your output if they should be *deleted* from the target sequence 
  because:
  - They are 'irrelevant' or 'opposites', or
  - Their template_match is ~ (no match), or
  - tpl_vars and tgt_vars differ as sets.
  
  Example:
  metadata:
    '2-0':
      template_match: t.0
      label: 'opposites'
      tpl_vars: [foo,bar]
      tgt_vars: [qux]
    ...
  
  Only output the YAML as specified.
  """, output_format='yaml')
    
    metadata = response.get('metadata', {})
    return [
      tgt_id
      for tgt_id, meta in metadata.items()
      if meta['label'] in ['irrelevant', 'opposites']
        or meta.get('template_match') in (None, '~')
        or set(meta.get('tpl_vars', [])) != set(meta.get('tgt_vars', []))
    ]

  def create_alignments(self, action_dict, candidate):
    agent = Agent()
    response = agent.ask(f"""
  This is a hunk of a patch in unified diff format, here called the template hunk:
  {self}
  
  It corresponds to a certain area of a package, which in another version is represented as CANDIDATE:
  {candidate.context_str()}
  
  CANDIDATE was produced by a call to candidate.context_str(), which produces a representation like:
  line_no\\tmatch_type\\tline_of_code (excluding whitespace)
  
  Think of the hunk as a template for how we might try to backport the patch to the candidate.
  A hunk can be understood as a series of actions performed in a given order. An action is either an INSERTION
  or a DELETION. An INSERTION corresponds to a contiguous set of lines of code that we want to inject into the
  candidate. A DELETION is a contiguous set of lines of code that we want to remove from the candidate.
  An alignment is our attempt to place actions in the candidate, in the correct order, based on where similar lines
  of code occur in the template hunk. 
  
  In an alignment:
  - An INSERTION is represented by one line number, which is the line AFTER WHICH the INSERTION will begin to insert lines of code.
  - A DELETION is represented by two line numbers, which are the range of code lines that will be deleted.
  
  For example:
  INSERTION of 5 lines at line 23 inserts 5 lines after line 23.
  DELETION of 3 lines at lines 32-34 deletes lines 32, 33, and 34.
  
  Here are the ACTIONS we want to perform on the candidate (in dict form): 
  {dict_str(action_dict)}
  
  For each action, determine its alignment(s) in CANDIDATE:
  - For INSERTION: output the line number after which to insert.
  - For DELETION: output first and last line numbers to be deleted.
  - Use the candidate's line numbers.
  
  Output in strict YAML as follows:
  alignments:
    <action_id>:
      insert_at:   # ~ if a DELETION, otherwise the line number after which to insert lines.
      delete_from: # ~ if an INSERTION, otherwise the first line number to delete.
      delete_to:   # ~ if an INSERTION, otherwise the last line number to delete.
  """, output_format="yaml")
  
    alignments = response.get('alignments', {})
    result = {}
    for aid, metadata in alignments.items():
      # If it's an insertion, list has only one element: [insert_at]
      # If deletion, list is [delete_from, delete_to]
      if metadata.get('insert_at') not in [None, '~']:
        result[aid] = [metadata['insert_at']]
      else:
        result[aid] = [metadata.get('delete_from'), metadata.get('delete_to')]
    return result

  def weave(self, candidate, threads):
    """
    Build self.delta by walking the candidate context (`ctx`) and executing each
    thread action.  The algorithm copies unchanged context lines up to the next
    action interval, then performs either an INSERTION or a DELETION.
  
    candidate.context is a dict {line_no -> {...}} covering every line that
      any interval in `threads` will touch.
    threads is an ordered list of dicts
      {'action': Action, 'interval': [start]  or  [start, end]}
    """
    from rich.console import Console
    from rich.panel import Panel
  
    console = Console()
  
    # ----------------------------------------------------------------- context
    ctx       = candidate.context          # { line_no : { 'line': ... } }
    ctx_keys  = sorted(ctx.keys())         # all line numbers we have
    line_no   = ctx_keys[0]                # current position in ctx
    self.top  = line_no                    # hunk header "top" line
    self.delta = []
  
    console.print(
      Panel(
        f"[bold green]START WEAVE[/bold green]\n"
        f"Candidate: [cyan]{candidate.path_to}[/cyan]\n"
        f"Context lines: [magenta]{ctx_keys[0]} - {ctx_keys[-1]}[/magenta] "
        f"({len(ctx_keys)} keys)"
      )
    )
  
    # -------------------------------------------------------------- main loop
    for thread in threads:
      action   = thread['action']
      interval = thread['interval']        # [start]  or  [start, end]

      # ---- fast sanity: does ctx cover the whole interval? ----
      if interval[0] < ctx_keys[0] or interval[-1] > ctx_keys[-1]:
        raise GarbageCandidateError(
          f"Candidate {candidate.path_to} covers "
          f"{ctx_keys[0]}–{ctx_keys[-1]} but interval {interval} "
          f"is outside that range."
        )
  
      console.print(
        Panel(
          f"[white]Thread:[/white] [bold yellow]{action}[/bold yellow]  "
          f"Interval: [green]{interval}[/green]  "
          f"Start line_no: [cyan]{line_no}[/cyan]",
          title="New Thread",
          style="sky_blue3"
        )
      )
  
      # ------------------------------------------------ copy unchanged context
      while line_no < interval[0]:
        if line_no not in ctx:
          raise ProcessingException(
            f"Missing ctx line {line_no} (ctx range {ctx_keys[0]}–{ctx_keys[-1]})"
          )
        self.delta.append(DiffLine(ctx[line_no]['line'], LineType.NOCHANGE))
        line_no += 1
  
      # ------------------------------------------------ perform the action
      if len(interval) == 1:
        # INSERTION
        anchor_line = interval[0]
        self.delta.append(DiffLine(ctx[anchor_line]['line'], LineType.NOCHANGE))
        for diff_line in action.lines:
          self.delta.append(DiffLine(diff_line.text, LineType.INSERTION))
        line_no = anchor_line + 1
  
      else:
        # DELETION
        for j in range(interval[0], interval[-1] + 1):
          self.delta.append(DiffLine(ctx[j]['line'], LineType.DELETION))
        line_no = interval[-1] + 1
  
    # ------------------------------------------------ copy any trailing context
    while line_no <= ctx_keys[-1]:
      if line_no not in ctx:
        raise ProcessingException(
          f"Trailing ctx missing line {line_no} (ctx range {ctx_keys[0]}–{ctx_keys[-1]})"
        )
      self.delta.append(DiffLine(ctx[line_no]['line'], LineType.NOCHANGE))
      line_no += 1
  
    # ------------------------------------------------ trim & finish
    self.trim_delta()

