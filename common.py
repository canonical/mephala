#!/usr/bin/python3

import re
import os
from agent import Agent
import yaml
import collections
import sys
import ahocorasick
from fuzzywuzzy import fuzz
from uuid import uuid4
from intervaltree import IntervalTree
import math
from enum import Enum
from itertools import islice
import difflib
from context import ContextManager

class CVERecord:
  def __init__(self, cve, desc):
    self.cve = cve
    self.desc = desc
  def __str__(self):
    return f'{self.cve}\n{self.desc}'

# Naming convention for patches and stuff:
# filename#hunk_index#candidate_id
class Patch:

  def __init__(self, cve_record, release, path_to=None, fit_to=None):
    self.cve_record = cve_record
    self.release = release
    self.path_to = path_to
    self.hunks = {}
    self.metadata = {}

    if fit_to is not None:
      self.transform(fit_to) 

  def __str__(self):
    out = ''
    for filename in self.hunks.keys():
      out += f'--- {filename}\n+++ {filename}\n'
      for hunk in self.hunks[filename]:
        out += str(hunk)

    return out

  def with_metadata(self, metadata):
    self.metadata = metadata
    return self

  def parse_patch(self):
    hunks = []
    #current_filename = None
    collecting_hunk = False  

    a, b = None, None
    collecting_filenames = False

    converter = lambda line: '/'.join(line.split(' ')[1].split('/')[1:]).strip()
    with open(self.path_to, "r") as file:
      for line in file:
        # New hunk in a different file
        #if line.startswith('diff --git'):
          #current_filename = line.split(' b/')[-1].strip()
        if line.startswith('---'):
          print(line)
          try:
            a = converter(line)
            collecting_filenames = True
          except IndexError as ie:
            print('ignore')
            continue
          
          #hunks.append(Hunk(current_filename))
          #collecting_hunk = False
        elif line.startswith('+++'):
          if not collecting_filenames:
            continue
          b = converter(line)
          if a != b:
            print('Mismatch! Probable new file')

          hunks.append(Hunk(b))
          collecting_hunk = False
        # Start of new hunk text
        elif line.startswith('@@'):
          if collecting_hunk:
            hunks.append(Hunk(hunks[-1].filename))
          collecting_hunk = True
        # Current hunk body
        elif collecting_hunk:
          hunks[-1].delta.append(DiffLine(line[1:-1], LineType.INSERTION if line[0] == '+' else LineType.DELETION if line[0] == '-' else LineType.NOCHANGE))

    return hunks

  # Kind of an intense process. This method is written to manage a pipeline (and the reader's sanity).
  def transform(self, other_patch):
   
    source_dir = ContextManager(mode='r').get_package_homes()[self.release] 
    for idx, hunk in enumerate(other_patch.parse_patch(), 1): 
      delta = hunk.delta
      print('### DELTA ###')
      for line in delta:
        print(line)

      # 1. Cross-reference patch code with source code to find similarities
      candidate_dict = { f"{i + 1}.{j}": candidate.with_path(f) 
        for i, (f, C) in enumerate(hunk.compare_to(source_dir, HunkState.INITIAL).items())
        for j, candidate in enumerate(C)} 

      if len(candidate_dict) == 0:
        print('Nowhere in the entire code base is similar enough to the patch code for this process to work. Consider banging your head against a wall?')
        continue

      for cid, c in candidate_dict.items():
        print(cid)
        print(c.context_str())

      # 2. Perform semantic and syntactic analysis of possible fits, cross-referenced with the CVE description
      selections = [str(sel) for sel in other_patch.metadata.get(idx) or self.semantic_pass(hunk, candidate_dict, other_patch.cve_record)]
      
      # 3. Actions
      actions = self.generate_actions(hunk)

      print(actions)

      # 4. Alignments
      alignment_dict = { sel: self.create_alignments(actions, hunk, candidate_dict[sel]) for sel in selections }

      print(alignment_dict)

      # 5. Threads
      thread_dict = {
        sel: sorted(
          [{'action': action, 'interval': alignment_dict[sel][i]} for i, action in enumerate(actions)],
          key=lambda thread: thread['interval'][0]	
        ) for sel in selections
      }
      print(thread_dict)
 
      # 6. Weave
      fabric_dict = { sel: self.weave(candidate_dict[sel], thread_dict[sel]) for sel in selections }

      # 7. Post-process Hunks
      for k,v in fabric_dict.items():
        print(k)
        print(str(v))
        if v.filename in self.hunks:
          self.hunks[v.filename].append(v)
        else:
          self.hunks[v.filename] = [v]

  def weave(self, candidate, threads):
    fabric = Hunk(candidate.path_to)
    ctx = candidate.context
    line_no = list(ctx.keys())[0]
    fabric.top = line_no
    for thread in threads:
      action = thread['action']
      interval = thread['interval']
      # We need to decide whether to insert a normal line, or do an action. This is based on whether an action has come up yet. 
      while interval[0] != line_no:
        fabric.delta.append(DiffLine(ctx[line_no]['line'], LineType.NOCHANGE))
        line_no += 1

      if len(interval) == 1:
        fabric.delta.append(DiffLine(ctx[line_no]['line'], LineType.NOCHANGE))
        for diff_line in action.lines:
          fabric.delta.append(DiffLine(diff_line.text, LineType.INSERTION))
        line_no += 1
      else:
        if interval[0] == interval[1]:
          fabric.delta.append(DiffLine(ctx[interval[0]]['line'], LineType.DELETION))
        else:
          for j in interval:
            fabric.delta.append(DiffLine(ctx[j]['line'], LineType.DELETION))
        line_no = interval[-1] + 1

    while line_no <= list(ctx.keys())[-1]:
      fabric.delta.append(DiffLine(ctx[line_no]['line'], LineType.NOCHANGE))
      line_no += 1

    fabric.trim_delta()
    return fabric

  def create_alignments(self, actions, hunk, candidate):
    prompts = [f'''
In unified diff format. This is HUNK:
{hunk}
It corresponds to a certain area of a package, which in another version is represented as CANDIDATE:
{candidate.context_str()}
CANDIDATE was produced by a call to candidate.context_str(), which produces a representation like:
line_no\tmatch_type\tline_of_code (excluding whitespace)

Now, let's try and weave the "actions" HUNK takes into CANDIDATE. Let's do this in two parts. 

Part 1:

An INSERTION action corresponds to a contiguous set of lines of code from HUNK that we want to inject into CANDIDATE. 
Based on the fact that CANDIDATE and HUNK are the same area of source code at different points in time, 
For each INSERTION action,
After which line of CANDIDATE should that INSERTION action be performed?

These are all actions:
{'\n'.join([f"ACTION {i}:\n{str(action)}" for i, action in enumerate(actions)])}

Please just write your answer like a dictionary. So action_no -> line_no_in_candidate_to_insert_after
''',
f''',
Ok, now let's do DELETIONS. Same deal, but important distinction: the lines to delete may have refactored over time. 
So for your answer, please write ranges of code lines that correspond to each action. Like
action_no -> (first_line_to_delete, last_line_to_delete)
''',
f'''
Ok, now please consolidate your dictionary.
'''
    ]
    out = '{ alignments: { action_no: [context_line_or_lines (depending on insertion or deletion)] } }'
    return self.llm_layer(prompts, out, 'alignments')

  def semantic_pass(self, hunk, candidate_dict, cve_text):

    prompts = [f'''
PATCH_HUNK is a section of at least one patch that helps address {self.cve}: {cve_text}. Can you summarize the changes this particular hunk makes wrt the CVE?
PATCH_HUNK:
{hunk}
    ''',
    f'''
The following code blocks, labelled AREA x.y, are code blocks from a package that PATCH_HUNK was generated against, but a different version. Maybe newer, maybe older. These code blocksare either semantically or syntactically similar to the code in PATCH_HUNK. Can you explain, for each AREA, whether the same vulnerable mechanism occurs IN AREA in this version of the source code?
{'\n'.join([f"AREA {version}:\n{candidate.path_to}\n{candidate.context_str()}" for version, candidate in candidate_dict.items()])}
    ''',
    f'''
Based on the following cases, can you identify the best fit AREA/s for PATCH_HUNK? Justify your choices. 
1) In the common case, only one AREA is the best fit, and it's the AREA that bears the strongest resemblance to PATCH_HUNK, the mechanism you described in PATCH_HUNK,
and secondarily what the CVE regards. 
2) Two or more candidates are possible if and only if: 
  a) code was split up between AREAs
  b) code was duplicated between AREAs

Don't pick more than one unless you are prepared to justify why case 2 applies.

You should prioritize identifying a single AREA. You should make your choice based on how I would if I were manually spelunking to look for where a patch hunk might fit. I would
keep in mind that this is unlikely to be the only hunk that takes care of making the changes that are needed to address this CVE. I would remember that maybe the names of classes
have changed across versions, that in some languages method names and variables can be very similar but I would need to account for that and identify a specific place to apply a
specific hunk. It's important to mirror the manual process closely. 
    ''',
    f'''
Reconsider your decision, if necessary. Mistakes you've previously made:
- For a hunk that touched parsing logic, you often failed to distinguish XML parsing from HTML parsing
- You made no choices when you should have made at least one
- You tend to try to pick candidates that "fix" the CVE, when really the CVE is secondary here and you should be picking candidates in terms of
  fit to the patch hunk, keeping in mind that we only care about lines that are present in both editions of the code (patch and source), deletions
  of lines that exist in both editions, and insertions of lines that don't exist in the candidate sections. The only thing you should care about is
  whether the patch "looks like" it should apply to the candidate. 
Give me a final choice, or choices if case 2 holds. 
    ''']
    out = "{'best': [NUMERIC VALUES OF BEST FIT OR FITS...]}"

    return self.llm_layer(prompts, out, 'best')

  def llm_layer(self, prompts, out, return_key):
    agent = Agent()

    for idx, prompt in enumerate(prompts):
      if idx == len(prompts) - 1:
        agent.ask(prompt, out, repeat=False)
      else:
        agent.raw_ask(prompt)

    for msg in agent.chain:
      for r,c in msg.items():
        pass
        #print(r)
        #print(c)

    return yaml.safe_load(agent.chain[-1]['content'])[return_key]
  

  def generate_actions(self, original_hunk):
    actions, current = [], None
    for dl in original_hunk.delta:
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
    return actions

class Pattern:
  def __init__(self, match_text, first_loc, partial_match=False):
    self.match_text = match_text
    self.locations = [first_loc]
    self.is_partial = partial_match
    #self.locations = {first_loc: partial_match}
    self.saturation = 1

  def found_at(self, line_no, partial_match=False):
    #self.locations[line_no] = partial_match
    self.locations.append(line_no)
    self.is_partial = partial_match or self.is_partial
    return True

  def locate_in(self, interval):
    return next((loc for loc in self.locations if loc in range(*interval)), None)

  def __str__(self):
    return f'Pattern: {self.match_text}; Saturation: {self.saturation}; Locations: {self.locations}'

class Candidate:

  def __init__(self, target_length, *patterns, **initial_values):
    self.id = str(uuid4())
    self.context = None
    
    self.target_length = target_length

    self.patterns = list(patterns)

    if 'extent' in initial_values:
      self.earliest_hit, self.latest_hit = initial_values['extent']
    else:
      # Insertion order guaranteed since python 3.7
      self.earliest_hit = patterns[0].locations[-1]
      #self.earliest_hit = list(patterns[0].locations.keys())[-1]
      self.latest_hit = self.earliest_hit

    if 'score' in initial_values:
      self.score = initial_values['score']
    else:
      self.score = 1

  @property
  def extent(self):
    extension_length = self.target_length - (self.latest_hit - self.earliest_hit)
    if extension_length <= 0:
      return (self.earliest_hit, self.latest_hit)
    else:
      padding = math.ceil(extension_length / 2)
      return (self.earliest_hit - padding, self.latest_hit + padding)

  def with_path(self, path_to):
    self.path_to = path_to
    return self

  # Context, here, being understood as everything that the candidate generator
  #   tagged as a "pattern" (meaning it was found to some degree
  #   in both the patch code and the source code), and the surrounding lines of code
  #   up to a certain padding and margin.
  #
  # Creates a dictionary of structure
  # { line_no -> {
  #    'line' -> actual line of code, 
  #    'is_pattern' -> whether the line of code is a "pattern" as defined,
  #    'is_partial' -> whether the line of code is a "partial" "pattern", meaning a "pattern" with either a smaller full ldis score or significant partial ldis score 
  def generate_context(self, source_lines):
    start, end = self.extent
    
    self.context = {pattern.locate_in((start,end)): pattern for pattern in self.patterns}

    margin_sz = 0

    # Just for safety, in case a pattern got tagged to this candidate but isn't in range
    if None in self.context:
      del self.context[None]

    for idx, line in islice(enumerate(source_lines, start=1), start - 1 - margin_sz if start >= 0 else 0, end + margin_sz):
      pattern = self.context.get(idx)
      full_match = pattern is not None and not pattern.is_partial
      partial_match = pattern is not None and pattern.is_partial
      self.context[idx] = {'line': line, 'is_pattern': full_match, 'is_partial': partial_match}

    self.context = {key: self.context[key] for key in sorted(self.context)}

    return self.context

  def __str__(self):
    return f'Candidate: earliest hit {self.earliest_hit}, latest hit {self.latest_hit}; Hit score {self.score}'

  def context_str(self):
    return '\n'.join([f'{k}\t{"Part" if v["is_partial"] else "Full" if v["is_pattern"] else "Miss"}\t{v["line"]}' for k,v in self.context.items()])

class HunkState(Enum):
  INITIAL=1
  FINAL=2

class LineType(Enum):
  NOCHANGE=0
  INSERTION=1
  DELETION=2

class ActionType(Enum):
  INSERTION=1
  DELETION=2

class Action:
  def __init__(self, action_type, first_line):
    self.action_type = action_type
    self.lines = [first_line]
  def __iadd__(self, other):
    self.lines.append(other)
    return self
  def __str__(self):
    return f"{self.action_type}\n{'\n'.join([str(line) for line in self.lines])}" 

class DiffLine:
  def __init__(self, text, line_type, source=None):
    self.text = text
    self.line_type = line_type
    if source:
      self.source = source

  def type_sym(self):
    return '+' if self.line_type == LineType.INSERTION else '-' if self.line_type == LineType.DELETION else ' '

  def __str__(self):
    return f'{self.type_sym()}{self.source if hasattr(self, "source") else ''}{self.text}'

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
    header = f"@@ -{start},{len(self.to_a())} +{start},{len(self.to_b())} @@"
    body = '\n'.join([str(line) for line in self.delta])

    return f"{header}\n{body}"

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

  # Now with fully-expanded tree search!
  def compare_to(self, source_dir, at: HunkState):
    
    if not isinstance(at, HunkState):
      raise TypeError("at should be type 'HunkState'")

    #pattern_lines = [line.text.strip() for line in self.state(at)]
    pattern_lines = [line.text.strip() for line in self.to_b()]
    self.pattern_blacklist = set()
    self.psats = {}
    candidates = {}
    _, ext = os.path.splitext(self.filename)

    for root, dirs, files in os.walk(source_dir):
      for directory in dirs:
        if directory in ['.pc', 'patches']:
          dirs.remove(directory)

      for file in files:
        if os.path.splitext(file)[1] != ext:
          continue

        path = os.path.join(root, file)

        with open(path, 'r') as src:
          source_lines = src.read().split('\n')

        candidates[path] = self.generate_candidates(source_lines, pattern_lines)
    
    candidates = {
      file: filtered_candidates
      for file, clist in candidates.items()
      if (filtered_candidates := [
        c for c in clist
        if not all(pattern.match_text in self.pattern_blacklist
                   for pattern in c.patterns
                   if not pattern.is_partial)
      ])
    }
 
    print('Blacklisted values:')
    for p in self.pattern_blacklist:
      print(p)

    return candidates

  #def generate_candidates(self, source_lines, matcher, candidate_length):
  def generate_candidates(self, source_lines, pattern_lines):

    # match_text -> Pattern object. Essentially a wrapper for text matches to store extra info.
    patterns = {}

    # Every candidate covers a certain interval of the source code, so the tracker pairs
    # Code range -> [Candidate]. 
    # Eventually we merge overlapping candidates. 
    tracker = IntervalTree()

    # Dynamic blacklist we'll populate in process. We want to represent common patterns
    # to this specific source file, and we don't know what they are until processing. 
    #pattern_blacklist = set()

    partials = set()

    source = {i: line for i, line in enumerate(source_lines, start=1)}

    ### START ###
 
    ### 1. AGGREGATE PATTERN MATCHES ###
    for line_no, file_line in source.items():
      fl = file_line.strip()

      if fl in self.pattern_blacklist:
        continue
  
      # 1. matches = [match for match_end, (insert_order, match) in matcher.iter(file_line.strip())]
      # 2. matches = [line for line in pattern_lines if fuzz.ratio(file_line.strip(), line) >= 95]
      # 3. matches = [line for line in pattern_lines if str_match(file_line.strip(), line)]
      matches = {line: (fuzz.ratio(fl, line), fuzz.partial_ratio(fl, line)) for line in pattern_lines}
      #if not matches:
      #  continue
      for match, (ldis, partial_ldis) in matches.items():

        # garbage
        if match in self.pattern_blacklist or ldis < self.PARTIAL_MATCH_SCORE:
          continue
 
        ### 1a. UPDATE PATTERN DICTIONARY AND BLACKLIST ###
        # some kind of really solid match
        if ldis >= self.NEAR_MATCH_SCORE or partial_ldis >= self.NEAR_MATCH_SCORE:
          if match in patterns:
            patterns[match].found_at(line_no)
          else:
            patterns[match] = Pattern(match, line_no)

          current_pattern = patterns[match]
          current_pattern.saturation += 1

          if current_pattern.saturation > self.KILL_THRESHOLD:
            self.pattern_blacklist.add(match)
            continue

          if partial_ldis == self.PERFECT_MATCH_SCORE:
            self.psats[fl] = self.psats.get(fl, 0) + 1
            if self.psats[fl] > self.KILL_THRESHOLD:
              self.pattern_blacklist.add(fl)
              continue

          ### 1b. UPDATE TRACKER ###
          new_candidate = Candidate(len(pattern_lines), current_pattern)
          tracker[range(*new_candidate.extent)] = new_candidate
        # an actual partial match, not to be confused with the fact that we are using partial ldis scores
        elif partial_ldis >= self.PARTIAL_MATCH_SCORE:
          partials.add(line_no)


    ### 2. MERGE & FILTER CANDIDATES ###
    def list_wrap(obj):
      return obj if isinstance(obj, list) else [obj]

    tracker.merge_overlaps(data_reducer=lambda c1,c2: list_wrap(c1) + list_wrap(c2))
    if len(partials) > 0:
      for start, end, candidates in tracker:
        first = list_wrap(candidates)[0]
        for partial in partials:
          if partial >= start and partial < end:
            first.patterns.append(Pattern(source[partial], partial, partial_match=True))

    consolidated_list = [Candidate(
                           len(pattern_lines),
                           *sum((candidate.patterns for candidate in list_wrap(candidate_list)), []),
                           extent=(start,end),
                           score=len(list_wrap(candidate_list)))
                         for start, end, candidate_list in tracker
                         if any(p.saturation <= self.KILL_THRESHOLD for candidate in list_wrap(candidate_list) for p in candidate.patterns)]
    ### END ###

    for candidate in consolidated_list:
      candidate.generate_context(source_lines)
      #print(candidate.context_str())
    #sys.exit(1)
    return consolidated_list

if __name__=="__main__":
  agent = Reviewer()
  #print(agent.get_vulnerabilities())
