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

#utils

# How many lines of context a patch hunk expects. 
CONTEXT_LENGTH = 3

def str_match(str1, str2):
  ldis = fuzz.ratio(str1, str2)
  match ldis:
    case _ if ldis >= 90:
      return True
    case _:
      return False 


# Naming convention for patches and stuff:
# filename#hunk_index#candidate_id
class Patch:

  def __init__(self, patch_file, cve):
    self.patch_file = patch_file
    self.cve = cve
    patch_name = patch_file.split('/')[-1]

    self.hunks = {idx + 1: hunk for idx, hunk in enumerate(self.parse_patch(patch_file))}

  def parse_patch(self, patch_path):
    hunks = []
    #current_filename = None
    collecting_hunk = False  

    a, b = None, None
    collecting_filenames = False

    converter = lambda line: '/'.join(line.split(' ')[1].split('/')[1:]).strip()
    with open(patch_path, "r") as file:
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
  # 1. We look for similarities between the hunks of the patch and the (potentially many) files  
  def fit(self, source_dir, cve_text, metadata={}):
    print(metadata)
    for key, hunk in self.hunks.items():
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
      selections = [str(sel) for sel in metadata.get(key) or self.semantic_pass(hunk, candidate_dict, cve_text)]
      
      #d = difflib.Differ()
      #for sel in selections:
      #  candidate = candidate_dict[str(sel)]
      #  print(candidate.context_str())
      #  print(candidate.target_length)
      #  diff = d.compare([ctx['line'] for _, ctx in candidate.context.items()], [dl.text for dl in delta])
      #  print('\n'.join(diff))
     
      # 3. Actions
      # action_dict = { sel: self.actions(hunk, candidate_dict[sel]) for sel in selections }
        
      # 3. Actions
      actions = self.generate_actions(hunk)

      # 4. Generate Alignments
      alignment_dict = { sel: self.align_actions(actions, hunk, candidate_dict[sel]) for sel in selections }

      print(alignment_dict)
      # TODO handle DELETIONS and INSERTIONS separately. insert is trivial compared to delete, which calls for like a "mapping" thing of lines 1..3 to 5.4 or smth
      # 4. Weave
      #for sel in selections:
      #  
      #  #self.weave(candidate_dict[sel], hunk)
      #  #self.weave(candidate_dict[sel], hunk, action_dict[sel])
 
  def align_actions(self, actions, hunk, candidate):
    prompts = [f'''
This is wrt the unified diff format. Here HUNK is given as:
{hunk}
~~~
We are trying to be a little clever.  HUNK applies to the source code of some package PKG in versions X.
Moreover, here is a section AREA of source code from PKG in version Y:
{candidate.context_str()}
~~~
I produced AREA by a call to candidate.context_str(), which produces a representation that looks like:
line_no\tmatch_type\tline_of_code (excluding whitespace) 

It's the same package, different versions. Here's the thing: you don't necessarily know whether X > Y, X == Y, or X < Y. Any of those could be true.
Between versions, we might expect to see syntactic differences, variables renamed, brackets moved to separate lines, whitespace removed, etc. Obvi
I did not cover all possible variations. But the main idea is HUNK and AREA represent the same area of the source code at different points in time.

In a preprocessing step, we converted HUNK into a set of ACTIONs. An ACTION is defined as:
INSERT: an unbroken sequence of code lines to be inserted between lines that already exist
DELETE: every line of code that is deleted. Note that every line of code that is deleted counts as a DELETE, in contrast with INSERT which considers
contiguous lines of code.

This is ACTIONS:
{'\n'.join([f"ACTION {i}:\n{str(action)}" for i, action in enumerate(actions)])}
~~~

Your course, simply, is to produce a mapping from action number to line number in candidate. If an ACTION is an INSERTION, the line number you pick is the line
before which the INSERTION ACTION will begin. If an ACTION is a DELETION, the line number you pick is line that will be marked for DELETION. 

IMPORTANT: lines may not match exactly, because who knows what changed between X and Y. That's why we're using you for this step in the process. We need you to 
allow for some fuzziness in determining where to perform INSERTIONS and DELETIONS.

Do be careful not to go too far off the reservation.
''',
'''
Now that you've generated your initial list, please invalidate your list. Use the following notes to explain why you may have made bad choices: 
Notes:
- What if an ACTION INSERTS code that is already present in AREA? We omit that ACTION from the output.
- What if an ACTION DELETES code that is not present in AREA? We omit that ACTION from the output.
- What if a refactor changed whether, for example, a stray curly bracket occurs on a standalone line or at the end of another, and as a consequence 
  there is a DELETION for a single curly bracket? Do we ignore the CONTEXT (the surrounding lines) of the relevant DELETION? No, of course not. We remember
  that the ACTION is not a standalone creature, and exists in the CONTEXT of HUNK, and we do not try to map ACTION to the wrong section of AREA. 
- What if a line of code, like a method signature, was split across multiple lines, or condensed into one line, between X and Y versions? 

I want you to be severe and harsh. You really have a habit of being too generous with yourself. Remember that we want to allow for fuzzy matching, but also remember
that you are just a token matcher and you have a habit of making mistakes.
''',
'''
Now, please generate a final list based on your initial list, and your invalidations.
'''
]
    out = '{ alignments: [ *give them in the same order as the ACTIONS occurred, and yield -1 if the ACTION is to be omitted* ] }'
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
        print(r)
        print(c)

    return yaml.safe_load(agent.chain[-1]['content'])[return_key]
  
  # Bespoke diff calculation algorithm for the specific purpose of "fitting" patch code
  #   to a different version of the same source code.
  def old_fit(self, source_dir, cve_text):
    for hunk in self.hunks:
      fit_dict = hunk.compare_to(source_dir, HunkState.INITIAL)

      if len(fit_dict) == 0:
        print('Patch not applicable')
        continue

      #strongest_fit = possible_fits[0] if len(possible_fits) == 1 else max(possible_fits, key=lambda c: c.score)

      delta = hunk.delta
      
      print('### DELTA ###')
      for line in delta:
        print(line)
      print('###')
      for f, C in fit_dict.items():
        print(f)
        for c in C:
          print(c.context_str())

      fits = []
      for file, candidates in fit_dict.items():
        for candidate in candidates:
          target = candidate.context
          #print('### TARGET ###')
          #print(candidate.context_str())
          #print('###')
          ### START ###
    
          ### 1. Anchor Points ###
          #
          # Unique matches between the patch code and the source code. We originally
          #   took advantage of these during candidate generation, and are re-using
          #   them to establish "locality" or context for each section of a hunk. 
          #
          anchor_keys = sorted([k for k,v in target.items() if v['is_pattern']])
          anchor_points = []
          for target_ptr in range(len(anchor_keys)):
            for delta_ptr in range((0 if len(anchor_points) == 0 else anchor_points[-1][1]), len(delta)):
              #if delta[delta_ptr].text.strip() == target[anchor_keys[target_ptr]]['line'].strip():
              if str_match(delta[delta_ptr].text.strip(), target[anchor_keys[target_ptr]]['line'].strip()):
                anchor_points.append((anchor_keys[target_ptr], delta_ptr)) 
                break
    
          print(anchor_points)
    
          ### 2. Segments ### 
          #
          # Subsections of the space between each anchor point. These are rectangular
          #   because we're comparing patch code and source code, and are defined with
          #   endpoints that correspond to all matches between the two texts. These
          #   allow us to contextualize valid insertions from the patch code. 
          #
          segments = []
          for i in range(len(anchor_points) - 1):
            start_tpt, start_dpt = anchor_points[i]
            end_tpt, end_dpt     = anchor_points[i + 1]
            d = start_dpt
            t = start_tpt
           
            ### 2a. Slats 
            # 
            # All matches between patch and source. Every line of code that isn't a match
            #   is the "space" between slats. 
            #
            slats = []
            collisions = {}
            for j in range(start_tpt + 1, end_tpt):
              tline = target[j]['line']
              for k in range(start_dpt + 1, end_dpt):
                dline = delta[k].text
                if tline.strip() == dline.strip() and k not in collisions:
                  slats.append((j, k))
                  collisions[k] = True
                  break # first match
    
            slats = [(start_tpt, start_dpt), *slats, (end_tpt, end_dpt)]
            #print(slats)
            for j in range(1, len(slats)):
              prev = slats[j - 1]
              cur = slats[j]
              assert prev[0] < cur[0] and prev[1] < cur[1] # TODO violations of strict ascend
              segments.append((prev, cur))
              
    
          #print(segments)
          ### 3. Hunk ###
          #
          # Segments composed of slats nicely translate to a hunk. Our only rules are:
          #   - Segments are given by (start, end], except for the first which is [start, end]
          #   - Slats are either NOCHANGE or DELETION depending on the state of the line in the patch code.
          #   - Non-slats are either INSERTIONS from the patch code or NOCHANGE lines from the source code.
          #   - The only context we have for how the new patch should be constructed is based on similarites
          #       between patch and source, so we arbitrarily choose to do all INSERTIONS followed by all
          #       NOCHANGES. 
          #
          adjusted = Hunk(file)
          for idx, seg in enumerate(segments):
            first = idx == 0
            start_tpt, start_dpt = seg[0]
            end_tpt, end_dpt     = seg[1]
            def add_anchor(t, d):
              adjusted.delta.append(DiffLine(target[t]['line'], LineType.DELETION if delta[d].line_type == LineType.DELETION else LineType.NOCHANGE))
    
            if first:
              add_anchor(start_tpt, start_dpt)
            for d in range(start_dpt + 1, end_dpt):
              dline = delta[d]
              if dline.line_type == LineType.INSERTION:
                adjusted.delta.append(dline)
    
            for t in range(start_tpt + 1, end_tpt):
              adjusted.delta.append(DiffLine(target[t]['line'], LineType.NOCHANGE))
    
            add_anchor(end_tpt, end_dpt)
          #print(f'Before###\n{adjusted}\n###') 
          ### 4. Context ###
          #
          # In unified format, the "context" of a hunk are the lines that come before
          #   the first change. The default size of this area of the hunk is 3. Here
          #   we either pad the top and bottom of the hunk with extra lines from the 
          #   target space if we don't have 3 context lines on either side, or we 
          #   prune context lines if there are more than 3 on either side to avoid
          #   possible future overfitting were someone to use this patch in a different
          #   context.
          # 
          top    = segments[0][0][0]  - 1 # first start_tpt
          bottom = segments[-1][1][0]     # last  end_tpt
          
          changes = [i for i, diffline in enumerate(adjusted.delta) if diffline.line_type != LineType.NOCHANGE]
          bottom_context_size = CONTEXT_LENGTH - (len(adjusted.delta) - 1 - changes[-1])
          #print(bottom_context_size, len(adjusted.delta), changes[-1])
          if (top_context_size := CONTEXT_LENGTH - changes[0]) > 0:
            #print(top_context_size)
            for _ in range(top_context_size):
              adjusted.delta.insert(0, DiffLine(target[top]['line'], LineType.NOCHANGE))
              top -= 1
          elif top_context_size < 0:
            adjusted.delta = adjusted.delta[abs(top_context_size) - 1:]
          #print(adjusted)
          if bottom_context_size > 0:
            for _ in range(bottom_context_size):
              adjusted.delta.append(DiffLine(target[bottom]['line'], LineType.NOCHANGE))
              bottom += 1
          elif bottom_context_size < 0:
            adjusted.delta = adjusted.delta[:bottom_context_size]

          adjusted.top = top
          
 
          ### END ###
          fits.append(adjusted)

      for idx, fit in enumerate(fits):
        print(f'### ADJUSTED ###\n{fit}\n###')
        #if possible_fits[idx] == strongest_fit:
        #  print(f'### ADJUSTED ###\n{adjusted}\n###')

  def weave(self, candidate, original_hunk, actions):
    fabric = Hunk(candidate.path_to)


  def generate_actions(self, original_hunk):

    # Action generator. 
    # An action is a delete or an insert. Deletes stand on their own, inserts are contiguous lines 
    actions = []
    current = None
    for dl in original_hunk.delta:

      match dl.line_type:
        # A no change will only end INSERTIONS, not cause actions
        case LineType.NOCHANGE:
          if current is not None:
            actions.append(current)
            current = None
        # INSERTIONS cause new actions or extend the current action
        case LineType.INSERTION:
          if current is None:
            current = Action(ActionType.INSERTION, dl)
          else:
            current += dl 
        # DELETIONS end current actions, cause a new action, and immediately end it
        case LineType.DELETION:
          if current is not None and current.action_type == ActionType.INSERTION:
            actions.append(current)
            current = None
          actions.append(Action(ActionType.DELETION, dl))

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
