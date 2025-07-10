from uuid import uuid4
import math
from itertools import islice
from enums import LineType


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
    """
    Returns a tuple (start, end) – 1-based line numbers inclusive – that
    defines the slice of the source file represented by this Candidate.
  
    • The raw match range is earliest_hit … latest_hit.
    • If that range is shorter than target_length, it is symmetrically
      padded outward so the total length equals target_length (±1 for odd
      lengths).
    • The final start value is never less than 1 (files are 1-based).
    """
    base_len = self.latest_hit - self.earliest_hit          # raw span
    extension_length = self.target_length - base_len
  
    if extension_length <= 0:
      start = self.earliest_hit
      end   = self.latest_hit
    else:
      padding = math.ceil(extension_length / 2)
      start = self.earliest_hit - padding
      end   = self.latest_hit + padding
 
    # clamp 
    if start < 1:
      delta = 1 - start        # how far we underflowed
      start = 1
      end   += delta           # keep overall length unchanged
  
    return (start, end)

  def with_path(self, path_to):
    self.path_to = path_to
    return self

  # (may need to be updated removed altogether (this string) )
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

  def code_str(self):
    return '\n'.join(self.lines)

  @property
  def lines(self):
    return [metadata["line"] for _, metadata in self.context.items()]

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

class CVERecord:
  def __init__(self, cve, desc):
    self.cve = cve
    self.desc = desc
  def __str__(self):
    return f'{self.cve}\n{self.desc}'

class Patch:

  def __init__(self, cve_record, release, path_to=None, fit_to=None):
    self.cve_record = cve_record
    self.release = release
    self.path_to = path_to 
    self.hunks = {}
    self.metadata = {}

    if fit_to is not None:
      logging.info(f'Fitting patch to {str(fit_to)}')
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

  def parse_patch_file(self):
    with open(self.path_to) as f: lines = f.read().splitlines()
    return self.to_hunks(lines)

  def to_hunks(self, lines):
    from hunk import Hunk

    hunks = []
    collecting_hunk = False  

    a, b = None, None
    collecting_filenames = False

    converter = lambda line: '/'.join(line.split(' ')[1].split('/')[1:]).strip()
    for line in lines:
      # New hunk in a different file
      if line.startswith('---'):
        print(line)
        try:
          a = converter(line)
          collecting_filenames = True
        except IndexError as ie:
          continue
          
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
        hunks[-1].delta.append(DiffLine(line[1:], LineType.INSERTION if line[0] == '+' else LineType.DELETION if line[0] == '-' else LineType.NOCHANGE))

    return hunks

