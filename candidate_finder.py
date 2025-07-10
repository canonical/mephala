import os
from intervaltree import IntervalTree
from fuzzywuzzy import fuzz

class CandidateFinder:
  def __init__(self, KILL_THRESHOLD=4, PARTIAL_MATCH_SCORE=30,
               NEAR_MATCH_SCORE=90, PERFECT_MATCH_SCORE=100):
    self.KILL_THRESHOLD = KILL_THRESHOLD
    self.PARTIAL_MATCH_SCORE = PARTIAL_MATCH_SCORE
    self.NEAR_MATCH_SCORE = NEAR_MATCH_SCORE
    self.PERFECT_MATCH_SCORE = PERFECT_MATCH_SCORE

  @staticmethod
  def candidate_from_file_region(file_path, start_line, length, fuzz=0):
    from common import Pattern, Candidate
    import os

    if not os.path.exists(file_path):
      return None
    with open(file_path, "r") as f:
      lines = f.read().split('\n')

    slice_start = max(start_line - 1 - fuzz, 0)  # 1-based
    slice_end = min(slice_start + length + 2*fuzz, len(lines))
    region_lines = lines[slice_start:slice_end]
    if not region_lines:
      return None
    # Provide a single pattern (the first line of the region)
    pattern_line = region_lines[0]
    fake_pattern = Pattern(pattern_line, slice_start+1)
    candidate = Candidate(
      length,
      *[fake_pattern],
      extent=(slice_start+1, slice_end),
      score=1
    ).with_path(file_path)
    candidate.generate_context(lines)
    return candidate

  @classmethod
  def generate_candidate_dictionary(cls, hunk, source_dir, clinks=None, single=False):
    import logging
    clinks = clinks or []
    logging.info('=== Static Code Analysis ===')
  
    finder = cls()
    candidates_by_path = finder.find_candidates(
      hunk, source_dir, at_state=getattr(hunk, 'state', None), single=single
    )
  
    candidate_dict = {}
    for i, (f, C) in enumerate(candidates_by_path.items()):
      for j, candidate in enumerate(C):
        cid = f"{i+1}.{j}c"
        candidate_dict[cid] = candidate.with_path(f)
  
    if not candidate_dict:
      logging.info('Code base is too dissimilar for this process to work. Returning empty candidate dictionary.')
      return {}
  
    if clinks:
      logging.info('Previous candidate data available')
      candidate_dict = {clink: candidate_dict[clink] for clink in clinks if clink in candidate_dict}
  
    for cid, c in candidate_dict.items():
      logging.info(cid)
      logging.info(f'\n{c.context_str()}')
  
    return candidate_dict

  def find_candidates(self, hunk, source_dir, at_state, single=False):
    if not hasattr(hunk, 'to_b'):
      raise TypeError("hunk must have .to_b() method")
    if not hasattr(hunk, 'filename'):
      raise TypeError("hunk must have .filename attr")
  
    pattern_lines = [line.text.strip() for line in hunk.to_b()]
    blacklist = set()
    psats = {}
    candidates = {}
    _, ext = os.path.splitext(hunk.filename)
  
    def process_file(path):
      with open(path, 'r') as src:
        source_lines = src.read().split('\n')
      clist = self._generate_candidates(
        source_lines, pattern_lines, blacklist, psats
      )
      filtered = [
        c for c in clist
        if not all(pattern.match_text in blacklist
                   for pattern in c.patterns
                   if not pattern.is_partial)
      ]
      return filtered
  
    if single:
      # Only the hunk's base filename, in the given source_dir or absolute
      file_path = os.path.join(source_dir, hunk.filename)
      if os.path.exists(file_path):
        filtered = process_file(file_path)
        if filtered:
          candidates[file_path] = filtered
      return candidates
  
    # Otherwise, walk whole tree
    for root, dirs, files in os.walk(source_dir):
      for directory in list(dirs):
        if directory in ['.pc', 'patches']:
          dirs.remove(directory)
      for file in files:
        if os.path.splitext(file)[1] != ext:
          continue
        path = os.path.join(root, file)
        filtered = process_file(path)
        if filtered:
          candidates[path] = filtered
  
    return candidates

  def _generate_candidates(self, source_lines, pattern_lines, pattern_blacklist, psats):
    from common import Pattern, Candidate

    tracker = IntervalTree()
    partials = set()
    source = {i: line for i, line in enumerate(source_lines, start=1)}
    patterns = {}

    # === 1. AGGREGATE PATTERN MATCHES ===
    for line_no, file_line in source.items():
      fl = file_line.strip()
      if fl in pattern_blacklist: continue
      # Fuzz match all pattern lines
      matches = {line: (fuzz.ratio(fl, line), fuzz.partial_ratio(fl, line)) for line in pattern_lines}
      for match, (ldis, partial_ldis) in matches.items():
        if match in pattern_blacklist or ldis < self.PARTIAL_MATCH_SCORE:
          continue
        # Strong match
        if ldis >= self.NEAR_MATCH_SCORE or partial_ldis >= self.NEAR_MATCH_SCORE:
          if match in patterns: patterns[match].found_at(line_no)
          else: patterns[match] = Pattern(match, line_no)
          current_pattern = patterns[match]
          current_pattern.saturation += 1
          if current_pattern.saturation > self.KILL_THRESHOLD:
            pattern_blacklist.add(match); continue
          if partial_ldis == self.PERFECT_MATCH_SCORE:
            psats[fl] = psats.get(fl, 0) + 1
            if psats[fl] > self.KILL_THRESHOLD:
              pattern_blacklist.add(fl); continue
          # Add candidate for interval tracker
          new_candidate = Candidate(len(pattern_lines), current_pattern)
          tracker[range(*new_candidate.extent)] = new_candidate
        # Partial matches only
        elif partial_ldis >= self.PARTIAL_MATCH_SCORE:
          partials.add(line_no)

    # === 2. MERGE & FILTER CANDIDATES ===
    def list_wrap(obj):
      return obj if isinstance(obj, list) else [obj]
    tracker.merge_overlaps(data_reducer=lambda c1, c2: list_wrap(c1)+list_wrap(c2))

    def score_block(cand_list, span_len):
      full_hits  = sum(
        1 for c in list_wrap(cand_list) for p in c.patterns
        if not p.is_partial
      )
      part_hits  = sum(
        1 for c in list_wrap(cand_list) for p in c.patterns
        if p.is_partial
      )
      ideal_len  = len(pattern_lines)
      length_pen = abs(span_len - ideal_len)          # distance from ideal
      return full_hits * 3 + part_hits - length_pen   # simple composite

    if len(partials) > 0:
      for start, end, candidates_ in tracker:
        first = list_wrap(candidates_)[0]
        for partial in partials:
          if partial >= start and partial < end:
            first.patterns.append(Pattern(source[partial], partial, partial_match=True))

    consolidated_list = [
      Candidate(
        len(pattern_lines),
        *sum((c.patterns for c in list_wrap(candidate_list)), []),
        extent=(max(1,start),end),
        score=score_block(candidate_list, end - max(1,start))
      )
      for start, end, candidate_list in tracker
      if any(p.saturation <= self.KILL_THRESHOLD
             for c in list_wrap(candidate_list)
             for p in c.patterns)
    ]
    for candidate in consolidated_list:
      candidate.generate_context(source_lines)
    return consolidated_list
