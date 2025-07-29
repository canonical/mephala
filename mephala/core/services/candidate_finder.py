"""
CandidateFinder
===============

Locates regions in a source tree that most closely resemble the “to-b”
side of a patch hunk.

Layer position
--------------
• Part of *core.services*: orchestrates work on model objects but keeps
  heavy AI / CLI out.

Public API
----------
generate_candidate_dictionary(hunk, source_dir, *, clinks=None,
                              single=False) -> dict[str, Candidate]
candidate_from_file_region(file_path, start_line, length, fuzz=0) -> Candidate | None
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List

from intervaltree import IntervalTree
from fuzzywuzzy import fuzz

from mephala.core.models import Pattern, Candidate

log = logging.getLogger(__name__)


class CandidateFinder:
    """
    Heuristic search for candidate regions.

    Tweakable knobs are exposed as constructor arguments so tests can dial
    them up or down easily.
    """

    def __init__(
        self,
        *,
        kill_threshold: int = 4,
        partial_match_score: int = 30,
        near_match_score: int = 90,
        perfect_match_score: int = 100,
    ) -> None:
        self.KILL_THRESHOLD = kill_threshold
        self.PARTIAL_MATCH_SCORE = partial_match_score
        self.NEAR_MATCH_SCORE = near_match_score
        self.PERFECT_MATCH_SCORE = perfect_match_score

    # ────────────────────────────────────────────────────────── static helper
    @staticmethod
    def candidate_from_file_region(
        file_path: str, start_line: int, length: int, *, fuzz: int = 0
    ) -> Candidate | None:
        """
        Convenience helper: pull *one* slice out of a file, centred on
        `start_line`, and wrap it in a Candidate object.
        """
        if not os.path.exists(file_path):
            return None

        with open(file_path, "r") as fp:
            lines = fp.read().splitlines()

        slice_start = max(start_line - 1 - fuzz, 0)          # 1-based → 0-based
        slice_end   = min(slice_start + length + 2 * fuzz, len(lines))
        region      = lines[slice_start:slice_end]
        if not region:
            return None

        pattern_line = region[0]
        fake_pattern = Pattern(pattern_line, slice_start + 1)
        cand = (
            Candidate(length, fake_pattern, extent=(slice_start + 1, slice_end), score=1)
            .with_path(file_path)
        )
        cand.generate_context(lines)
        return cand

    # ────────────────────────────────────────────────────────── public facade
    @classmethod
    def generate_candidate_dictionary(
        cls,
        hunk,
        source_dir: str,
        *,
        clinks: List[str] | None = None,
        single: bool = False,
    ) -> Dict[str, Candidate]:
        """
        Top-level entry: walk `source_dir`, call `find_candidates`, and
        return `{candidate_id : Candidate}` suitable for the CLI.
        """
        clinks = clinks or []
        log.info("=== Static Code Analysis ===")

        finder = cls()
        by_path = finder.find_candidates(
            hunk, source_dir, at_state=getattr(hunk, "state", None), single=single
        )

        result: Dict[str, Candidate] = {}
        for i, (path, cands) in enumerate(by_path.items(), 1):
            for j, cand in enumerate(cands):
                result[f"{i}.{j}c"] = cand.with_path(path)

        if clinks:
            log.info("Previous candidate links supplied; filtering to keep them")
            result = {cid: result[cid] for cid in clinks if cid in result}

        for cid, cand in result.items():
            log.info("%s\n%s", cid, cand.context_str())

        return result

    # ────────────────────────────────────────────────────────── heavy lifting
    def find_candidates(self, hunk, source_dir: str, *, at_state, single=False):
        """
        Returns {path : [Candidate, …]}
        """
        if not hasattr(hunk, "to_b"):
            raise TypeError("hunk must have .to_b() method")
        if not hasattr(hunk, "filename"):
            raise TypeError("hunk must have .filename attr")

        pattern_lines = [line.text.strip() for line in hunk.to_b()]
        blacklist: set[str] = set()
        psats: dict[str, int] = {}
        candidates: dict[str, List[Candidate]] = {}

        _, ext = os.path.splitext(hunk.filename)

        def process_file(path: str):
            with open(path, "r") as fp:
                source_lines = fp.read().splitlines()
            clist = self._generate_candidates(source_lines, pattern_lines, blacklist, psats)
            return [
                c
                for c in clist
                if not all(
                    p.match_text in blacklist for p in c.patterns if not p.is_partial
                )
            ]

        if single:
            file_path = os.path.join(source_dir, hunk.filename)
            if os.path.exists(file_path):
                filtered = process_file(file_path)
                if filtered:
                    candidates[file_path] = filtered
            return candidates

        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in {".pc", "patches"}]
            for fname in files:
                if os.path.splitext(fname)[1] != ext:
                    continue
                path = os.path.join(root, fname)
                filtered = process_file(path)
                if filtered:
                    candidates[path] = filtered

        return candidates

    # ────────────────────────────────────────────────────────── inner engine
    def _generate_candidates(
        self,
        source_lines: List[str],
        pattern_lines: List[str],
        blacklist: set[str],
        psats: Dict[str, int],
    ) -> List[Candidate]:
        tracker = IntervalTree()
        partials: set[int] = set()
        source = {i: line for i, line in enumerate(source_lines, 1)}
        patterns: Dict[str, Pattern] = {}

        # ---------- 1. aggregate pattern matches
        for line_no, raw in source.items():
            stripped = raw.strip()
            if stripped in blacklist:
                continue

            matches = {
                line: (fuzz.ratio(stripped, line), fuzz.partial_ratio(stripped, line))
                for line in pattern_lines
            }

            for match, (ldis, pldis) in matches.items():
                if match in blacklist or ldis < self.PARTIAL_MATCH_SCORE:
                    continue

                # strong match
                if ldis >= self.NEAR_MATCH_SCORE or pldis >= self.NEAR_MATCH_SCORE:
                    pat = patterns.setdefault(match, Pattern(match, line_no))
                    pat.found_at(line_no)
                    pat.saturation += 1
                    if pat.saturation > self.KILL_THRESHOLD:
                        blacklist.add(match)
                        continue

                    if pldis == self.PERFECT_MATCH_SCORE:
                        psats[stripped] = psats.get(stripped, 0) + 1
                        if psats[stripped] > self.KILL_THRESHOLD:
                            blacklist.add(stripped)
                            continue

                    cand = Candidate(len(pattern_lines), pat)
                    tracker[range(*cand.extent)] = cand

                # partial matches only
                elif pldis >= self.PARTIAL_MATCH_SCORE:
                    partials.add(line_no)

        # ---------- 2. merge & score
        def as_list(obj):
            return obj if isinstance(obj, list) else [obj]

        tracker.merge_overlaps(data_reducer=lambda a, b: as_list(a) + as_list(b))

        def score_block(cand_list, span_len):
            full_hits = sum(
                1
                for c in as_list(cand_list)
                for p in c.patterns
                if not p.is_partial
            )
            part_hits = sum(
                1
                for c in as_list(cand_list)
                for p in c.patterns
                if p.is_partial
            )
            ideal = len(pattern_lines)
            length_penalty = abs(span_len - ideal)
            return full_hits * 3 + part_hits - length_penalty

        if partials:
            for start, end, cands in tracker:
                first = as_list(cands)[0]
                for p in partials:
                    if start <= p < end:
                        first.patterns.append(Pattern(source[p], p, partial_match=True))

        consolidated: List[Candidate] = [
            Candidate(
                len(pattern_lines),
                *sum((c.patterns for c in as_list(cand_list)), []),
                extent=(max(1, start), end),
                score=score_block(cand_list, end - max(1, start)),
            )
            for start, end, cand_list in tracker
            if any(
                p.saturation <= self.KILL_THRESHOLD
                for c in as_list(cand_list)
                for p in c.patterns
            )
        ]

        for cand in consolidated:
            cand.generate_context(source_lines)
        return consolidated
