from __future__ import annotations
import math
from itertools import islice
from typing import List, Dict, Any

from .pattern   import Pattern

class Candidate:
    earliest_hit: int
    latest_hit: int
    context: Dict[int, Dict[str, Any]]

    def __init__(self, target_length: int, *patterns: Pattern,
                 extent=None, score=1):
        self.patterns      = list(patterns)
        self.target_length = target_length
        self.earliest_hit, self.latest_hit = extent or (
            patterns[0].locations[-1], patterns[0].locations[-1]
        )
        self.score     = score
        self.path_to   = ""
        self.context   = {}   # populated by generate_context()

    # ---------------------------------------------------------- geometry
    @property
    def extent(self):
        base_len = self.latest_hit - self.earliest_hit
        extension = self.target_length - base_len
        if extension <= 0:
            start, end = self.earliest_hit, self.latest_hit
        else:
            pad = math.ceil(extension / 2)
            start, end = self.earliest_hit - pad, self.latest_hit + pad
        if start < 1:
            end += 1 - start
            start = 1
        return start, end

    # ---------------------------------------------------------- helpers
    def with_path(self, path: str) -> "Candidate":
        self.path_to = path
        return self

    def generate_context(self, source_lines: List[str]):
        start, end = self.extent
        self.context = {p.locate_in((start, end)): p for p in self.patterns}
        # scrap None key if any pattern not in range
        self.context.pop(None, None)

        for idx, line in islice(enumerate(source_lines, 1), start - 1, end):
            pat = self.context.get(idx)
            self.context[idx] = dict(
                line=line,
                is_pattern=bool(pat and not pat.is_partial),
                is_partial=bool(pat and pat.is_partial),
            )
        self.context = dict(sorted(self.context.items()))
        return self.context

    # ---------------------------------------------------------- views
    def lines(self):
        return [m["line"] for m in self.context.values()]

    def context_str(self):
        def _mk(k: int, v: dict[str, str]) -> str:
            kind = "Part" if v["is_partial"] else "Full" if v["is_pattern"] else "Miss"
            return f"{k}\t{kind}\t{v['line']}"

        return "\n".join(_mk(k, v) for k, v in self.context.items())

    def __str__(self):
        return f"Candidate({self.path_to}, score={self.score})"
