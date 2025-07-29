"""
Pure diff / weaving logic.

Public API
----------
Hunk.from_diff_lines(lines [, filename]) → Hunk
hunk.generate_actions()                 → list[Action]
hunk.weave(candidate, threads)          → None   (modifies self.delta)

Other modules (cli, services, ai) may call these but must not mutate
internal state directly.
"""
from __future__ import annotations

import textwrap
import logging
import re

from mephala.core.models.enums      import HunkState, LineType, ActionType
from mephala.core.models.diff_line  import DiffLine
from mephala.core.models.action     import Action
from mephala.core.models.candidate  import Candidate
from mephala.core.exceptions        import (
    GarbageCandidateError,
    ProcessingException,
)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────── helpers
def _dict_str(d):
    return "\n".join(f"{k}:\n{v}" for k, v in d.items())


# ─────────────────────────────────────────────────────────────── class
class Hunk:
    """
    A single unified-diff hunk (no file-names, just the body section).
    """

    MARGIN = 3  # context lines kept when trimming
    # ---------------------------------------------------------------- init
    def __init__(self, filename: str, delta: list[DiffLine] | None = None):
        self.filename = filename
        self.delta: list[DiffLine] = delta or []
        self.top: int | None = None      # top line after weave()

    # ---------------------------------------------------------------- magic
    def __str__(self):
        start = self.top or ""
        a_file = f"a/{self.filename}"
        b_file = f"b/{self.filename}"
        header = f"@@ -{start},{len(self.to_a())} +{start},{len(self.to_b())} @@"
        body   = "\n".join(str(dl) for dl in self.delta)
        return f"--- {a_file}\n+++ {b_file}\n{header}\n{body}"

    # ---------------------------------------------------------------- parse
    @classmethod
    def from_diff_lines(cls, lines: list[str], filename: str | None = None):
        delta: list[DiffLine] = []
        auto_fname = filename

        for ln in lines:
            if ln.startswith(("---", "+++")):
                if not auto_fname:
                    try:
                        auto_fname = "/".join(ln.split(" ")[1].split("/")[1:]).strip()
                    except Exception:
                        auto_fname = None
                continue
            if ln.startswith("@@"):
                continue
            if ln.startswith("+"):
                delta.append(DiffLine(ln[1:], LineType.INSERTION))
            elif ln.startswith("-"):
                delta.append(DiffLine(ln[1:], LineType.DELETION))
            else:
                txt = ln[1:] if ln.startswith(" ") else ln
                delta.append(DiffLine(txt, LineType.NOCHANGE))

        if not auto_fname:
            auto_fname = "<unknown>"

        h = cls(auto_fname)
        h.delta = delta
        return h

    # ---------------------------------------------------------------- views
    def to_a(self):
        return [dl for dl in self.delta if dl.line_type in (LineType.NOCHANGE, LineType.DELETION)]

    def to_b(self):
        return [dl for dl in self.delta if dl.line_type in (LineType.NOCHANGE, LineType.INSERTION)]

    def state(self, during: HunkState):
        return self.to_a() if during == HunkState.INITIAL else self.to_b()

    # ---------------------------------------------------------------- clean-up
    def trim_delta(self):
        """
        Keep at most `MARGIN` unchanged lines before and after the first/
        last edited line.  Works even when the hunk contains fewer than
        `MARGIN` leading or trailing context lines.
        """
        first = next(
            (i for i, dl in enumerate(self.delta)
             if dl.line_type != LineType.NOCHANGE),
            None
        )
        last = next(
            (len(self.delta) - 1 - i for i, dl in enumerate(reversed(self.delta))
             if dl.line_type != LineType.NOCHANGE),
            None
        )
        if first is None or last is None:
            raise GarbageCandidateError("Delta has only NOCHANGE lines")

        # ----- clamp slice to valid list indices -------------------------
        lhs_off   = max(first - self.MARGIN, 0)
        rhs_limit = min(last  + self.MARGIN, len(self.delta) - 1)

        # ----- apply slice ----------------------------------------------
        self.delta = self.delta[lhs_off : rhs_limit + 1]

        # adjust absolute top-line number of the hunk
        if self.top is not None:
            self.top += lhs_off
    # ---------------------------------------------------------------- actions
    def generate_actions(self) -> list[Action]:
        actions: list[Action] = []
        current: Action | None = None
        for dl in self.delta:
            if dl.line_type == LineType.NOCHANGE:
                if current:
                    actions.append(current)
                    current = None
                continue

            atype = ActionType.INSERTION if dl.line_type == LineType.INSERTION else ActionType.DELETION
            if not current or current.action_type != atype:
                if current:
                    actions.append(current)
                current = Action(atype, dl)
            else:
                current += dl
        if current:
            actions.append(current)
        self.actions = actions
        return actions

    # ---------------------------------------------------------------- weaving  (pure algorithm)
    def weave(self, candidate: Candidate, threads: list[dict]):
        """
        Build self.delta by walking the candidate context and executing each
        thread action.

        threads: [{'action': Action, 'interval': [start] or [start,end]}, ...]
        """
        ctx       = candidate.context
        ctx_keys  = sorted(ctx)
        line_no   = ctx_keys[0]
        self.top  = line_no
        self.delta = []

        for thread in threads:
            action = thread["action"]
            iv     = thread["interval"]

            # sanity-check interval lies within the candidate slice
            if iv[0] < ctx_keys[0] or iv[-1] > ctx_keys[-1]:
                raise GarbageCandidateError(
                    f"interval {iv} outside candidate context "
                    f"{ctx_keys[0]}–{ctx_keys[-1]}"
                )

            # ---------- untouched context before the interval ----------
            while line_no < iv[0]:
                self._add_nochange(ctx, line_no)
                line_no += 1

            # ---------- INSERTION (single coordinate) ------------------
            if len(iv) == 1:
                anchor = iv[0]

                # The anchor might have been deleted earlier in *this* hunk.
                # Walk upwards until we find a line that is still present.
                while anchor not in ctx and anchor > ctx_keys[0]:
                    anchor -= 1

                # 0. unchanged anchor line first
                if anchor >= line_no:
                    self._add_nochange(ctx, anchor)

                # 1. indentation – borrow from the first non-blank line below
                look = anchor + 1
                while look in ctx and ctx[look]["line"].strip() == "":
                    look += 1
                indent = re.match(r"[ \t]*",
                                  ctx.get(look, {}).get("line", "")).group(0)

                # 2. write insertion lines, but *skip* any line that would be
                #    identical to the one that follows after we have finished
                next_ctx_line = ctx.get(anchor + 1, {}).get("line", "").rstrip()

                tpl_block = textwrap.dedent("\n".join(dl.text for dl in action.lines))
                for raw in tpl_block.splitlines():
                    candidate_line = f"{indent}{raw}"
                    if candidate_line.rstrip() == next_ctx_line:
                        # would duplicate the following context line – skip
                        continue
                    self.delta.append(DiffLine(candidate_line, LineType.INSERTION))

                line_no = anchor + 1

            # ---------- DELETION --------------------------------------
            else:
                for j in range(iv[0], iv[-1] + 1):
                    self.delta.append(DiffLine(ctx[j]["line"], LineType.DELETION))
                line_no = iv[-1] + 1

        # ---------- trailing context after the last thread -------------
        while line_no <= ctx_keys[-1]:
            self._add_nochange(ctx, line_no)
            line_no += 1

        # final tidy-up
        self.trim_delta()

    # -------------------------------------------------- helpers
    def _add_nochange(self, ctx, ln):
        if ln not in ctx:
            raise ProcessingException(f"missing ctx line {ln}")
        self.delta.append(DiffLine(ctx[ln]["line"], LineType.NOCHANGE))
