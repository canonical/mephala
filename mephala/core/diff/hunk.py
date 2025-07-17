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
import difflib
import logging

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
        first = next((i for i, dl in enumerate(self.delta) if dl.line_type != LineType.NOCHANGE), None)
        last  = next((len(self.delta) - 1 - i for i, dl in enumerate(reversed(self.delta)) if dl.line_type != LineType.NOCHANGE), None)
        if first is None or last is None:
            raise GarbageCandidateError("Delta has only NOCHANGE lines")
        lhs_off = first - self.MARGIN
        self.delta = self.delta[lhs_off:last + self.MARGIN + 1]
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

            # ---------- INSERTION --------------------------------------
            if len(iv) == 1:
                anchor = iv[0]
                self._add_nochange(ctx, anchor)      # keep the anchor line

                # desired left margin of the block
                anchor_ws = len(ctx[anchor]["line"]) - len(ctx[anchor]["line"].lstrip(" \t"))
                tpl_ws    = len(action.lines[0].text) - len(action.lines[0].text.lstrip(" \t"))

                for dl in action.lines:
                    raw       = dl.text
                    raw_ws    = len(raw) - len(raw.lstrip(" \t"))
                    rel_ws    = raw_ws - tpl_ws                 # indentation relative to block start
                    new_ws    = max(anchor_ws + rel_ws, 0)      # shift block to anchor column
                    stripped  = raw.lstrip(" \t")
                    new_text  = (" " * new_ws) + stripped
                    self.delta.append(DiffLine(new_text, LineType.INSERTION))

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
