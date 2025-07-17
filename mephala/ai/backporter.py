"""
Glue between LLM (mephala.ai.Agent) and the pure diff logic.

Backporter(hunk, candidate, cve_record).run() returns a *new* Hunk that
represents the proposed backport.
"""
from __future__ import annotations
import logging
import os
import textwrap
import difflib
from pathlib import Path

from mephala.ai.agent          import Agent
from mephala.core.models.enums import ActionType
from mephala.core.models.diff_line import DiffLine
from mephala.core.models.action    import Action
from mephala.core.models.candidate import Candidate
from mephala.core.models.cve_record import CVERecord
from mephala.core.diff.hunk        import Hunk
from mephala.core.exceptions       import GarbageCandidateError

log = logging.getLogger(__name__)


class Backporter:
    """
    Orchestrates the old create_backport() pipeline.
    """

    def __init__(self, hunk: Hunk, candidate: Candidate, cve: CVERecord):
        self.hunk      = hunk
        self.candidate = candidate
        self.cve       = cve
        self.agent     = Agent()   # singleton

    # ─────────────────────────────────────────────── public
    def run(self) -> Hunk:
        draft = self._draft_backport()
        actions = self.hunk.generate_actions()
        prune   = self._prune_actions(actions)
        align   = self._align_actions(prune)
        new_hunk = self._weave(align)
        return new_hunk

    # ─────────────────────────────────────────────── steps
    # 1. draft with LLM
    def _draft_backport(self) -> str:
        pattern = self._extension_to_language(Path(self.candidate.path_to).suffix)
        prompt = f"""
Imagine you had a hunk of a patch, generated against version X:
{self.hunk}

It addresses CVE {self.cve.cve}:
{self.cve.desc}

Below is code from the target version where we think the patch must go:
{self.candidate.path_to}:
{self.candidate.context_str()}

Write what that code would look like *after* the patch is applied.
Preserve indentation – do not left-justify.

Respond only with ```{pattern}``` fenced code.
"""
        return self.agent.ask(prompt, pattern=pattern)

    # 2. prune actions via LLM
    def _prune_actions(self, actions: list[Action]) -> list[Action]:
        tpl = {f"t.{i}": a for i, a in enumerate(actions)}
        tgt = {f"0-{i}": a for i, a in enumerate(actions)}  # self-diff template
        yaml = self.agent.ask(
            f"""
You have two ordered dicts:

template: {self._dict_str(tpl)}
target  : {self._dict_str(tgt)}

Mark any target actions that are 'irrelevant' or 'opposites'.
Return YAML:
metadata:
  <target_id>:
    label: <irrelevant|opposites|other>
""",
            output_format="yaml",
        )
        delete_ids = [
            k for k, meta in yaml.get("metadata", {}).items()
            if meta.get("label") in ("irrelevant", "opposites")
        ]
        return [a for idx, a in enumerate(actions) if f"0-{idx}" not in delete_ids]

    # 3. align actions via LLM
    def _align_actions(self, actions: list[Action]):
        action_dict = {f"{i}a": a for i, a in enumerate(actions)}

        yaml = self.agent.ask(
            f"""
This is a hunk of a patch in unified diff format, here called the template hunk:
{self.hunk}

It corresponds to a certain area of a package, which in another version is represented as CANDIDATE:
{self.candidate.context_str()}

CANDIDATE was produced by a call to candidate.context_str(), which produces a representation like:
line_no\\tmatch_type\\tline_of_code (excluding whitespace)

Think of the hunk as a template for how we might try to back-port the patch to the candidate.
A hunk can be understood as a series of actions performed in a given order. An action is either an INSERTION
or a DELETION.

An INSERTION corresponds to a contiguous set of lines of code that we want to inject into the candidate.
A DELETION is a contiguous set of lines of code that we want to remove from the candidate.

An alignment is our attempt to place actions in the candidate, in the correct order, based on where similar
lines of code occur in the template hunk.

In an alignment:
- An INSERTION is represented by one line number, which is the line AFTER WHICH the INSERTION will begin.
- A DELETION is represented by two line numbers, which are the range of code lines that will be deleted.

Examples:
INSERTION of 5 lines at line 23 inserts 5 lines **after** line 23.
DELETION  of 3 lines at lines 32-34 deletes lines 32, 33 and 34.

Here are the ACTIONS we want to perform on the candidate (in dict form):
{self._dict_str(action_dict)}

For each action, determine its alignment(s) in CANDIDATE:
- For INSERTION: output the line number after which to insert.
- For DELETION : output first and last line numbers to be deleted.
- Use the candidate's line numbers.

Output in strict YAML as follows:
alignments:
  <action_id>:
    insert_at:   # ~ if a DELETION, otherwise the line number after which to insert lines.
    delete_from: # ~ if an INSERTION, otherwise the first line number to delete.
    delete_to:   # ~ if an INSERTION, otherwise the last line number to delete.
""",
            output_format="yaml",
        )

        # ─────────────── normalise & validate YAML → list[{'action', 'interval'}]
        aligned: list[dict] = []

        for aid, meta in yaml.get("alignments", {}).items():
            if aid not in action_dict:
                continue

            # INSERTION (single coordinate)
            ins = meta.get("insert_at")
            if ins not in (None, "~"):
                try:
                    interval = [int(ins)]
                except (TypeError, ValueError):
                    continue
                aligned.append({"action": action_dict[aid], "interval": interval})
                continue

            # DELETION (two coordinates)
            frm = meta.get("delete_from")
            to  = meta.get("delete_to")
            if frm in (None, "~") or to in (None, "~"):
                continue
            try:
                interval = [int(frm), int(to)]
            except (TypeError, ValueError):
                continue
            aligned.append({"action": action_dict[aid], "interval": interval})

        return aligned

    # 4. weave & produce new Hunk
    def _weave(self, threads):
        new_hunk = Hunk(self.hunk.filename) 
        new_hunk.weave(self.candidate, threads)
        return new_hunk

    # ─────────────────────────────────────────────── tiny utils
    @staticmethod
    def _dict_str(d):
        return "\n".join(f"{k}:\n{v}" for k, v in d.items())

    @staticmethod
    def _extension_to_language(ext: str):
        return {
            ".py": "python",
            ".c": "c",
            ".cpp": "cpp",
            ".js": "javascript",
            ".java": "java",
        }.get(ext.lower(), "text")
