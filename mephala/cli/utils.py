from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, List

import questionary
import typer
from rich.console import Console
from rich.prompt  import Prompt

from mephala.core.config.context_manager import ContextManager

console = Console()
ctx     = ContextManager()

# ----------------------------------------------------------------------
class SaveTree:

    BASE_DIR = ".metadata"

    def __init__(self, overwrite: bool = False):
        self.stack: List[str] = [str(ctx.cwd), self.BASE_DIR]
        self.overwrite = overwrite
        self._mkdir(Path(*self.stack))

    # low-level helpers -------------------------------------------------
    def _mkdir(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)

    def _path(self) -> Path:
        return Path(*self.stack)

    # directory traversal ----------------------------------------------
    def drilldown(self, name: str):
        self.stack.append(name)
        self._mkdir(self._path())

    def step_up(self):
        if len(self.stack) > 2:
            self.stack.pop()

    def dir_is_empty(self) -> bool:
        try:
            return not any(self._path().iterdir())
        except FileNotFoundError:
            return True

    # save helpers ------------------------------------------------------
    def _write(self, filename: str, content: str):
        target = self._path() / filename
        if target.exists() and not self.overwrite:
            console.print(f"[yellow]SKIP[/yellow] would overwrite {target}")
            return
        target.write_text(content)

    def save_hunk(self, hunk, *, name="auto.patch"):
        self._write(name, f"{hunk}\n")

    def save_choices(self, cand_dict, *, name="choices.txt"):
        body = ""
        for i, cand in enumerate(sorted(cand_dict.values(), key=lambda c: -c.score), 1):
            body += f"Candidate {i} (score {cand.score}):\n"
            body += f"path: {cand.path_to}\n"
            body += "\n".join(cand.lines())
            body += "\n---\n"
        self._write(name, body)

    def mark_unresolved(self, reason: str, *, name="unresolved.txt"):
        self._write(name, reason)

# ----------------------------------------------------------------------
# small UI helpers
def picker(title: str, options: List[str]) -> str:
    console.print(title)
    for idx, opt in enumerate(options, 1):
        console.print(f"{idx}. {opt}")
    choice = Prompt.ask("Pick", choices=[str(i) for i in range(1, len(options) + 1)])
    return options[int(choice) - 1]


def confirm_action() -> bool:
    return questionary.select("Proceed?", choices=["Yes", "No"]).ask() == "Yes"
