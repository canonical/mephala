"""
`mephala auto-wizard`

Mostly the old logic from main.py::auto_wizard but with new imports and
helpers taken from cli.utils.
"""
from __future__ import annotations

import asyncio
import os
from enum import Enum, auto
from pathlib import Path

from rich.console import Console

from mephala.core.config.context_manager      import ContextManager
from mephala.core.services.package_manager    import PackageManager
from mephala.core.services.patch_manager      import PatchManager
from mephala.core.services.candidate_finder   import CandidateFinder
from mephala.core.exceptions                  import GarbageCandidateError
from mephala.core.models.enums                import LineType
from mephala.core.models.diff_line            import DiffLine
from mephala.core.diff.hunk                   import Hunk
from mephala.ai.backporter                    import Backporter

from .utils import SaveTree, picker, confirm_action

console = Console()
ctx     = ContextManager()
pkg_mgr = PackageManager(ctx)
pch_mgr = PatchManager(ctx)

saver   = SaveTree()

# ----------------------------------------------------- enums / helpers
class HunkApplyStatus(Enum):
    SUCCESS  = auto()
    FUZZ     = auto()
    NO_FILE  = auto()
    FAIL     = auto()

def parse_quilt_output_by_hunk(output: str):
    """
    Replicates the old regex-based parser; returns
    [(HunkApplyStatus, line_no), …]
    """
    import re
    status = []
    fail  = re.compile(r"Hunk #\d+ FAILED at (\d+)\.")
    fuzz  = re.compile(r"Hunk #\d+ succeeded at (\d+) with fuzz")
    succ  = re.compile(r"Hunk #\d+ succeeded at (\d+)")
    nofil = re.compile(r"No file to patch\.  Skipping patch\.")
    ign   = re.compile(r"(\d+) out of (\d+) hunks? ignored")

    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if m := fail.search(line):
            status.append((HunkApplyStatus.FAIL, int(m.group(1))))
        elif m := fuzz.search(line):
            status.append((HunkApplyStatus.FUZZ, int(m.group(1))))
        elif m := succ.search(line):
            status.append((HunkApplyStatus.SUCCESS, int(m.group(1))))
        elif nofil.search(line):
            look = 0
            while (i + look < len(lines)) and (look < 3):
                if m := ign.search(lines[i + look]):
                    n = int(m.group(1))
                    status.extend([(HunkApplyStatus.NO_FILE, -1)] * n)
                    break
                look += 1
        i += 1
    return status

# ----------------------------------------------------- public Typer command
def auto_wizard_cmd():
    # 1. user picks patch & release
    upstream = {p.meta.file_path: p for p in pch_mgr.patches}
    patch_path = picker("Pick a patch", list(upstream))
    saver.drilldown(Path(patch_path).stem)

    releases = ctx.get_package_homes()
    release  = picker("Pick a release", list(releases))
    saver.drilldown(release)

    patch = upstream[patch_path]

    # 2. parse hunks + run quilt dry-run once
    hunk_dict = {f"{i}h": h for i, h in enumerate(patch.hunks, 1)}
    quilt_out = asyncio.run(
        pkg_mgr.apply_patch_to(release, patch_path, dry_run=True)
    )
    per_hunk = parse_quilt_output_by_hunk(quilt_out)

    # 3. iterate hunks
    for idx, (hid, hunk) in enumerate(hunk_dict.items()):
        status, lineno = per_hunk[idx]
        console.print(f"[bold yellow]Hunk {hid}: {status.name}[/bold yellow]")
        saver.drilldown(hid)

        if not saver.dir_is_empty():
            console.print("[yellow]Skipping (directory not empty)[/yellow]")
            saver.step_up()
            continue

        # ------------------------------------ SUCCESS
        if status == HunkApplyStatus.SUCCESS:
            saver.save_hunk(hunk)

        # ------------------------------------ FUZZ
        elif status == HunkApplyStatus.FUZZ:
            file_path = Path(releases[release]) / hunk.filename
            candidate = CandidateFinder.candidate_from_file_region(
                file_path, lineno, len(hunk.to_b())
            )
            if candidate:
                fixed = _fix_hunk_fuzz(hunk, candidate)
                saver.save_hunk(fixed)
            else:
                saver.mark_unresolved("Could not extract candidate for fuzz")

        # ------------------------------------ FAIL / NO_FILE
        else:
            single = status == HunkApplyStatus.FAIL
            cand_dict = CandidateFinder.generate_candidate_dictionary(
                hunk, releases[release], single=single
            )
            if not cand_dict:
                saver.mark_unresolved("No candidate found")
            else:
                best = max(cand_dict.values(), key=lambda c: c.score)
                if best.score < 3:
                    saver.mark_unresolved("No high-confidence candidate")
                else:
                    try:
                        new_hunk = Backporter(hunk, best, patch.meta.cve_record).run()
                        saver.save_hunk(new_hunk)
                        saver.save_choices(cand_dict)
                    except GarbageCandidateError:
                        saver.mark_unresolved("Bad candidate produces garbage")

        saver.step_up()

    console.print("[green]AUTO back-port completed![/green]")

# ----------------------------------------------------- misc helper
def _fix_hunk_fuzz(hunk: Hunk, cand, fuzz: int = 3) -> Hunk:
    """
    Replaces the first/last `fuzz` context lines of the hunk with lines
    from the candidate slice.
    """
    top_ctx  = cand.lines[:fuzz]
    bot_ctx  = cand.lines[-fuzz:] if fuzz else []
    mid_part = hunk.to_b()[fuzz : len(hunk.to_b()) - fuzz or None]

    new_lines = (
        [DiffLine(t, LineType.NOCHANGE) for t in top_ctx]
        + mid_part
        + [DiffLine(t, LineType.NOCHANGE) for t in bot_ctx]
    )

    fixed = Hunk(hunk.filename, new_lines)
    fixed.top = hunk.top
    return fixed
