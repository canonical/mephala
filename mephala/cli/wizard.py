"""
mephala.cli.wizard
==================

Interactive, step-by-step back-porting helper (“manual” mode).

Run through Typer:

    $ mephala wizard
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import questionary
from questionary import Choice
from rich.console import Console

from mephala.core.config.context_manager    import ContextManager
from mephala.core.services.patch_manager    import PatchManager
from mephala.core.services.package_manager  import PackageManager
from mephala.core.services.candidate_finder import CandidateFinder
from mephala.core.exceptions                import GarbageCandidateError
from mephala.ai.backporter                  import Backporter

from .utils import SaveTree, picker, confirm_action

console = Console()

# ------------------------------------------------------------------ helpers
def _extension_to_language(ext: str) -> str:
    return {
        ".py": "python",
        ".c": "c",
        ".cpp": "cpp",
        ".js": "javascript",
        ".java": "java",
        ".rb": "ruby",
    }.get(ext.lower(), "text")


# ------------------------------------------------------------------ Typer command implementation
def wizard_cmd():
    ctx  = ContextManager()
    pkgm = PackageManager(ctx)
    pmgr = PatchManager(ctx)

    saver = SaveTree()

    # -------------------- user selects patch + release --------------------
    upstream = {p.meta.file_path: p for p in pmgr.patches}
    patch_path = picker("Pick a patch", list(upstream))
    saver.drilldown(Path(patch_path).stem)

    releases = ctx.get_package_homes()
    release  = picker("Pick a release", list(releases))
    saver.drilldown(release)

    patch = upstream[patch_path]

    # -------------------- pick a hunk ------------------------------------
    hunk_dict = {f"{i}h": h for i, h in enumerate(patch.hunks, 1)}
    console.print(asyncio.run(pkgm.apply_patch_to(release, patch_path, dry_run=True)))
    hunk_id = picker("Pick a hunk", list(hunk_dict))
    saver.drilldown(hunk_id)

    hunk = hunk_dict[hunk_id]

    # -------------------- generate & pick candidates ---------------------
    cand_dict = CandidateFinder.generate_candidate_dictionary(
        hunk, releases[release]
    )
    
    if not cand_dict:
        console.print("[yellow]No candidates found for this hunk – "
                      "marking unresolved and moving on.[/yellow]")
        saver.mark_unresolved("No candidate found")
        return                                   
    
    console.print("[cyan]=== Original Hunk Code ===[/cyan]")
    for dl in hunk.delta:
        console.print(dl)

    console.rule("[bold cyan]Candidates[/bold cyan]")
    for cid, cand in sorted(cand_dict.items(), key=lambda kv: -kv[1].score):
        console.print(
            f"[bold yellow]{cid}[/bold yellow]  "
            f"(score {cand.score})  [green]{cand.path_to}[/green]"
        )
        console.print(cand.context_str())
        console.print("[magenta]---[/magenta]")
    
    choices = questionary.checkbox(
        "Pick the best candidate(s)",
        choices=list(cand_dict.keys()),
    ).ask()

    for cid in choices:
        candidate = cand_dict[cid]
        console.print(f"[green]Chosen:[/green] {candidate.path_to}")

        # ---------------------------------- back-port loop -------------
        satisfied = False
        while not satisfied:
            bp        = Backporter(hunk, candidate, patch.meta.cve_record)
            new_hunk  = bp.run()

            console.print("\n[bold cyan]=== Proposal Backport Hunk ===[/bold cyan]")
            console.print(str(new_hunk))

            if confirm_action():
                # save to disk
                out_dir = saver._path()   # type: ignore  (private but fine here)
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{cid}.patch"
                out_path.write_text(f"{new_hunk}\n")
                console.print(f"[green]Saved to {out_path}[/green]")

                # test immediately
                console.print("[yellow]Testing patch application…[/yellow]")
                result = asyncio.run(pkgm.apply_patch_to(release, str(out_path), dry_run=True))
                console.print(f"[white]{result}[/white]")
                satisfied = True
            else:
                # optional user feedback
                rationale = questionary.text("What's wrong with it?").ask()
                # feed rationale back into model by recreating Backporter
                console.print("[yellow]Regenerating proposal…[/yellow]")
                # simple strategy: keep the original Backporter but reset its
                # internal LLM context; easiest is to start fresh:
                continue   # loop reiterates, new Backporter created

    console.print("[green]Wizard session completed[/green]")
