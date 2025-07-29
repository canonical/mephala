"""
PackageManager
==============

Manipulates on-disk source packages and applies quilt patches in a
sandbox.

Layer:  core.services
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------

class PackageManager:
    """
    Coordinates operations on a single source package across multiple
    Ubuntu releases, using ContextManager for paths / metadata.
    """

    def __init__(self, context) -> None:
        """
        Parameters
        ----------
        context : mephala.core.config.context_manager.ContextManager
            An already-initialised context object.
        """
        self.ctx = context

        # ------------------------------------------------------------------
        # 1. locate package check-outs per release  →  ctx['package_homes']
        # ------------------------------------------------------------------
        if not self.ctx.value_exists("package_homes"):
            pkg = self.ctx.get_package()
            pkg_homes: Dict[str, str] = {}

            for rel in self.ctx.supported_releases:
                rel_dir = Path(self.ctx.package_workspace) / pkg / rel
                matches = glob.glob(str(rel_dir / f"{pkg}-*"))
                if matches:
                    pkg_homes[rel] = matches[0]

            self.ctx.save("package_homes", pkg_homes)

        # ------------------------------------------------------------------
        # 2. pull CVE descriptions from ubuntu-cve-tracker  →  ctx['cve_descriptions']
        # ------------------------------------------------------------------
        try:
            sys.path.insert(0, str(Path(self.ctx.uct) / "scripts"))
            from cve_lib import load_cve                                 # type: ignore

            cve_dict = {
                cve: load_cve(str(Path(self.ctx.uct) / "active" / cve))
                for cve in self.ctx.get_cves()
            }
            if not self.ctx.value_exists("cve_descriptions"):
                self.ctx.save(
                    "cve_descriptions",
                    {cve: data["Description"] for cve, data in cve_dict.items()},
                )
        finally:
            if sys.path[0].endswith("/scripts"):
                sys.path.pop(0)   # restore import path

    # ════════════════════════════════════════════════════════════════════
    #                         PUBLIC  API
    # ════════════════════════════════════════════════════════════════════
    async def apply_patch_to(
        self, release: str, patch_path: str, *, dry_run: bool = True
    ) -> str:
        """
        Import, push, (optionally) pop & delete a patch using quilt inside
        the package workspace.

        Returns stdout of `quilt push` (even in dry-run mode).
        """

        # Guard only the hunks produced by Mephala itself – they always live
        # somewhere beneath .metadata/
        from mephala.core.utils.patch_checks import is_patch_well_formed
        if ".metadata" in Path(patch_path).parts:
            if not is_patch_well_formed(Path(patch_path).read_text()):
                raise RuntimeError(
                    f"{patch_path} looks malformed – aborting; inspect struct_errors.txt"
                )

        pkg_home = self.ctx.get_package_homes().get(release)
        if not pkg_home:
            raise ValueError(f"Unknown release '{release}'")

        import_cmd = ["quilt", "import", "-f", patch_path]
        push_cmd   = ["quilt", "push"]
        pop_cmd    = ["quilt", "pop"]
        del_cmd    = ["quilt", "delete", os.path.basename(patch_path)]

        # quilt import
        await self._run(import_cmd, cwd=pkg_home)

        # quilt push
        stdout, _stderr, rc = await self._run(push_cmd, cwd=pkg_home, capture=True, ignore_error=True)

        if dry_run:
            # rollback regardless of success
            if rc == 0:
                await self._run(pop_cmd,  cwd=pkg_home)
            await self._run(del_cmd, cwd=pkg_home)
        else:
            # on real run we delete only on error
            if rc != 0:
                await self._run(del_cmd, cwd=pkg_home)
                raise RuntimeError(f"quilt push failed (rc={rc})")

        return stdout

    # ════════════════════════════════════════════════════════════════════
    #                         INTERNAL HELPERS
    # ════════════════════════════════════════════════════════════════════
    # ─── inside class PackageManager ────────────────────────────────────────
    async def _run(
        self,
        cmd: list[str],
        *,
        cwd: str,
        capture: bool = False,
        ignore_error: bool = False,
    ) -> tuple[str, str, int]:
        """
        Async wrapper around subprocess; returns (stdout, stderr, rc).
        """
        log.debug("Running %s (cwd=%s)", " ".join(cmd), cwd)
    
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()
    
        stdout = stdout_b.decode() if stdout_b is not None else ""
        stderr = stderr_b.decode() if stderr_b is not None else ""
    
        if proc.returncode != 0 and not ignore_error:
            log.error(stderr)
            raise subprocess.CalledProcessError(proc.returncode, cmd, stdout, stderr)
    
        if not capture:
            return "", "", proc.returncode
        return stdout, stderr, int(proc.returncode)

    # ════════════════════════════════════════════════════════════════════
    #                    OPTIONAL:  vulnerability scrape
    # ════════════════════════════════════════════════════════════════════
    def scrape_vulnerabilities(self) -> Dict[str, Any]:
        """
        Parses ubuntu-cve-tracker ‘active’ files for the current package
        and returns  {release : {cve : {'affected': ['main', 'esm']}}}
        """
        vulnerability_dict: Dict[str, Dict[str, Any]] = {}
        pkg = self.ctx.get_package()

        for cve in self.ctx.get_cves():
            with open(Path(self.ctx.uct) / "active" / cve) as fp:
                patches_start = False
                for line in fp:
                    if pkg in line.strip() and line.strip().startswith("Patches_"):
                        patches_start = True
                    elif patches_start and ":" in line:
                        release_name, status = line.strip().split(":", 1)
                        affected = (
                            "esm"
                            if "/esm" in release_name or "esm-apps/" in release_name
                            else "main"
                        )

                        release = (
                            release_name.split("_")[0]
                            .replace("/esm", "")
                            .replace("esm-apps/", "")
                        )

                        if release not in self.ctx.supported_releases:
                            continue
                        if "needed" in status or "needs-triage" in status:
                            vulnerability_dict.setdefault(release, {}) \
                                             .setdefault(cve, {"affected": []}) \
                                             ["affected"].append(affected)
                    elif patches_start and ":" not in line:
                        break

        return vulnerability_dict
