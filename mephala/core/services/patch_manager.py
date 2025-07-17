"""
PatchManager
============

Collects all *.patch files for the current package, parses them into
Patch objects, and exposes them to the rest of the application.

Layer: core.services
"""

from __future__ import annotations

import glob
import logging
import os
from pathlib import Path
from typing import List

from mephala.core.config.context_manager import ContextManager
from mephala.core.diff.patch             import Patch
from mephala.core.models.cve_record      import CVERecord

log = logging.getLogger(__name__)


class PatchManager:
    """
    Reads patches from  <cwd>/patches/*.patch  (cwd == ctx.cwd) and turns
    them into Patch objects tagged with their CVE IDs.
    """

    PATCHES_DIR = "patches"

    # ------------------------------------------------------------------ init
    def __init__(self, ctx: ContextManager) -> None:
        """
        Parameters
        ----------
        ctx : ContextManager
            Runtime context (already contains patch_links, package_homes,
            cve_descriptions, …).
        """
        self.ctx = ctx

        # sanity-check that the context was fully populated earlier
        assert self.ctx.values_exist(
            "patch_links", "package_homes", "cve_descriptions"
        ), "ContextManager missing required keys"

        self.patch_dir: Path = self.ctx.cwd / self.PATCHES_DIR
        self.patch_files: List[str] = glob.glob(str(self.patch_dir / "*.patch"))

        links = self.ctx.get_patch_links()          # {patch_filename : CVE-ID}
        descs = self.ctx.get_cve_descriptions()     # {CVE-ID : description}

        self.patches: List[Patch] = []
        for patch_path in self.patch_files:
            patch_name = os.path.basename(patch_path)
            if patch_name not in links:
                log.warning("No CVE link for patch %s – skipping", patch_name)
                continue

            cve_id = links[patch_name]
            cve_rec = CVERecord(cve_id, descs.get(cve_id, ""))
            meta = self._build_meta(cve_rec, "upstream", patch_path)
            self.patches.append(Patch.from_file(patch_path, meta))

        log.info("Loaded %d patches from %s", len(self.patches), self.patch_dir)

    # ---------------------------------------------------------------- helpers
    def _build_meta(self, cve_record: CVERecord, release: str, path: str):
        from mephala.core.models.patch_meta import PatchMeta

        return PatchMeta(cve_record=cve_record, release=release, file_path=path)

    # ---------------------------------------------------------------- repr
    def __repr__(self) -> str:  # pragma: no cover
        return f"<PatchManager {len(self.patches)} patches from {self.patch_dir}>"
