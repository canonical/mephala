from __future__ import annotations
from typing import List

from mephala.core.models.diff_line  import DiffLine
from mephala.core.models.enums      import LineType
from mephala.core.models.patch_meta import PatchMeta
from .hunk                          import Hunk      # existing algorithmic Hunk

class Patch:
    """A parsed patch file: meta (no I/O) + list[Hunk]."""

    def __init__(self, meta: PatchMeta, hunks: List[Hunk]):
        self.meta  = meta
        self.hunks = hunks

    # ------------------------------------------------ class helpers
    @classmethod
    def from_file(cls, file_path: str, meta: PatchMeta) -> "Patch":
        with open(file_path) as fp:
            lines = fp.read().splitlines()
        hunks = cls._to_hunks(lines)
        return cls(meta, hunks)

    # --------------------------------------------------------------------- internals
    @staticmethod
    def _to_hunks(lines: list[str]) -> list[Hunk]:
        hunks: list[Hunk] = []
        collecting_hunk   = False
    
        a_filename: str | None = None
        b_filename: str | None = None
        collecting_filenames   = False

        def _conv(header_line: str) -> str:
            return "/".join(header_line.split(" ")[1].split("/")[1:]).strip()    
    
        for line in lines:
            # ----- new file header ('--- a/…')
            if line.startswith("---"):
                try:
                    a_filename = _conv(line)
                    collecting_filenames = True
                except IndexError:
                    continue
    
            # ----- matching '+++ b/…' header
            elif line.startswith("+++"):
                if not collecting_filenames:
                    continue
                b_filename = _conv(line)
                if a_filename != b_filename:
                    # mismatch usually means rename; still use b_filename
                    pass
    
                hunks.append(Hunk(b_filename))
                collecting_hunk = False
    
            # ----- start of a new hunk body
            elif line.startswith("@@"):
                if collecting_hunk:
                    hunks.append(Hunk(hunks[-1].filename))
                collecting_hunk = True
    
            # ----- lines inside the current hunk
            elif collecting_hunk:
                hunks[-1].delta.append(
                    DiffLine(
                        line[1:],
                        LineType.INSERTION if line[0] == "+"
                        else LineType.DELETION if line[0] == "-"
                        else LineType.NOCHANGE,
                    )
                )
    
        return hunks
    # ------------------------------------------------ str
    def __str__(self):
        out = ""
        for h in self.hunks:
            out += str(h) + "\n"
        return out
