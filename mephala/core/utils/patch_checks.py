"""
Light-weight validation helpers for unified diff fragments.
Used by Backporter to catch obvious errors *before* we try to
apply the patch with quilt.
"""
from __future__ import annotations
import re
from difflib import unified_diff
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from mephala.core.diff.hunk import Hunk
    from mephala.core.models.candidate import Candidate

# ----------------------------------------------------------------- fast syntax check
def is_patch_well_formed(text: str) -> bool:
    """
    Very tolerant check:

    • there must be at least one pair of   --- a/…  +++ b/…
    • every '--- ' line must have a matching '+++' within the next
      15 lines (covers multi-file patches)
    • at least one @@ marker inside the patch

    Good enough to reject obviously corrupt fragments while never
    complaining about a normal git-format patch.
    """
    lines = text.splitlines()
    hdr_idx: list[int] = [i for i, ln in enumerate(lines) if ln.startswith("--- ")]
    if not hdr_idx:
        return False
    if len([ln for ln in lines if ln.startswith("+++ ")]) != len(hdr_idx):
        return False

    for i in hdr_idx:
        if not any(ln.startswith("+++ ") for ln in lines[i + 1 : i + 16]):
            return False

    return "@@" in text


# ----------------------------------------------------------------- structural checks
def validate_structure(original_hunk: "Hunk", backport_text: str) -> List[str]:
    """
    Compare a generated back-port hunk with the original upstream hunk.
    Returns a list of violation strings (empty ⇢ looks ok).
    """
    errors: list[str] = []

    header_cnt = backport_text.count("--- ")
    if header_cnt != 1:
        errors.append(f"expected exactly 1 file header, found {header_cnt}")

    # header must precede first @@ marker
    first_hdr = backport_text.find("--- ")
    first_at  = backport_text.find("@@")
    if first_at != -1 and first_hdr > first_at:
        errors.append("file header appears after first @@ marker")

    # @@ marker count should match the original hunk
    if backport_text.count("@@") != str(original_hunk).count("@@"):
        errors.append("@@ marker count differs from original")

    # diff meta lines must not appear in the body
    body = [
        ln for ln in backport_text.splitlines()
        if not re.match(r"^(--- |\+\+\+ |@@ )", ln.lstrip())
    ]
    meta_inside = any(re.match(r"[ \t]*[+\- ]{0,2}(--- |\+\+\+ |@@ )", ln) for ln in body)
    if meta_inside:
        errors.append("diff meta line leaked into body")

    return errors


# ----------------------------------------------------------------- human triage diff
def triage_diff(original: "Hunk", backported: "Hunk", candidate: "Candidate") -> str:
    """
    Return a *triple* diff that shows
        1. upstream → back-port
        2. back-port → code slice in candidate file
    """
    from_me, to_me = [dl.text for dl in original.to_b()], [dl.text for dl in backported.to_b()]
    cand           = candidate.lines()

    diff1 = "\n".join(unified_diff(from_me, to_me, n=3, fromfile="orig-to-b",     tofile="backport-to-b"))
    diff2 = "\n".join(unified_diff(to_me,   cand,  n=3, fromfile="backport-to-b", tofile="target-file"))

    return diff1 + "\n\n" + diff2
