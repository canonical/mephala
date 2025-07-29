from pathlib import Path

import pytest

from mephala.core.diff.hunk               import Hunk
from mephala.core.services.candidate_finder import CandidateFinder


# ---------------------------------------------------------------- helpers
def mk_hunk(diff_body: str, fname: str = "probe.py") -> Hunk:
    """
    Build a minimal Hunk whose *to-b* side contains `diff_body`.
    """
    diff_lines = (
        ["--- a/" + fname, "+++ b/" + fname, "@@ -1,0 +1,1 @@"]
        + diff_body.strip("\n").splitlines()
    )
    return Hunk.from_diff_lines(diff_lines)


def write_file(path: Path, *lines: str) -> None:
    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def candidate_dir(tmp_path: Path) -> Path:
    return tmp_path


# ========================================================================
# 1.  W-flag  –  whitespace-only edit
# ========================================================================
def test_whitespace_only_match_recognised(candidate_dir: Path):
    """
    CandidateFinder must keep whitespace-only near-duplicates;
    we only assert presence and positive score (ranking may tie).
    """
    hunk = mk_hunk("+return result;")

    exact  = candidate_dir / "exact.py"
    noisy  = candidate_dir / "spaces.py"

    write_file(exact, "return result;")
    write_file(noisy, "   return   result ;")   # extra spaces

    cdict  = CandidateFinder.generate_candidate_dictionary(
        hunk, str(candidate_dir)
    )
    scores = {Path(c.path_to).name: c.score for c in cdict.values()}

    # both variants must be present and have non-zero score
    assert set(scores) == {"exact.py", "spaces.py"}
    assert all(v > 0 for v in scores.values())


# ========================================================================
# 2.  V-flag  –  variable rename / near-duplicate
# ========================================================================
def test_variable_rename_match_recognised(candidate_dir: Path):
    hunk = mk_hunk("+value = encoding")

    exact   = candidate_dir / "exact.py"
    renamed = candidate_dir / "rename.py"

    write_file(exact,   "value = encoding")
    write_file(renamed, "value = enc")   # shorter variable name

    cdict  = CandidateFinder.generate_candidate_dictionary(
        hunk, str(candidate_dir)
    )
    scores = {Path(c.path_to).name: c.score for c in cdict.values()}

    # both candidates kept, each with positive score
    assert set(scores) == {"exact.py", "rename.py"}
    assert all(v > 0 for v in scores.values())
