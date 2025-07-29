from mephala.core.utils.patch_checks import validate_structure, triage_diff
from mephala.core.diff.hunk          import Hunk
from mephala.core.models.candidate   import Candidate


# ───────────────────────────────────────────────────────── helpers
def tiny_hunk():
    diff = [
        "--- a/x",
        "+++ b/x",
        "@@ -1,1 +1,1 @@",
        "-old",
        "+new",
    ]
    return Hunk.from_diff_lines(diff), "\n".join(diff) + "\n"


def dummy_candidate():
    cand = Candidate(1, extent=(1, 1))
    cand.context = {1: {"line": "new"}}
    cand.path_to = "src/x"
    return cand


# ───────────────────────────────────────────────────────── validate_structure
def test_validate_structure_ok():
    orig, backport = tiny_hunk()
    assert validate_structure(orig, backport) == []


def test_validate_structure_header_count():
    orig, backport = tiny_hunk()
    bad = backport.replace("--- a/x", "--- a/x\n--- a/y", 1)
    errs = validate_structure(orig, bad)
    assert any("exactly 1 file header" in e for e in errs)


def test_validate_header_position():
    orig, backport = tiny_hunk()
    # 1. remove the original header
    bad = backport.replace("--- a/x\n", "", 1)
    # 2. re-insert it AFTER the first @@ marker  →  illegal position
    bad = bad.replace("@@ -1,1 +1,1 @@", "@@ -1,1 +1,1 @@\n--- a/x", 1)
    errs = validate_structure(orig, bad)
    assert any("file header appears after" in e for e in errs)


def test_validate_at_marker_mismatch():
    orig, backport = tiny_hunk()
    bad = backport + "@@ bogus @@\n"
    errs = validate_structure(orig, bad)
    assert any("@@ marker count differs" in e for e in errs)


def test_validate_meta_leaked():
    orig, backport = tiny_hunk()
    leaked = backport.replace("+new", "+@@ meta leak")
    errs = validate_structure(orig, leaked)
    assert any("meta line leaked" in e for e in errs)


# ───────────────────────────────────────────────────────── triage_diff
def test_triage_diff_returns_string():
    """Even when hunks are identical the helper must return a string."""
    orig, backport_txt = tiny_hunk()
    backport = Hunk.from_diff_lines(backport_txt.splitlines())
    diff = triage_diff(orig, backport, dummy_candidate())
    assert isinstance(diff, str)
