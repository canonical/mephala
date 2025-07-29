import re
from pathlib import Path
from unittest.mock import patch


# ───────────────────────────────────────────────────── monkey-patch & import
MIN_ENV = {
    "release_list":        [],
    "package_workspace":   ".",
    "ubuntu-cve-tracker":  ".",
}

with patch(
    "mephala.core.config.context_manager.ContextManager._load_env",
    lambda self, _: MIN_ENV,
):
    # now the import is safe because ContextManager.__init__ will call
    # the stubbed _load_env instead of reading a file
    from mephala.cli.utils import SaveTree


# ───────────────────────────────────────────────────── helpers
def mk_fragment(header: str, body: str) -> str:
    return (
        f"--- a/{header}\n"
        f"+++ b/{header}\n"
        "@@ -1,1 +1,1 @@\n"
        f"{body}\n"
    )


def write_fragment(base: Path, dir_name: str, file_name: str, text: str):
    tgt = base / dir_name
    tgt.mkdir(parents=True, exist_ok=True)
    (tgt / file_name).write_text(text)


# ───────────────────────────────────────────────────── test
def test_finalize_patch_header_deduplication(tmp_path: Path):
    """
    • fragment A  IU-1   (pure insertion)
    • fragment B  IU-2   (pure deletion)        – same file as A
    • fragment C  IU-3   (replacement)          – different file
    Expect:
      – exactly one header pair per file in the combined patch
      – hunks appear in directory order 1h,2h,3h
    """

    # redirect SaveTree’s base dir into the pytest tmp path
    SaveTree.BASE_DIR = str(tmp_path / ".metadata")
    saver = SaveTree(overwrite=True)

    upstream_path = tmp_path / "orig.patch"
    upstream_path.write_text("dummy header\n")
    release = "focal"

    frag_A = mk_fragment("foo.c", "+added")
    frag_B = mk_fragment("foo.c", "-gone")
    frag_C = mk_fragment("bar.c", "-old\n+new")

    write_fragment(Path(saver._path()), "1h", "a.patch", frag_A)
    write_fragment(Path(saver._path()), "2h", "b.patch", frag_B)
    write_fragment(Path(saver._path()), "3h", "c.patch", frag_C)

    out_path = saver.finalize_patch(str(upstream_path), release)
    text     = out_path.read_text()

    # one header pair per file
    assert text.count("--- a/foo.c") == 1
    assert text.count("+++ b/foo.c") == 1
    assert text.count("--- a/bar.c") == 1
    assert text.count("+++ b/bar.c") == 1

    # hunks appear in numeric directory order
    hunk_headers = re.findall(r"@@ .*? @@", text)
    assert hunk_headers[0] in frag_A
    assert hunk_headers[1] in frag_B
    assert hunk_headers[2] in frag_C

    # banner from finalize_patch is present
    assert "Back-ported to release" in text

    # final patch passes syntax sanity-check
    from mephala.core.utils.patch_checks import is_patch_well_formed
    assert is_patch_well_formed(text)
