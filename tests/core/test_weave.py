from __future__ import annotations

from mephala.core.diff.hunk           import Hunk
from mephala.core.models.candidate    import Candidate
from mephala.core.models.action       import Action
from mephala.core.models.diff_line    import DiffLine
from mephala.core.models.enums        import ActionType, LineType


# ───────────────────────────────────────────────────────── helpers
def mk_candidate(start: int, lines: list[str]):
    """
    Build a minimal Candidate slice whose context keys run
    start … start+len(lines)-1.

    No Pattern objects are needed for weave(), therefore we pass an
    explicit extent to keep Candidate.__init__() happy.
    """
    end  = start + len(lines) - 1
    cand = Candidate(len(lines), extent=(start, end))   # <-- fixed
    cand.context = {start + i: {"line": ln} for i, ln in enumerate(lines)}
    cand.path_to = "dummy/file.rb"
    return cand

def mk_action(kind: str, payload: list[str]):
    """
    Create an Action with the supplied payload lines.
    """
    a = Action(ActionType[kind], DiffLine(payload[0], LineType.INSERTION))
    for ln in payload[1:]:
        a += DiffLine(ln, LineType.INSERTION)
    return a


def run_weave(candidate, threads):
    # filename irrelevant for weave logic; put something plausible
    h = Hunk("foo/bar.c")
    h.weave(candidate, threads)
    return h


# ───────────────────────────────────────────────────────── IU-1 : insertion
def test_weave_insertion_only():
    cand = mk_candidate(10, ["a", "b", "c"])
    ins  = mk_action("INSERTION", ["X", "Y"])
    threads = [{"action": ins, "interval": [11]}]   # after line 11 == "b"

    h = run_weave(cand, threads)

    expect = [
        " a",          # 10
        " b",          # 11
        "+X",          # insert
        "+Y",
        " c",          # 12
    ]
    assert [str(dl) for dl in h.delta] == expect
    assert h.top == 10
    assert h.MARGIN == 3 or len(h.delta) == 5
    assert h.__str__().count("@@") >= 2


# ───────────────────────────────────────────────────────── IU-2 : deletion
def test_weave_deletion_only():
    cand = mk_candidate(1, ["p", "q", "r", "s"])
    dele = mk_action("DELETION", ["q", "r"])
    threads = [{"action": dele, "interval": [2, 3]}]

    h = run_weave(cand, threads)

    expect = [
        " p",   # 1
        "-q",   # 2
        "-r",   # 3
        " s",   # 4
    ]
    assert [str(dl) for dl in h.delta] == expect


# ───────────────────────────────────────────────────────── IU-3 : replace
def test_weave_replacement():
    cand = mk_candidate(40, ["old1", "old2", "tail"])
    dele = mk_action("DELETION",  ["old1", "old2"])
    ins  = mk_action("INSERTION", ["new1", "new2"])
    threads = [
        {"action": dele, "interval": [40, 41]},
        {"action": ins,  "interval": [41]},     # after deletion block
    ]

    h = run_weave(cand, threads)

    expect = [
        "-old1",   # deletion 40
        "-old2",   # deletion 41
        "+new1",   # insertion
        "+new2",
        " tail",   # 42
    ]
    assert [str(dl) for dl in h.delta] == expect


# ───────────────────────────────────────────────────────── IU-4 : overlap-insert
def test_weave_overlap_insert_normalised():
    cand = mk_candidate(100, ["A", "B", "C", "D", "E"])
    dele = mk_action("DELETION",  ["B", "C", "D"])
    ins  = mk_action("INSERTION", ["X"])
    threads = [
        {"action": dele, "interval": [101, 103]},
        {"action": ins,  "interval": [103]},   # anchor already shifted
    ]

    h = run_weave(cand, threads)

    expect = [
        " A",      # 100
        "-B",      # 101
        "-C",      # 102
        "-D",      # 103
        "+X",      # insert after deletion block
        " E",      # 104
    ]
    assert [str(dl) for dl in h.delta] == expect
    # quick structure sanity
    text = str(h)
    assert text.count("--- ") == 1 and text.count("+++ ") == 1 and text.count("@@") >= 2
