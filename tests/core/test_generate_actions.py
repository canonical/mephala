from mephala.core.diff.hunk           import Hunk
from mephala.core.models.enums        import ActionType


def mk_hunk(text: str):
    """ helper: build a Hunk from a raw diff body string """
    lines = text.strip("\n").splitlines()
    # add fake file headers so from_diff_lines() finds a filename
    lines = ["--- a/foo", "+++ b/foo", "@@ -1,0 +1,0 @@"] + lines
    return Hunk.from_diff_lines(lines)


# ------------------------ IU-1  pure insertion ----------------------------- #
def test_actions_insertion_only():
    h = mk_hunk("""
+one
+two
""")
    acts = h.generate_actions()
    assert len(acts) == 1
    assert acts[0].action_type is ActionType.INSERTION
    assert [ln.text for ln in acts[0].lines] == ["one", "two"]


# ------------------------ IU-2  pure deletion ------------------------------ #
def test_actions_deletion_only():
    h = mk_hunk("""
-one
-two
""")
    acts = h.generate_actions()
    assert len(acts) == 1
    assert acts[0].action_type is ActionType.DELETION
    assert [ln.text for ln in acts[0].lines] == ["one", "two"]


# ------------------------ IU-3  replacement  D I --------------------------- #
def test_actions_replacement():
    h = mk_hunk("""
-old
+new
""")
    acts = h.generate_actions()
    assert [a.action_type for a in acts] == [
        ActionType.DELETION, ActionType.INSERTION
    ]
    assert [ln.text for ln in acts[0].lines] == ["old"]
    assert [ln.text for ln in acts[1].lines] == ["new"]


# ------------------------ IU-4  overlap case looks same at Action level ---- #
def test_actions_overlap_same_as_replacement():
    # here we just add another unchanged line so the hunk looks realistic
    h = mk_hunk("""
-context
-old
+new
""")
    acts = h.generate_actions()
    assert [a.action_type for a in acts] == [
        ActionType.DELETION, ActionType.INSERTION
    ]


# ------------------------ “W” flag – whitespace only ----------------------- #
def test_actions_whitespace_only_edit():
    h = mk_hunk("""
-old
+old   
""")  # four trailing spaces
    acts = h.generate_actions()
    assert [a.action_type for a in acts] == [
        ActionType.DELETION, ActionType.INSERTION
    ]
