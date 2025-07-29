from __future__ import annotations

import copy
from collections import Counter

from mephala.ai.backporter          import Backporter
from mephala.core.models.action     import Action
from mephala.core.models.diff_line  import DiffLine
from mephala.core.models.enums      import ActionType, LineType


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def mk_thread(kind: ActionType | str, interval):
    if isinstance(kind, str):
        kind = ActionType[kind]
    dummy_line = DiffLine("x", LineType.INSERTION)
    return {"action": Action(kind, dummy_line), "interval": list(interval)}


# ---------------------------------------------------------------------------
# 1. pure insertion / deletion  →  only re-ordering allowed
# ---------------------------------------------------------------------------
def test_normalize_threads_preserves_intervals():
    threads = [
        mk_thread("INSERTION", [5]),
        mk_thread("DELETION",  [8, 9]),
    ]
    before = copy.deepcopy(threads)

    fixed = Backporter._normalize_threads(threads)

    # Same *multiset* of intervals
    assert Counter(tuple(t["interval"]) for t in fixed) == \
           Counter(tuple(t["interval"]) for t in before)

    # No anchor was rewritten
    assert all(i in ([5], [8, 9]) for t in fixed for i in [t["interval"]])

# ---------------------------------------------------------------------------
# 2. replacement (delete then insert at d_to)  →  anchor unchanged
# ---------------------------------------------------------------------------
def test_normalize_threads_replacement_keeps_anchor():
    threads = [
        mk_thread("DELETION",  [10, 11]),
        mk_thread("INSERTION", [11]),
    ]
    fixed = Backporter._normalize_threads(copy.deepcopy(threads))

    assert fixed[0]["interval"] == [10, 11]
    assert fixed[1]["interval"] == [11]


# ---------------------------------------------------------------------------
# 3a. overlap – single insertion inside deletion  →  anchor rewritten
# ---------------------------------------------------------------------------
def test_normalize_threads_moves_single_anchor():
    threads = [
        mk_thread("DELETION",  [20, 24]),
        mk_thread("INSERTION", [22]),
    ]
    fixed = Backporter._normalize_threads(copy.deepcopy(threads))

    assert fixed[1]["interval"] == [24]


# ---------------------------------------------------------------------------
# 3b. overlap – multiple insertions inside same deletion
# ---------------------------------------------------------------------------
def test_normalize_threads_moves_multiple_anchors():
    threads = [
        mk_thread("DELETION",  [30, 35]),
        mk_thread("INSERTION", [30]),
        mk_thread("INSERTION", [33]),
        mk_thread("INSERTION", [35]),
    ]
    fixed = Backporter._normalize_threads(copy.deepcopy(threads))

    for thr in fixed:
        if thr["action"].action_type is ActionType.INSERTION:
            assert thr["interval"] == [35]

    # deletion followed immediately by its insertions
    del_idx = next(i for i, thr in enumerate(fixed)
                   if thr["action"].action_type is ActionType.DELETION)
    assert all(thr["action"].action_type is ActionType.INSERTION
               for thr in fixed[del_idx + 1 :])
