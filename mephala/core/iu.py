"""
mephala.core.iu
===============

Single source of truth for the Interaction-Unit terminology used in
tests and dev docs.
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List

class IUType(Enum):
    INSERTION  = auto()   # IU-1
    DELETION   = auto()   # IU-2
    REPLACE    = auto()   # IU-3
    OVERLAP    = auto()   # IU-4

@dataclass(slots=True)
class IUFlags:
    whitespace : bool = False   # W
    near_dup   : bool = False   # V
    rename     : bool = False   # R

@dataclass(slots=True)
class InteractionUnit:
    iu_type : IUType
    lines   : List[str]                # payload (DiffLine.text)
    flags   : IUFlags = field(default_factory=IUFlags)

# ------------------------------------------------------------------ helpers
def classify_actions(action_list) -> List[InteractionUnit]:
    """
    Very small utility used only by the dev-test suite: convert the
    Action sequence produced by Hunk.generate_actions() into a list of
    InteractionUnit objects.  *Not* part of the runtime pipeline.
    """
    from mephala.core.models.enums import ActionType
    ius: List[InteractionUnit] = []
    it = iter(action_list)

    for act in it:
        if act.action_type is ActionType.INSERTION:
            ius.append(InteractionUnit(IUType.INSERTION,
                                       [ln.text for ln in act.lines]))
        elif act.action_type is ActionType.DELETION:
            try:
                nxt = next(it)
                if nxt.action_type is ActionType.INSERTION:
                    ius.append(
                        InteractionUnit(
                            IUType.REPLACE,
                            [ln.text for ln in act.lines + nxt.lines],
                        )
                    )
                else:          # two deletions in a row → treat separately
                    ius.append(
                        InteractionUnit(IUType.DELETION,
                                        [ln.text for ln in act.lines])
                    )
                    ius.append(
                        InteractionUnit(IUType.DELETION,
                                        [ln.text for ln in nxt.lines])
                    )
            except StopIteration:
                ius.append(
                    InteractionUnit(IUType.DELETION,
                                    [ln.text for ln in act.lines])
                )
    return ius
