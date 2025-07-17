from enum import Enum, auto

class HunkState(Enum):
    INITIAL = auto()
    FINAL   = auto()

class LineType(Enum):
    NOCHANGE  = 0
    INSERTION = 1
    DELETION  = 2

class ActionType(Enum):
    INSERTION = 1
    DELETION  = 2
