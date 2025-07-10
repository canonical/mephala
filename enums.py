from enum import Enum

class HunkState(Enum):
  INITIAL=1
  FINAL=2

class LineType(Enum):
  NOCHANGE=0
  INSERTION=1
  DELETION=2

class ActionType(Enum):
  INSERTION=1
  DELETION=2
