from .enums import ActionType
from .diff_line import DiffLine

class Action:
    def __init__(self, action_type: ActionType, first_line: DiffLine):
        self.action_type = action_type
        self.lines = [first_line]

    def __iadd__(self, other: DiffLine):
        self.lines.append(other)
        return self

    def __str__(self):
        return f"{self.action_type.name}\n" + "\n".join(map(str, self.lines))
