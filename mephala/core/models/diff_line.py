from .enums import LineType

class DiffLine:
    def __init__(self, text: str, line_type: LineType, source: str | None = None):
        self.text = text
        self.line_type = line_type
        self.source = source

    def type_sym(self):
        return '+' if self.line_type == LineType.INSERTION else \
               '-' if self.line_type == LineType.DELETION else ' '

    def __str__(self):
        src = self.source or ''
        return f"{self.type_sym()}{src}{self.text}"
