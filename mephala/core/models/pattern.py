class Pattern:
    def __init__(self, match_text: str, first_loc: int, partial_match=False):
        self.match_text  = match_text
        self.locations   = [first_loc]
        self.is_partial  = partial_match
        self.saturation  = 1

    def found_at(self, line_no: int, partial_match=False):
        self.locations.append(line_no)
        self.is_partial = self.is_partial or partial_match
        return True

    def locate_in(self, interval):
        return next((loc for loc in self.locations if loc in range(*interval)), None)

    def __str__(self):
        return (f"Pattern(text={self.match_text!r}, "
                f"locs={self.locations}, partial={self.is_partial})")
