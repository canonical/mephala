from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class CVERecord:
    cve:  str
    desc: str

    def __str__(self) -> str:
        return f"{self.cve}\n{self.desc}"
