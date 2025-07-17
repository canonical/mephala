from dataclasses import dataclass, field
from typing import Any

from .cve_record import CVERecord

@dataclass(slots=True)
class PatchMeta:
    cve_record: CVERecord
    release:    str
    file_path:  str
    metadata:   dict[str, Any] = field(default_factory=dict)
