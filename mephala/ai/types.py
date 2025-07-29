from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict

@dataclass
class InvocationRecord:
    stage:        str                 # e.g. “draft_backport”, “prune_actions”
    prompt:       str
    params:       Dict[str, Any]
    raw_answer:   str | None = None
    parsed:       Any       | None = None
    taken_path:   str       | None = None   # free-text summary
    ts:           str = field(default_factory=lambda: datetime.utcnow().isoformat())
