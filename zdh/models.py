from dataclasses import dataclass, asdict, field
from typing import Optional
import json

@dataclass
class Evidence:
    source: str
    propagation: list[str] = field(default_factory=list)
    sink: str = ""
    controls: list[str] = field(default_factory=list)
    reason: str = ""

@dataclass
class Finding:
    rule_id: str
    kind: str
    severity: str
    confidence: int
    file: str
    line: int
    message: str
    evidence: Evidence
    repo: Optional[str] = None
    commit: Optional[str] = None
    function: str = ""
    entry_points: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False)
