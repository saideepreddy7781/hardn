from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str  # secret | code | dependency | config | posture
    file: str = ""
    line: int = 0
    snippet: str = ""
    cwe: str = ""
    fix: str = ""
    sources: list = field(default_factory=lambda: ["hardn"])
    extra: dict = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return SEV_RANK[self.severity]

    def location(self) -> str:
        if not self.file:
            return "(project-wide)"
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    stack: dict
    findings: list
    engines: dict  # engine name -> status text
    files_scanned: int
    duration: float


def cap_severity(sev: str, cap: str) -> str:
    return sev if SEV_RANK[sev] <= SEV_RANK[cap] else cap
