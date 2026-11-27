from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Finding:
    check_id: str
    resource_id: str
    region: str
    status: str
    resource_arn: str = ""
    status_extended: str = ""

    @classmethod
    def from_dict(cls, d):
        return cls(
            check_id=d["check_id"],
            resource_id=d["resource_id"],
            region=d["region"],
            status=d["status"],
            resource_arn=d.get("resource_arn", ""),
            status_extended=d.get("status_extended", ""),
        )


@dataclass
class Plan:
    check_id: str
    resource_id: str
    region: str
    commands: list
    diff: dict
    blast_radius: dict
    advice: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Result:
    check_id: str
    resource_id: str
    mode: str
    outcome: str
    plan: Optional[dict] = None
    snapshot: Optional[dict] = None
    timings: dict = field(default_factory=dict)
    total_seconds: float = 0.0
    error: str = ""

    def to_dict(self):
        return asdict(self)
