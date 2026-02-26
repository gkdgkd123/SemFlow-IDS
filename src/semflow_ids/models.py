from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class TrafficSample:
    sample_id: str
    event_type: str
    timestamp: str | None
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    flow_id: int | None
    alert: dict[str, Any] | None = None
    http: dict[str, Any] | None = None
    flow: dict[str, Any] | None = None
    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    sample_id: str
    final_label: str
    risk_score: float
    reason_short: str
    evidence_spans: list[dict[str, Any]]
    attack_type: str | None
    suricata_alert: dict[str, Any] | None
    stage: str
    model_meta: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
