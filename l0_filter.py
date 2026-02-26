from __future__ import annotations

from typing import Any

from models import DetectionResult, TrafficSample


def _priority_to_risk(priority: int | None) -> float:
    if priority is None:
        return 0.5
    mapping = {
        1: 0.95,
        2: 0.85,
        3: 0.70,
        4: 0.55,
    }
    return mapping.get(priority, 0.50)


def apply_l0_filter(sample: TrafficSample) -> DetectionResult:
    alert = sample.alert or {}
    if alert:
        priority = alert.get("severity") or alert.get("priority")
        risk_score = _priority_to_risk(_to_int(priority))
        suricata_alert = {
            "sid": alert.get("signature_id"),
            "msg": alert.get("signature"),
            "category": alert.get("category"),
            "priority": _to_int(priority),
        }
        evidence = [
            {"field": "alert.signature_id", "value": alert.get("signature_id")},
            {"field": "alert.signature", "value": alert.get("signature")},
            {"field": "alert.category", "value": alert.get("category")},
        ]
        return DetectionResult(
            sample_id=sample.sample_id,
            final_label="malicious",
            risk_score=risk_score,
            reason_short="Matched Suricata alert rule",
            evidence_spans=evidence,
            attack_type=None,
            suricata_alert=suricata_alert,
            stage="L0",
            model_meta=None,
        )

    return DetectionResult(
        sample_id=sample.sample_id,
        final_label="suspicious",
        risk_score=0.40,
        reason_short="No Suricata alert hit, keep for higher-stage analysis",
        evidence_spans=[{"field": "event_type", "value": sample.event_type}],
        attack_type=None,
        suricata_alert=None,
        stage="L0_pass",
        model_meta=None,
    )


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
