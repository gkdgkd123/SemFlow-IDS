from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import TrafficSample

SUPPORTED_EVENT_TYPES = {"alert", "http", "flow"}


def parse_eve_jsonl(file_path: str) -> tuple[list[TrafficSample], dict[str, int]]:
    samples: list[TrafficSample] = []
    stats = {
        "total_lines": 0,
        "parsed_events": 0,
        "supported_events": 0,
        "skipped_invalid_json": 0,
        "skipped_unsupported": 0,
    }

    with Path(file_path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stats["total_lines"] += 1
            raw = line.strip()
            if not raw:
                continue

            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                stats["skipped_invalid_json"] += 1
                continue

            stats["parsed_events"] += 1
            sample = normalize_event(event, line_no)
            if sample is None:
                stats["skipped_unsupported"] += 1
                continue

            stats["supported_events"] += 1
            samples.append(sample)

    return samples, stats


def normalize_event(event: dict[str, Any], line_no: int) -> TrafficSample | None:
    event_type = event.get("event_type")
    if event_type not in SUPPORTED_EVENT_TYPES:
        return None

    sample_id = f"{line_no}-{event.get('flow_id', 'na')}"
    return TrafficSample(
        sample_id=sample_id,
        event_type=event_type,
        timestamp=event.get("timestamp"),
        src_ip=event.get("src_ip"),
        src_port=event.get("src_port"),
        dest_ip=event.get("dest_ip"),
        dest_port=event.get("dest_port"),
        proto=event.get("proto"),
        app_proto=event.get("app_proto"),
        flow_id=event.get("flow_id"),
        alert=event.get("alert"),
        http=event.get("http"),
        flow=event.get("flow"),
        raw_event=event,
    )


def write_traffic_samples_jsonl(samples: list[TrafficSample], output_path: str) -> None:
    with Path(output_path).open("w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
