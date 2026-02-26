from __future__ import annotations

import json
from pathlib import Path

from semflow_ids.models import DetectionResult


def write_detection_results_jsonl(results: list[DetectionResult], output_path: str) -> None:
    with Path(output_path).open("w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
