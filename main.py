import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from semflow_ids.detection.l0_filter import apply_l0_filter
from semflow_ids.ingest.eve_parser import parse_eve_jsonl, write_traffic_samples_jsonl
from semflow_ids.output.output_writer import write_detection_results_jsonl


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SemFlow-IDS milestone-1 prototype")
    p.add_argument("--input", required=True, help="Path to Suricata eve.json (JSONL)")
    p.add_argument("--output", default="results.jsonl", help="Output detection JSONL path")
    p.add_argument(
        "--samples-output",
        default="",
        help="Optional path to dump normalized TrafficSample JSONL",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    samples, parse_stats = parse_eve_jsonl(args.input)

    if args.samples_output:
        write_traffic_samples_jsonl(samples, args.samples_output)

    results = [apply_l0_filter(sample) for sample in samples]
    write_detection_results_jsonl(results, args.output)

    l0_hits = sum(1 for r in results if r.stage == "L0")
    run_stats = {
        "input_path": args.input,
        "output_path": args.output,
        "samples_output_path": args.samples_output or None,
        "total_lines": parse_stats["total_lines"],
        "parsed_events": parse_stats["parsed_events"],
        "supported_events": parse_stats["supported_events"],
        "skipped_invalid_json": parse_stats["skipped_invalid_json"],
        "skipped_unsupported": parse_stats["skipped_unsupported"],
        "results_count": len(results),
        "l0_hits": l0_hits,
        "l0_hit_rate": round(l0_hits / len(results), 4) if results else 0.0,
    }
    print(json.dumps(run_stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
