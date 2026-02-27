import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from semflow_ids.detection.l0_filter import apply_l0_filter
from semflow_ids.ingest.eve_parser import parse_eve_jsonl, write_traffic_samples_jsonl
from semflow_ids.modeling.ollama_client import OllamaClient, analyze_l1, analyze_l2_group
from semflow_ids.models import DetectionResult
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
    p.add_argument(
        "--enable-l1",
        action="store_true",
        help="Enable L1 semantic analysis (requires API access)",
    )
    p.add_argument(
        "--enable-l2",
        action="store_true",
        help="Enable L2 attack chain analysis (requires L1 enabled)",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    samples, parse_stats = parse_eve_jsonl(args.input)

    if args.samples_output:
        write_traffic_samples_jsonl(samples, args.samples_output)

    # L0 检测
    l0_results = [apply_l0_filter(sample) for sample in samples]

    # L1 语义分析（仅对 L0_pass 的样本，分类抽样）
    l1_enabled = args.enable_l1
    l1_results = []
    if l1_enabled:
        client = OllamaClient()

        # 分类抽样：按 event_type + has_http 分组，每组最多 10 条
        from collections import defaultdict
        categories = defaultdict(list)

        for sample, l0_result in zip(samples, l0_results):
            if l0_result.stage == "L0_pass":
                has_http = bool(sample.http and sample.http.get("url"))
                key = (sample.event_type, has_http)
                categories[key].append((sample, l0_result))

        # 打印分类统计
        print("[L1] 分类抽样统计:")
        for key, items in sorted(categories.items()):
            print(f"  {key[0]}(has_http={key[1]}): {len(items)} 条 -> 抽 10 条")

        # 每类最多抽 2 条
        max_per_category = 2
        for key, items in categories.items():
            samples_to_analyze = items[:max_per_category]
            for sample, l0_result in samples_to_analyze:
                l1_analysis = analyze_l1(sample.to_dict(), client)
                l1_results.append(l1_analysis)
                semantic = l1_analysis.get("semantic_features", {})
                print(f"[L1] {key[0]}({sample.sample_id}): isSuspicious={semantic.get('isSuspicious')}, features={semantic.get('semantic_features', [])[:2]}")

    # 合并结果
    results = []
    l1_hit_count = 0

    # 按 src_ip 分组，为 L2 准备
    from collections import defaultdict
    ip_groups = defaultdict(list)

    for sample, l0_result in zip(samples, l0_results):
        if l0_result.stage == "L0":
            # 有 L0 告警，直接使用 L0 结果
            results.append(l0_result)
        elif l0_result.stage == "L0_pass" and l1_enabled:
            # L0 通过，检查 L1 结果
            l1_match = None
            for l1 in l1_results:
                if l1.get("sample_id") == sample.sample_id:
                    l1_match = l1
                    break

            if l1_match:
                semantic = l1_match.get("semantic_features", {})
                is_suspicious = semantic.get("is_suspicious", False)
                risk_level = semantic.get("risk_level", "low")

                # 风险分数映射
                risk_score_map = {"low": 3, "medium": 6, "high": 8, "critical": 10}
                risk_score = risk_score_map.get(risk_level, 5)

                if is_suspicious:
                    l1_hit_count += 1

                # 保存样本和 L1 结果到 ip_groups，供 L2 使用
                ip_groups[sample.src_ip].append({
                    "sample": sample,
                    "l0_result": l0_result,
                    "l1_analysis": semantic,
                    "l1_raw": l1_match,
                    "risk_score": risk_score,
                })
            else:
                results.append(l0_result)
        else:
            # 未启用 L1 或不是 HTTP 流量，保持 L0_pass
            results.append(l0_result)

    # L2 攻击链分析（按 src_ip 关联多流量）
    l2_enabled = args.enable_l2 and l1_enabled
    l2_results = {}
    if l2_enabled:
        print("[L2] 按来源 IP 关联分析...")
        client = OllamaClient()

        for src_ip, group in ip_groups.items():
            if len(group) >= 2:  # 至少2条流量才做关联分析
                print(f"[L2] 分析 IP {src_ip}: {len(group)} 条流量")

                # 准备 L2 输入
                samples_for_l2 = []
                for item in group:
                    samples_for_l2.append({
                        "sample_id": item["sample"].sample_id,
                        "src_ip": item["sample"].src_ip,
                        "risk_score": item["risk_score"],
                        "l1_analysis": item["l1_analysis"],
                    })

                l2_analysis = analyze_l2_group(samples_for_l2, client)
                l2_results[src_ip] = l2_analysis

                print(f"[L2] {src_ip}: attack_chain={l2_analysis.get('attack_chain')}, risk_adjusted={l2_analysis.get('risk_adjusted')}")

    # 应用 L2 结果到最终输出
    if l2_enabled and l2_results:
        final_results = []
        for r in results:
            if r.stage == "L1":
                src_ip = None
                # 找到对应的 src_ip
                for ip, group in ip_groups.items():
                    for item in group:
                        if item["sample"].sample_id == r.sample_id:
                            src_ip = ip
                            break

                if src_ip and src_ip in l2_results:
                    l2 = l2_results[src_ip]
                    # 更新风险分数
                    new_risk_score = l2.get("risk_score", r.risk_score)

                    # 创建新的 DetectionResult
                    final_results.append(DetectionResult(
                        sample_id=r.sample_id,
                        final_label=r.final_label,
                        risk_score=new_risk_score,
                        reason_short=l2.get("attack_summary", l2.get("traffic_summary", r.reason_short)),
                        evidence_spans=r.evidence_spans,
                        attack_type=", ".join(l2.get("attack_chain", [])) or None,
                        suricata_alert=r.suricata_alert,
                        stage="L2",
                        model_meta={
                            "l1_analysis": r.model_meta.get("l1_analysis") if r.model_meta else None,
                            "l2_analysis": l2,
                        },
                    ))
                else:
                    final_results.append(r)
            else:
                final_results.append(r)
        results = final_results

    write_detection_results_jsonl(results, args.output)

    l0_hits = sum(1 for r in results if r.stage == "L0")
    l2_hits = sum(1 for r in results if r.stage == "L2")
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
        "l1_enabled": l1_enabled,
        "l1_analyzed": len(l1_results),
        "l1_suspicious": l1_hit_count,
        "l2_enabled": l2_enabled,
        "l2_analyzed": len(l2_results),
        "l2_hits": l2_hits,
    }
    print(json.dumps(run_stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
