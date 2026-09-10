#!/usr/bin/env python3
"""汇总一次攻击实验的阶段测量结果为一个可读 CSV。"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


# 正式结果只保留用户需要的三项资源指标；逐命令 JSON 仍可在 --keep-work 时用于排查。
OUTPUT_METRICS = ("time_s", "cpu_usage_pct", "memory_mb")
PHASE_ORDER = {
    "feature_extraction": 0,
    "model_training": 1,
    "traffic_generation": 2,
    "model_detection": 3,
    "total": 9,
}


def parse_args() -> argparse.Namespace:
    """定义测量目录、攻击名称和最终 CSV 路径。"""
    parser = argparse.ArgumentParser(description="汇总攻击实验效率测量结果")
    parser.add_argument("--metrics-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--attack", required=True)
    return parser.parse_args()


def summarize(items: list[dict]) -> dict:
    """合并同一方法和阶段的命令；时间与 CPU 求和，采样指标取均值/峰值。"""
    wall = sum(float(item["wall_time_s"]) for item in items)
    total_cpu = sum(float(item["total_cpu_time_s"]) for item in items)
    result = {
        "status": "success" if all(item.get("status") == "success" for item in items) else "failed",
        "command_count": len(items),
        "wall_time_s": wall,
        "user_cpu_time_s": sum(float(item["user_cpu_time_s"]) for item in items),
        "system_cpu_time_s": sum(float(item["system_cpu_time_s"]) for item in items),
        "total_cpu_time_s": total_cpu,
        "avg_cpu_core_utilization_pct": total_cpu / max(wall, 1e-9) * 100.0,
        "sampled_avg_cpu_pct": statistics.fmean(float(item["sampled_avg_cpu_pct"]) for item in items),
        "sampled_peak_cpu_pct": max(float(item["sampled_peak_cpu_pct"]) for item in items),
        "avg_rss_mb": statistics.fmean(float(item["avg_rss_mb"]) for item in items),
        "peak_rss_mb": max(float(item["peak_rss_mb"]) for item in items),
    }
    return result


def main() -> None:
    """读取所有子命令测量文件并写入阶段明细及方法总开销。"""
    args = parse_args()
    metric_files = sorted(Path(args.metrics_dir).glob("*.json"))
    if not metric_files:
        raise RuntimeError(f"没有找到效率测量文件: {args.metrics_dir}")

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for path in metric_files:
        item = json.loads(path.read_text(encoding="utf-8"))
        groups[(str(item["method"]), str(item["phase"]))].append(item)

    rows: list[dict] = []
    for (method, phase), items in groups.items():
        summary = summarize(items)
        row = {
            "attack": args.attack,
            "method": method,
            "phase": phase,
            "time_s": summary["wall_time_s"],
            "cpu_usage_pct": summary["avg_cpu_core_utilization_pct"],
            "memory_mb": summary["peak_rss_mb"],
        }
        row.update({"status": summary["status"], "command_count": summary["command_count"]})
        rows.append(row)

    # 生成每种方法的总开销，便于后续直接比较总时间和总资源。
    for method in sorted({method for method, _ in groups}):
        items = [item for (item_method, _), values in groups.items() if item_method == method for item in values]
        summary = summarize(items)
        row = {
            "attack": args.attack,
            "method": method,
            "phase": "total",
            "time_s": summary["wall_time_s"],
            "cpu_usage_pct": summary["avg_cpu_core_utilization_pct"],
            "memory_mb": summary["peak_rss_mb"],
            "status": summary["status"],
            "command_count": summary["command_count"],
        }
        rows.append(row)

    rows.sort(key=lambda row: (row["method"], PHASE_ORDER.get(row["phase"], 8), row["phase"]))
    fields = ["attack", "method", "phase", "status", "command_count", *OUTPUT_METRICS]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)
    print(f"效率结果: {output}")


if __name__ == "__main__":
    main()
