#!/usr/bin/env python3
"""Add CTU-13 Botnet labels and provenance fields to a UnifiedPcapToCSV CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """定义输入输出路径及 CTU-13 场景元数据参数。"""
    parser = argparse.ArgumentParser(description="标记 CTU-13 Botnet CSV")
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_csv", required=True)
    parser.add_argument("--scenario", default="12")
    parser.add_argument("--family", default="Unknown")
    return parser.parse_args()


def main() -> None:
    """以流为单位写入 Botnet 标签，并保留原始 CSV 的所有层记录。"""
    args = parse_args()
    source = Path(args.input_csv)
    target = Path(args.output_csv)
    target.parent.mkdir(parents=True, exist_ok=True)

    with source.open("r", encoding="utf-8", newline="") as input_handle:
        reader = csv.DictReader(input_handle)
        if not reader.fieldnames:
            raise ValueError("输入 CSV 没有表头")
        # 解析器输出没有标签列；新增字段只写一次表头，避免修改 payload 和协议记录。
        fieldnames = list(reader.fieldnames)
        for name in ("label", "source_label", "binary_label", "dataset", "scenario", "family"):
            if name not in fieldnames:
                fieldnames.append(name)
        with target.open("w", encoding="utf-8", newline="") as output_handle:
            writer = csv.DictWriter(output_handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in reader:
                # 公开 botnet-capture PCAP 已经是 Botnet-only，因此每个 flow 都是正类。
                row["label"] = "Botnet"
                row["source_label"] = "Botnet"
                row["binary_label"] = "1"
                row["dataset"] = "CTU-13"
                row["scenario"] = str(args.scenario)
                row["family"] = str(args.family)
                writer.writerow(row)


if __name__ == "__main__":
    main()
