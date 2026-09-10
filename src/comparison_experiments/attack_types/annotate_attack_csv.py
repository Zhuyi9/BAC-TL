#!/usr/bin/env python3
"""Attach one verified attack label and provenance fields to a project CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """定义攻击标签、来源名称以及输入输出文件。"""
    parser = argparse.ArgumentParser(description="为攻击专用 PCAP 的转换 CSV 添加正类标签")
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_csv", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--attack_key", required=True)
    return parser.parse_args()


def main() -> None:
    """保留所有协议层记录，并把已确认的攻击专用捕获统一标为正类。"""
    args = parse_args()
    source = Path(args.input_csv)
    target = Path(args.output_csv)
    target.parent.mkdir(parents=True, exist_ok=True)

    with source.open("r", encoding="utf-8", newline="") as input_handle:
        reader = csv.DictReader(input_handle)
        if not reader.fieldnames:
            raise ValueError("输入 CSV 没有表头")
        fieldnames = list(reader.fieldnames)
        for name in ("label", "source_label", "binary_label", "dataset", "attack_type"):
            if name not in fieldnames:
                fieldnames.append(name)
        with target.open("w", encoding="utf-8", newline="") as output_handle:
            writer = csv.DictWriter(output_handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in reader:
                row["label"] = args.label
                row["source_label"] = args.label
                row["binary_label"] = "1"
                row["dataset"] = args.dataset
                row["attack_type"] = args.attack_key
                writer.writerow(row)


if __name__ == "__main__":
    main()
