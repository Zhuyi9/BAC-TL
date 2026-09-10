#!/usr/bin/env python3
"""按 behavior 行标签筛选完整流，并保留这些流的所有协议层记录。"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from label_utils import canonicalize_label


def parse_args() -> argparse.Namespace:
    """定义输入 CSV、目标标签和筛选模式。"""
    parser = argparse.ArgumentParser(description="按流标签筛选带完整层级记录的 CSV")
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_csv", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--exclude", action="store_true", help="筛选非目标标签流")
    return parser.parse_args()


def main() -> None:
    """先收集目标 behavior 流 ID，再写出这些流的全部层级行。"""
    args = parse_args()
    target = canonicalize_label(args.label)
    selected: set[str] = set()
    with Path(args.input_csv).open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") != "behavior":
                continue
            if canonicalize_label(row.get("label")) == target:
                selected.add(str(row["flow_id"]))

    output = Path(args.output_csv)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows_written = 0
    with Path(args.input_csv).open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("输入 CSV 没有表头")
        with output.open("w", encoding="utf-8", newline="") as target_file:
            writer = csv.DictWriter(target_file, fieldnames=reader.fieldnames)
            writer.writeheader()
            for row in reader:
                is_target = str(row["flow_id"]) in selected
                keep = not is_target if args.exclude else is_target
                if keep:
                    writer.writerow(row)
                    rows_written += 1
    print(json.dumps({"selected_flows": len(selected), "rows_written": rows_written}, ensure_ascii=False))


if __name__ == "__main__":
    main()
