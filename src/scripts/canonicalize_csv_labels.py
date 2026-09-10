#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from label_utils import canonicalize_label


def parse_args():
    parser = argparse.ArgumentParser(description="Canonicalize labels in a CSV file.")
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_csv", help="Defaults to overwriting --input_csv.")
    parser.add_argument("--chunksize", type=int, default=200000)
    return parser.parse_args()


def main():
    args = parse_args()
    input_csv = Path(args.input_csv)
    output_csv = Path(args.output_csv) if args.output_csv else input_csv
    temp_csv = output_csv.with_suffix(output_csv.suffix + ".tmp")

    first_write = True
    before_counts: dict[str, int] = {}
    after_counts: dict[str, int] = {}
    for chunk in pd.read_csv(input_csv, chunksize=args.chunksize, low_memory=False):
        if "label" not in chunk.columns:
            raise ValueError(f"{input_csv} does not contain a label column")

        before = chunk["label"].fillna("").astype(str).value_counts()
        for label, count in before.items():
            before_counts[label] = before_counts.get(label, 0) + int(count)

        chunk["label"] = chunk["label"].map(canonicalize_label)

        after = chunk["label"].fillna("").astype(str).value_counts()
        for label, count in after.items():
            after_counts[label] = after_counts.get(label, 0) + int(count)

        chunk.to_csv(temp_csv, index=False, mode="w" if first_write else "a", header=first_write)
        first_write = False

    temp_csv.replace(output_csv)
    print(f"output_csv={output_csv}")
    print("before:")
    for label, count in sorted(before_counts.items()):
        print(f"  {label}: {count}")
    print("after:")
    for label, count in sorted(after_counts.items()):
        print(f"  {label}: {count}")


if __name__ == "__main__":
    main()
