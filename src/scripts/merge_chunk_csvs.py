#!/usr/bin/env python3
"""Merge chunk CSV files and rewrite per-chunk flow_id values.

Each chunk produced by ``UnifiedPcapToCSV.py`` numbers its local flows from 1.
That means we can assign globally unique flow IDs with a simple per-chunk
offset instead of maintaining a large local->global mapping table.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge chunk CSV files and assign globally unique flow_id values."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing chunk CSV files.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the merged CSV output file.",
    )
    return parser.parse_args()


def merge_chunk_csvs(input_dir: Path, output_path: Path) -> tuple[int, int]:
    chunk_files = sorted(input_dir.glob("*.csv"))
    if not chunk_files:
        raise FileNotFoundError(f"No CSV files found in {input_dir}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    flow_id_offset = 0
    merged_flows = 0
    rows_written = 0

    with output_path.open("w", newline="", encoding="utf-8", buffering=1024 * 1024) as fout:
        writer: csv.writer | None = None

        for chunk_file in chunk_files:
            max_local_flow_id = 0

            with chunk_file.open("r", newline="", encoding="utf-8", buffering=1024 * 1024) as fin:
                reader = csv.reader(fin)
                try:
                    header = next(reader)
                except StopIteration:
                    continue

                if "flow_id" not in header:
                    raise ValueError(f"Missing flow_id column in {chunk_file}")
                flow_id_idx = header.index("flow_id")

                if writer is None:
                    writer = csv.writer(fout)
                    writer.writerow(header)

                for row in reader:
                    local_flow_id = int(row[flow_id_idx])
                    if local_flow_id > max_local_flow_id:
                        max_local_flow_id = local_flow_id

                    row[flow_id_idx] = str(local_flow_id + flow_id_offset)
                    writer.writerow(row)
                    rows_written += 1

            flow_id_offset += max_local_flow_id
            merged_flows = flow_id_offset

    return merged_flows, rows_written


def main() -> None:
    args = parse_args()
    total_flows, total_rows = merge_chunk_csvs(Path(args.input_dir), Path(args.output))
    print(f"merged_flows={total_flows}")
    print(f"merged_rows={total_rows}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
