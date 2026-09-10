#!/usr/bin/env python3
"""
Extract all rows belonging to the first N unique flow IDs from a CSV file.

By default, the script is fully correct even if the same flow_id appears again
later in the file. If the input is grouped by flow_id, pass
`--grouped-by-flow-id` to stop early once the Nth flow is completed.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract rows for the first N unique flow_id values."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the source CSV file.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output CSV file.",
    )
    parser.add_argument(
        "--num-flows",
        type=int,
        default=100000,
        help="Number of unique flow_id values to keep from the beginning.",
    )
    parser.add_argument(
        "--flow-id-column",
        default="flow_id",
        help="Column name used to identify flows.",
    )
    parser.add_argument(
        "--grouped-by-flow-id",
        action="store_true",
        help="Stop early once the Nth flow ends if rows are already grouped by flow_id.",
    )
    return parser.parse_args()


def extract_first_n_flows(
    input_path: Path,
    output_path: Path,
    num_flows: int,
    flow_id_column: str,
    grouped_by_flow_id: bool,
) -> tuple[int, int]:
    selected_flow_ids: set[str] = set()
    rows_written = 0
    last_flow_id: str | None = None
    limit_reached = False

    with input_path.open("r", newline="", encoding="utf-8") as src, output_path.open(
        "w", newline="", encoding="utf-8"
    ) as dst:
        reader = csv.DictReader(src)
        if reader.fieldnames is None or flow_id_column not in reader.fieldnames:
            raise ValueError(
                f"Column '{flow_id_column}' not found. Available columns: {reader.fieldnames}"
            )

        writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)
        writer.writeheader()

        for row in reader:
            flow_id = row[flow_id_column]

            if flow_id in selected_flow_ids:
                writer.writerow(row)
                rows_written += 1
            elif not limit_reached:
                selected_flow_ids.add(flow_id)
                if len(selected_flow_ids) >= num_flows:
                    limit_reached = True
                writer.writerow(row)
                rows_written += 1
            elif grouped_by_flow_id and last_flow_id is not None and flow_id != last_flow_id:
                break

            last_flow_id = flow_id

    return len(selected_flow_ids), rows_written


def main() -> None:
    args = parse_args()

    if args.num_flows <= 0:
        raise ValueError("--num-flows must be a positive integer")

    unique_flows, rows_written = extract_first_n_flows(
        input_path=Path(args.input),
        output_path=Path(args.output),
        num_flows=args.num_flows,
        flow_id_column=args.flow_id_column,
        grouped_by_flow_id=args.grouped_by_flow_id,
    )

    print(f"unique_flows={unique_flows}")
    print(f"rows_written={rows_written}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
