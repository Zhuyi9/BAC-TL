#!/usr/bin/env python3
"""Build a test CSV from a flow range across chunk CSV files.

The script reads chunk CSVs in filename order, takes flows from the requested
global range, and rewrites flow_id values to a continuous sequence starting at 1.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a flow range from chunk CSV files with continuous flow IDs."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing chunk CSV files.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output CSV file.",
    )
    parser.add_argument(
        "--start-flow",
        type=int,
        default=1,
        help="1-based inclusive start flow index in the chunk set.",
    )
    parser.add_argument(
        "--end-flow",
        type=int,
        help="1-based inclusive end flow index in the chunk set.",
    )
    parser.add_argument(
        "--num-flows",
        type=int,
        help="Number of flows to extract. If set, end-flow is derived from start-flow.",
    )
    return parser.parse_args()


def extract_flow_range_from_chunks(
    input_dir: Path, output_path: Path, start_flow: int, end_flow: int
) -> tuple[int, int]:
    chunk_files = sorted(input_dir.glob("*.csv"))
    if not chunk_files:
        raise FileNotFoundError(f"No CSV files found in {input_dir}")
    if start_flow <= 0:
        raise ValueError("--start-flow must be a positive integer")
    if end_flow < start_flow:
        raise ValueError("--end-flow must be greater than or equal to --start-flow")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    next_global_flow = 1
    rows_written = 0
    selected_flows = 0

    with output_path.open("w", newline="", encoding="utf-8", buffering=1024 * 1024) as fout:
        writer: csv.writer | None = None

        for chunk_file in chunk_files:
            if next_global_flow > end_flow:
                break

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

                current_local_flow_id = 0

                for row in reader:
                    local_flow_id = int(row[flow_id_idx])
                    if local_flow_id != current_local_flow_id:
                        current_local_flow_id = local_flow_id
                        current_global_flow = next_global_flow
                        next_global_flow += 1
                    else:
                        current_global_flow = next_global_flow - 1

                    if current_global_flow > end_flow:
                        break
                    if current_global_flow < start_flow:
                        continue

                    row[flow_id_idx] = str(current_global_flow - start_flow + 1)
                    writer.writerow(row)
                    rows_written += 1
                    selected_flows = current_global_flow - start_flow + 1

    return selected_flows, rows_written


def main() -> None:
    args = parse_args()
    if args.num_flows is not None and args.end_flow is not None:
        raise ValueError("Use either --num-flows or --end-flow, not both")

    end_flow = args.end_flow
    if args.num_flows is not None:
        if args.num_flows <= 0:
            raise ValueError("--num-flows must be a positive integer")
        end_flow = args.start_flow + args.num_flows - 1
    if end_flow is None:
        raise ValueError("Either --num-flows or --end-flow must be provided")

    selected_flows, rows_written = extract_flow_range_from_chunks(
        Path(args.input_dir), Path(args.output), args.start_flow, end_flow
    )
    print(f"start_flow={args.start_flow}")
    print(f"end_flow={end_flow}")
    print(f"selected_flows={selected_flows}")
    print(f"rows_written={rows_written}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
