#!/usr/bin/env python3
"""Analyze timestamp offsets between extracted flows and official CIC labels."""

from __future__ import annotations

import argparse
import bisect
from collections import Counter, defaultdict
from zoneinfo import ZoneInfo

import ast
import json
from pathlib import Path

import numpy as np
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare flow timestamps with the nearest official CIC flow timestamps."
    )
    parser.add_argument("--official-csv", required=True, help="Official labeled CIC CSV path.")
    parser.add_argument("--my-csv", required=True, help="Extracted flow CSV path.")
    parser.add_argument(
        "--chunksize",
        type=int,
        default=200000,
        help="Chunk size for CSV reads.",
    )
    parser.add_argument(
        "--tz-name",
        default="America/Toronto",
        help="Timezone used to interpret official timestamps.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="How many most common rounded offsets to print.",
    )
    return parser.parse_args()


def parse_official_csv(official_csv: str, chunksize: int, tz_name: str):
    idx = defaultdict(list)
    tz = ZoneInfo(tz_name)
    usecols = [
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Protocol",
        "Timestamp",
        "Label",
    ]

    for chunk in pd.read_csv(
        official_csv,
        usecols=usecols,
        chunksize=chunksize,
        dtype=str,
        low_memory=False,
        encoding="utf-8-sig",
        skipinitialspace=True,
    ):
        ts_series = pd.to_datetime(chunk["Timestamp"], dayfirst=True, errors="coerce")

        def to_epoch(ts):
            if pd.isna(ts):
                return None
            if ts.tzinfo is None:
                try:
                    ts = ts.replace(tzinfo=tz)
                except Exception:
                    ts = ts.tz_localize(tz)
            return float(ts.timestamp())

        for pos, (_, row) in enumerate(chunk.iterrows()):
            ts = to_epoch(ts_series.iat[pos])
            if ts is None:
                continue
            key = (
                str(row["Source IP"]).strip(),
                str(row["Source Port"]).strip(),
                str(row["Destination IP"]).strip(),
                str(row["Destination Port"]).strip(),
                str(row["Protocol"]).strip().upper(),
            )
            idx[key].append(ts)

    final_idx = {}
    for key, timestamps in idx.items():
        timestamps.sort()
        final_idx[key] = timestamps
    return final_idx


def build_my_flow_index(my_csv: str, chunksize: int):
    flow_index = {}

    for chunk in pd.read_csv(my_csv, chunksize=chunksize, dtype={"flow_id": str}, low_memory=False):
        for _, row in chunk.iterrows():
            flow_id = str(row.get("flow_id"))
            if flow_id in ("nan", "None"):
                continue

            ts = row.get("timestamp")
            try:
                ts = float(ts)
            except Exception:
                ts = None

            if flow_id not in flow_index:
                flow_index[flow_id] = {
                    "first_ts": ts if ts is not None else np.inf,
                    "src": None,
                    "dst": None,
                    "sport": None,
                    "dport": None,
                    "proto": None,
                }

            if ts is not None and ts < flow_index[flow_id]["first_ts"]:
                flow_index[flow_id]["first_ts"] = ts

            enc = row.get("encoding_header")
            if pd.isna(enc):
                continue

            try:
                parsed = json.loads(enc)
            except Exception:
                try:
                    parsed = ast.literal_eval(enc)
                except Exception:
                    parsed = None

            if not isinstance(parsed, dict):
                continue

            if parsed.get("src_ip"):
                flow_index[flow_id]["src"] = str(parsed.get("src_ip"))
            if parsed.get("dst_ip"):
                flow_index[flow_id]["dst"] = str(parsed.get("dst_ip"))
            if parsed.get("proto") is not None:
                p = parsed.get("proto")
                try:
                    pi = int(p)
                    if pi == 6:
                        flow_index[flow_id]["proto"] = "6"
                    elif pi == 17:
                        flow_index[flow_id]["proto"] = "17"
                    else:
                        flow_index[flow_id]["proto"] = str(p)
                except Exception:
                    flow_index[flow_id]["proto"] = str(p).upper()
            if parsed.get("sport") is not None:
                flow_index[flow_id]["sport"] = str(parsed.get("sport"))
            if parsed.get("dport") is not None:
                flow_index[flow_id]["dport"] = str(parsed.get("dport"))
            if parsed.get("type") is not None and flow_index[flow_id]["proto"] is None:
                proto = str(parsed.get("type")).upper()
                flow_index[flow_id]["proto"] = "6" if proto == "TCP" else "17" if proto == "UDP" else proto

    for meta in flow_index.values():
        if meta["first_ts"] == np.inf:
            meta["first_ts"] = None

    return flow_index


def nearest_diff(ts: float, candidates: list[float]) -> float | None:
    if not candidates:
        return None
    pos = bisect.bisect_left(candidates, ts)
    diffs = []
    if pos < len(candidates):
        diffs.append(candidates[pos] - ts)
    if pos > 0:
        diffs.append(candidates[pos - 1] - ts)
    if not diffs:
        return None
    return min(diffs, key=lambda d: abs(d))


def analyze_offsets(flow_index, official_idx):
    matched = []
    unmatched_key = 0
    incomplete = 0

    for meta in flow_index.values():
        src = meta.get("src")
        dst = meta.get("dst")
        sport = meta.get("sport")
        dport = meta.get("dport")
        proto = meta.get("proto")
        ts = meta.get("first_ts")

        if not all([src, dst, sport, dport, proto]) or ts is None:
            incomplete += 1
            continue

        key_fwd = (src, sport, dst, dport, str(proto).upper())
        key_rev = (dst, dport, src, sport, str(proto).upper())

        best = None
        for key in (key_fwd, key_rev):
            diff = nearest_diff(ts, official_idx.get(key, []))
            if diff is None:
                continue
            if best is None or abs(diff) < abs(best):
                best = diff

        if best is None:
            unmatched_key += 1
        else:
            matched.append(best)

    return matched, unmatched_key, incomplete


def main() -> None:
    args = parse_args()

    official_idx = parse_official_csv(args.official_csv, args.chunksize, args.tz_name)
    flow_index = build_my_flow_index(args.my_csv, args.chunksize)
    diffs, unmatched_key, incomplete = analyze_offsets(flow_index, official_idx)

    print(f"total_flows={len(flow_index)}")
    print(f"matched_by_key={len(diffs)}")
    print(f"unmatched_key={unmatched_key}")
    print(f"incomplete_meta={incomplete}")

    if not diffs:
        return

    arr = np.array(diffs, dtype=np.float64)
    abs_arr = np.abs(arr)
    print(f"diff_seconds_min={arr.min():.3f}")
    print(f"diff_seconds_max={arr.max():.3f}")
    print(f"diff_seconds_mean={arr.mean():.3f}")
    print(f"diff_seconds_median={np.median(arr):.3f}")
    print(f"abs_diff_seconds_mean={abs_arr.mean():.3f}")
    print(f"abs_diff_seconds_median={np.median(abs_arr):.3f}")
    for q in (5, 25, 75, 95):
        print(f"abs_diff_p{q}={np.percentile(abs_arr, q):.3f}")

    rounded = Counter(int(round(x)) for x in arr)
    print("top_rounded_offsets_seconds=")
    for offset, count in rounded.most_common(args.top_k):
        print(f"{offset}: {count}")


if __name__ == "__main__":
    main()
