#!/usr/bin/env python3
"""Split a labeled attack CSV by complete time windows without loading payloads."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """定义输入 CSV、输出目录和时间比例参数。"""
    parser = argparse.ArgumentParser(description="按流起始时间切分攻击 CSV")
    parser.add_argument("--input_csv", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--output_prefix", default="ctu13")
    parser.add_argument("--train_ratio", type=float, default=0.6)
    parser.add_argument("--calib_ratio", type=float, default=0.2)
    parser.add_argument("--macro_window", type=float, default=60.0)
    parser.add_argument("--min_packets", type=int, default=2)
    return parser.parse_args()


def choose_window_cuts(counts: list[int], train_ratio: float, calib_ratio: float) -> tuple[int, int]:
    """选择最接近目标流量比例、但不切断宏观窗口的两个边界。"""
    if len(counts) < 3:
        raise RuntimeError("有效宏观窗口少于 3 个，无法划分训练、校准和测试集")
    cumulative = []
    running = 0
    for count in counts:
        running += count
        cumulative.append(running)

    train_target = running * train_ratio
    calib_target = running * (train_ratio + calib_ratio)
    train_cut = min(range(1, len(counts) - 1), key=lambda idx: abs(cumulative[idx - 1] - train_target))
    calib_cut = min(
        range(train_cut + 1, len(counts)),
        key=lambda idx: abs(cumulative[idx - 1] - calib_target),
    )
    return train_cut, calib_cut


def main() -> None:
    """先定位每条流的时间分位点，再按完整流写出三个 CSV。"""
    args = parse_args()
    if not (0 < args.train_ratio < 1 and 0 <= args.calib_ratio < 1 and args.train_ratio + args.calib_ratio < 1):
        raise ValueError("train_ratio 和 calib_ratio 必须为有效比例，且总和小于 1")
    if args.macro_window <= 0:
        raise ValueError("--macro_window 必须大于 0")
    if args.min_packets <= 0:
        raise ValueError("--min_packets 必须大于 0")
    if not args.output_prefix or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in args.output_prefix):
        raise ValueError("--output_prefix 只能包含字母、数字、下划线和连字符")

    source = Path(args.input_csv)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 第一遍只读取 behavior 行。切分比例由有效流决定，但同一 60 秒窗口中的所有流
    # 最终进入同一数据段，避免训练段末尾出现被流数量分位点截断的残缺窗口。
    flow_info: dict[str, tuple[float, int]] = {}
    with source.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") == "behavior":
                try:
                    stats = json.loads(row.get("encoding_header") or "{}")
                except json.JSONDecodeError:
                    stats = {}
                flow_info[str(row["flow_id"])] = (
                    float(row["timestamp"]),
                    int(stats.get("packet_count", 0)),
                )
    if len(flow_info) < 3:
        raise RuntimeError("有效流数量不足，无法进行三段时间切分")

    window_counts: dict[float, int] = {}
    for timestamp, packet_count in flow_info.values():
        if packet_count < args.min_packets:
            continue
        window_start = math.floor(timestamp / args.macro_window) * args.macro_window
        window_counts[window_start] = window_counts.get(window_start, 0) + 1
    windows = sorted(window_counts)
    train_cut, calib_cut = choose_window_cuts(
        [window_counts[window] for window in windows], args.train_ratio, args.calib_ratio
    )
    train_last_window = windows[train_cut - 1]
    calib_last_window = windows[calib_cut - 1]

    train_ids = set()
    calib_ids = set()
    for flow_id, (timestamp, _) in flow_info.items():
        window_start = math.floor(timestamp / args.macro_window) * args.macro_window
        if window_start <= train_last_window:
            train_ids.add(flow_id)
        elif window_start <= calib_last_window:
            calib_ids.add(flow_id)

    handles = {
        "train": (output_dir / f"{args.output_prefix}_train.csv").open("w", encoding="utf-8", newline=""),
        "calib": (output_dir / f"{args.output_prefix}_calib.csv").open("w", encoding="utf-8", newline=""),
        "test": (output_dir / f"{args.output_prefix}_test.csv").open("w", encoding="utf-8", newline=""),
    }
    try:
        writer_map: dict[str, csv.DictWriter] | None = None
        with source.open("r", encoding="utf-8", newline="") as input_handle:
            reader = csv.DictReader(input_handle)
            if not reader.fieldnames:
                raise ValueError("输入 CSV 没有表头")
            writer_map = {name: csv.DictWriter(handle, fieldnames=reader.fieldnames) for name, handle in handles.items()}
            for writer in writer_map.values():
                writer.writeheader()
            for row in reader:
                flow_id = str(row["flow_id"])
                split = "train" if flow_id in train_ids else "calib" if flow_id in calib_ids else "test"
                writer_map[split].writerow(row)
    finally:
        for handle in handles.values():
            handle.close()

    valid_train = sum(
        packet_count >= args.min_packets and flow_id in train_ids
        for flow_id, (_, packet_count) in flow_info.items()
    )
    valid_calib = sum(
        packet_count >= args.min_packets and flow_id in calib_ids
        for flow_id, (_, packet_count) in flow_info.items()
    )
    valid_total = sum(packet_count >= args.min_packets for _, packet_count in flow_info.values())
    print(
        f"flows={len(flow_info)} valid_flows={valid_total} "
        f"valid_train={valid_train} valid_calib={valid_calib} valid_test={valid_total - valid_train - valid_calib} "
        f"train_last_window={train_last_window} calib_last_window={calib_last_window}"
    )


if __name__ == "__main__":
    main()
