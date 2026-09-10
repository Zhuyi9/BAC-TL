#!/usr/bin/env python3
"""将已有 v3 固化伪未来数据扩展为长期试验所需的多个评估窗口。

已有 v3 数据实际包含三个未来窗口。为了先验证十轮长期评估流程，脚本
保留前三个窗口，并循环复用已有窗口的完整流记录生成后续窗口。后续窗口
不是新的独立采集数据，manifest 会明确记录这一点；正式论文实验应替换
为独立构造的十个连续伪未来窗口。
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from copy import deepcopy
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    """定义 v3 源目录、输出目录和目标窗口数。"""
    parser = argparse.ArgumentParser(description="扩展 pseudo_future_cosine_stratified_v3 评估窗口")
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rounds", type=int, default=10)
    return parser.parse_args()


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """读取项目 CSV 的表头和行。"""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_rows(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    """按原字段写出 CSV。"""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def combine_rows(paths: list[Path], output: Path) -> None:
    """合并多个真实窗口，并为各窗口重新分配不重复的 flow_id。"""
    writer = None
    offset = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        for path in paths:
            fields, rows = read_rows(path)
            if writer is None:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
            ids = set()
            for row in rows:
                local_id = int(row["flow_id"])
                ids.add(local_id)
                row["flow_id"] = str(local_id + offset)
                writer.writerow({field: row.get(field, "") for field in fields})
            if ids:
                offset += max(ids) + 1


def duplicate_to_count(rows: list[dict[str, str]], target_count: int) -> list[dict[str, str]]:
    """复制完整流直到达到指定流数量，并为复制流分配新 ID。"""
    by_id: dict[str, list[dict[str, str]]] = {}
    order: list[str] = []
    for row in rows:
        flow_id = str(row["flow_id"])
        if flow_id not in by_id:
            by_id[flow_id] = []
            order.append(flow_id)
        by_id[flow_id].append(row)
    if len(order) >= target_count:
        return rows
    result = list(rows)
    next_id = max(int(flow_id) for flow_id in order) + 1
    for index in range(target_count - len(order)):
        source_id = order[index % len(order)]
        for row in by_id[source_id]:
            copied = deepcopy(row)
            copied["flow_id"] = str(next_id)
            result.append(copied)
        next_id += 1
    return result


def main() -> None:
    """复制前三个 v3 窗口并循环扩展到指定轮数。"""
    args = parse_args()
    source = Path(args.source_dir).resolve()
    output = Path(args.output_dir).resolve()
    if args.rounds <= 0:
        raise ValueError("扩展窗口数必须大于 0")
    metadata_path = source / "future_window_metadata.csv"
    metadata = pd.read_csv(metadata_path)
    base_rounds = int(metadata["horizon"].max())
    if base_rounds < 3:
        raise RuntimeError("源 v3 数据少于 3 个伪未来窗口")
    output.mkdir(parents=True, exist_ok=True)

    # 依据每个目标时间窗从混合真实正类中拆出真实流，后续实验按轮次读取。
    real_fields, real_rows = read_rows(source / "real_positive.csv")
    real_by_window: dict[int, list[dict[str, str]]] = {}
    # 流的归属按 behavior 汇总行时间确定；链路层数据包可能跨越宏观窗口，
    # 不能直接按每个数据包时间分组，否则同一条流会被计入两个窗口。
    flow_windows: dict[str, int] = {}
    for row in real_rows:
        if row.get("layer") == "behavior":
            timestamp = float(row["timestamp"])
            flow_windows[str(row["flow_id"])] = int((timestamp // 60.0) * 60.0)
    for row in real_rows:
        window = flow_windows.get(str(row["flow_id"]))
        if window is not None:
            real_by_window.setdefault(window, []).append(row)
    target_starts = [float(value) for value in metadata["target_window_start"].tolist()]
    source_manifest = json.loads((source / "dataset_manifest.json").read_text(encoding="utf-8"))
    target_counts = [int(value) for value in source_manifest.get("target_counts", [])]
    if len(target_counts) < base_rounds:
        target_counts = [len({str(row["flow_id"]) for row in real_by_window.get(int(start), [])}) for start in target_starts]
    generated_fields, _ = read_rows(source / "future_window_01_generated.csv")
    new_metadata = []
    prediction_window_paths = []
    for horizon in range(1, args.rounds + 1):
        source_horizon = ((horizon - 1) % base_rounds) + 1
        source_meta = metadata.iloc[source_horizon - 1]
        generated_source = source / f"future_window_{source_horizon:02d}_generated.csv"
        generated_target = output / f"future_window_{horizon:02d}_generated.csv"
        shutil.copy2(generated_source, generated_target)

        source_start = float(source_meta["target_window_start"])
        real_target = output / f"real_window_{horizon:02d}.csv"
        selected_real = real_by_window.get(int(source_start), [])
        if not selected_real:
            raise RuntimeError(f"real_positive.csv 中没有目标窗口 {source_start}")
        # 后续循环窗口整体平移 60 秒，确保测试源中形成连续且可区分的十个时间窗。
        shift = (horizon - source_horizon) * 60.0
        shifted_real = []
        for row in selected_real:
            copied = deepcopy(row)
            copied["timestamp"] = str(float(copied["timestamp"]) + shift)
            shifted_real.append(copied)
        write_rows(real_target, real_fields, shifted_real)
        prediction_target = output / f"_prediction_window_{horizon:02d}.csv"
        prediction_rows = duplicate_to_count(shifted_real, target_counts[(source_horizon - 1) % len(target_counts)])
        write_rows(prediction_target, real_fields, prediction_rows)
        prediction_window_paths.append(prediction_target)
        real_flow_count = len({str(row["flow_id"]) for row in selected_real})
        new_metadata.append({
            "horizon": horizon,
            "target_window_start": target_starts[(horizon - 1) % len(target_starts)] + (horizon - source_horizon) * 60.0,
            "source_horizon": source_horizon,
            "target_real_flow_count": int(real_flow_count),
            "generated_flow_count": int(source_meta["generated_flow_count"]),
            "actual_flow_count": int(source_meta["actual_flow_count"]),
            "extension_mode": "observed_v3_for_first_3; shifted_cyclic_replay_after_3",
        })

    # 负类池和源数据清单沿用 v3，便于每轮按同一原始标签比例抽样。
    shutil.copy2(source / "ids_negative.csv", output / "ids_negative.csv")
    shutil.copy2(source / "generation_config.json", output / "base_generation_config.json")
    combine_rows(prediction_window_paths, output / "test_positive_source.csv")
    manifest = {
        "dataset_type": "ctu13_pseudo_future_v3_long_term_extension",
        "source_dataset": str(source),
        "rounds": args.rounds,
        "observed_rounds": min(3, args.rounds),
        "extension_mode": "rounds_after_3_shifted_cyclic_replay_existing_v3_windows",
        "warning": "窗口 4 以后是已有 v3 伪未来窗口的循环复用，不是独立观测窗口。",
        "settings": {
            "macro_window": 60.0,
            "slice_window": 1.0,
            "nearest_metric": "cosine",
            "negative_mode": "stratified",
            "mix_ratio": 0.5,
        },
    }
    pd.DataFrame(new_metadata).to_csv(output / "future_window_metadata.csv", index=False)
    for path in prediction_window_paths:
        path.unlink(missing_ok=True)
    (output / "dataset_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
