#!/usr/bin/env python3
"""计算仿构流与历史目标流逐包离散曲线的余弦相似度。"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="计算生成流和历史目标流的逐包曲线相似度")
    parser.add_argument("--generated-csv", required=True)
    parser.add_argument("--target-curve", required=True)
    return parser.parse_args()


def load_generated_curves(csv_path: Path) -> list[np.ndarray]:
    """按流读取 ``(相对到达时刻, 链路层帧长度)`` 点序列。"""
    packets: dict[str, list[tuple[int, float, int]]] = defaultdict(list)
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["layer"] != "link":
                continue
            packets[str(row["flow_id"])].append(
                (int(row["packet_index"]), float(row["timestamp"]), int(row["size"]))
            )

    curves = []
    for flow_id in sorted(packets, key=lambda value: int(value)):
        ordered = sorted(packets[flow_id], key=lambda item: (item[0], item[1]))
        if not ordered:
            continue
        first_timestamp = ordered[0][1]
        curves.append(
            np.asarray(
                [
                    (max(timestamp - first_timestamp, 0.0), frame_length)
                    for _, timestamp, frame_length in ordered
                ],
                dtype=np.float64,
            )
        )
    if not curves:
        raise RuntimeError(f"生成输入没有有效链路层数据包: {csv_path}")
    return curves


def load_target_curve(profile_path: Path) -> tuple[np.ndarray, dict]:
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    records = payload.get("packet_curve") or []
    if not records:
        raise RuntimeError(f"历史目标流逐包曲线为空: {profile_path}")
    curve = np.asarray(
        [(float(item["arrival_time"]), int(item["frame_length"])) for item in records],
        dtype=np.float64,
    )
    return curve, payload


def cosine_similarity(left: np.ndarray, right: np.ndarray) -> float:
    left_flat = left.reshape(-1).astype(np.float64)
    right_flat = right.reshape(-1).astype(np.float64)
    denominator = np.linalg.norm(left_flat) * np.linalg.norm(right_flat)
    if denominator == 0:
        return float("nan")
    value = float(np.dot(left_flat, right_flat) / denominator)
    return float(np.clip(value, -1.0, 1.0))


def curve_similarities(generated: np.ndarray, target: np.ndarray) -> tuple[float, float]:
    """计算包长序列，以及到达时刻和包长二维点序列的整体余弦。"""
    if generated.shape != target.shape:
        raise RuntimeError(
            f"生成流和目标流的逐包曲线形状不一致: {generated.shape} != {target.shape}"
        )
    length_cosine = cosine_similarity(generated[:, 1], target[:, 1])

    # 两条曲线共同使用目标流尺度，保留生成流相对目标流的真实偏差。
    time_scale = max(float(np.max(np.abs(target[:, 0]))), 1e-12)
    length_scale = max(float(np.max(np.abs(target[:, 1]))), 1.0)
    scales = np.asarray([time_scale, length_scale], dtype=np.float64)
    curve_cosine = cosine_similarity(generated / scales, target / scales)
    return length_cosine, curve_cosine


def main() -> None:
    args = parse_args()
    generated_curves = load_generated_curves(Path(args.generated_csv))
    target_curve, target_metadata = load_target_curve(Path(args.target_curve))

    length_values = []
    curve_values = []
    exact_length_packets = 0
    total_packets = 0
    for generated_curve in generated_curves:
        length_cosine, curve_cosine = curve_similarities(generated_curve, target_curve)
        length_values.append(length_cosine)
        curve_values.append(curve_cosine)
        exact_length_packets += int(np.sum(generated_curve[:, 1] == target_curve[:, 1]))
        total_packets += len(target_curve)

    result = {
        "packet_length_cosine": float(np.mean(length_values)),
        "packet_curve_cosine": float(np.mean(curve_values)),
        "generated_flow_count": len(generated_curves),
        "target_flow_id": str(target_metadata.get("target_flow_id", "")),
        "target_packet_count": int(len(target_curve)),
        "nearest_flow_distance": float(target_metadata.get("nearest_flow_distance", float("nan"))),
        "exact_frame_length_fraction": float(exact_length_packets / max(total_packets, 1)),
        "aggregation": "per_generated_flow_cosine_then_mean",
        "packet_length_definition": "captured_link_layer_frame_length_bytes",
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
