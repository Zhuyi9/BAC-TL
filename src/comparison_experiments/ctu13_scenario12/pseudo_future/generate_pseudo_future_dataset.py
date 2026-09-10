#!/usr/bin/env python3
"""生成受控概念漂移的伪未来测试集。

脚本只使用 CTU-13 训练段训练好的质心预测器和历史流作为生成种子。
默认模式递归应用相对变化；``direct`` 模式则从全部真实历史重新选择
种子，并直接使用检索到的历史目标流片内模式，不把生成结果回灌为种子。
生成正类不会写回训练集；它只和原测试段的真实正类按窗口约 50/50 混合。
负类先排除目标标签，再优先从 IDS-2017 时间尾段抽样；尾段不足时向更早
的非目标数据扩展，最终形成固定测试集。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

SCRIPT_DIR = Path(__file__).resolve().parent
# pseudo_future/ctu13_scenario12/comparison_experiments/flow_gene
PROJECT_ROOT = SCRIPT_DIR.parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ReconstitutePackets import reconstruct_csv_to_pcap
from drift_prediction.bridge import centroid_to_drift_profile
from drift_prediction.common import extract_multiple_flows, flow_to_temporal_coordinates, parse_labeled_csv
from drift_prediction.generate_single_step_from_centroid_prediction import (
    extract_link_packet_curve,
    packet_curve_to_slice_profile,
    select_nearest_historical_flow,
    temporal_profile_metrics,
)
from drift_prediction.model import CentroidSeqTransformer
from label_utils import canonicalize_label


def parse_args() -> argparse.Namespace:
    """定义输入数据、模型位置和递归窗口参数。"""
    parser = argparse.ArgumentParser(description="构造 CTU-13 受控概念漂移伪未来测试集")
    parser.add_argument("--train_csv", required=True)
    parser.add_argument("--test_positive_csv", required=True)
    parser.add_argument("--ids_csv", required=True)
    parser.add_argument("--centroid_dir", required=True)
    parser.add_argument("--model_path", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--label", default="Botnet")
    parser.add_argument("--horizons", type=int, default=3)
    parser.add_argument("--macro_window", type=float, default=60.0)
    parser.add_argument("--slice_window", type=float, default=1.0)
    parser.add_argument("--max_slices", type=int, default=60)
    parser.add_argument("--min_packets", type=int, default=2)
    parser.add_argument("--mix_ratio", type=float, default=0.5, help="每个测试窗口使用的生成正类比例")
    parser.add_argument(
        "--generated_multiplier", type=float, default=1.0,
        help="在基础生成比例上扩大生成流数量；默认 1，不改变原窗口规模",
    )
    parser.add_argument("--negative_count", type=int, default=0, help="负类数量；0 表示与选出的正类相同")
    parser.add_argument("--random_state", type=int, default=42)
    parser.add_argument(
        "--generation_mode",
        choices=["recursive_relative", "direct"],
        default="recursive_relative",
        help="recursive_relative 使用 alpha/beta 递归重构；direct 直接使用历史目标流片内模式",
    )
    parser.add_argument(
        "--nearest_metric",
        choices=["normalized_euclidean", "cosine"],
        default="normalized_euclidean",
        help="直接模式检索目标历史流时使用的距离",
    )
    parser.add_argument(
        "--negative_mode",
        choices=["stratified", "benign_first"],
        default="stratified",
        help="固定负类按原标签比例抽样，或在独立测试尾段优先选择 BENIGN",
    )
    parser.add_argument("--intra_slice_mode", choices=["even", "random", "jitter"], default="even")
    parser.add_argument("--size_noise_sigma", type=float, default=0.10)
    parser.add_argument("--time_jitter_ratio", type=float, default=0.05)
    parser.add_argument("--time_jitter_cap", type=float, default=0.05)
    parser.add_argument(
        "--allow_seed_reuse",
        action="store_true",
        help="历史正类流不足以覆盖多个伪未来窗口时允许重复使用种子流",
    )
    return parser.parse_args()


def load_model(model_path: Path, device: torch.device):
    """加载质心 Transformer 及训练阶段归一化参数。"""
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    model = CentroidSeqTransformer(**checkpoint["config"]).to(device)
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    return model, checkpoint


def predict_next_centroid(model, checkpoint, history, label_id, device):
    """根据当前连续历史窗口预测下一个窗口质心。"""
    max_history_len = int(checkpoint["config"]["history_len"])
    centroid_shape = tuple(checkpoint["centroid_shape"])
    sequence = np.stack(history[-max_history_len:]).astype(np.float32)
    length = sequence.shape[0]
    padded = np.zeros((max_history_len,) + centroid_shape, dtype=np.float32)
    padded[:length] = sequence
    normalized = ((padded[None, ...] - checkpoint["x_mean"]) / checkpoint["x_std"]).astype(np.float32)
    if length < max_history_len:
        normalized[:, length:] = 0.0
    normalized = normalized.reshape(1, max_history_len, -1)
    with torch.no_grad():
        output = model(
            torch.from_numpy(normalized).to(device),
            torch.tensor([label_id], dtype=torch.long, device=device),
            lengths=torch.tensor([length], dtype=torch.long, device=device),
        )
    centroid = output.cpu().numpy().reshape((1,) + centroid_shape)[0]
    # 训练检查点的 y_mean/y_std 带有 keepdims 产生的首维，去掉后再还原
    # 为单个质心的 [切片数, 3] 形状，避免广播出多余批次维度。
    y_mean = np.asarray(checkpoint["y_mean"], dtype=np.float32).reshape(centroid_shape)
    y_std = np.asarray(checkpoint["y_std"], dtype=np.float32).reshape(centroid_shape)
    centroid = centroid * y_std + y_mean
    centroid[:, 0] = history[-1][:, 0]
    centroid[:, 1:] = np.maximum(centroid[:, 1:], 0.0)
    return centroid.astype(np.float32)


def latest_training_ids(train_csv: Path, label: str, min_packets: int, macro_window: float, count: int | None = None):
    """选择训练段最后一个完整窗口的种子流，数量不足时明确报错。"""
    rows = []
    with train_csv.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") != "behavior":
                continue
            stats = json.loads(row.get("encoding_header") or "{}")
            if int(stats.get("packet_count", 0)) < min_packets:
                continue
            timestamp = float(row["timestamp"])
            rows.append((str(row["flow_id"]), timestamp, math.floor(timestamp / macro_window) * macro_window))
    if not rows:
        raise RuntimeError("训练 CSV 没有满足 min_packets 的种子流")
    last_window = max(item[2] for item in rows)
    candidates = sorted([item for item in rows if item[2] == last_window], key=lambda item: (item[1], item[0]))
    requested = len(candidates) if count is None else count
    if requested > len(candidates):
        raise RuntimeError(f"训练最后窗口只有 {len(candidates)} 条流，无法生成 {requested} 条种子流")
    if requested == len(candidates):
        return [item[0] for item in candidates]
    indices = np.linspace(0, len(candidates) - 1, requested).round().astype(int)
    return [candidates[index][0] for index in indices]


def select_csv_flow_ids(csv_path: Path, count: int) -> list[str]:
    """从上一轮生成 CSV 中按稳定顺序选择指定数量的完整流。"""
    rows = read_behavior_rows(csv_path, min_packets=1)
    ids = []
    seen = set()
    for row in rows:
        if row["flow_id"] not in seen:
            seen.add(row["flow_id"])
            ids.append(row["flow_id"])
    if count > len(ids):
        raise RuntimeError(f"上一轮生成结果只有 {len(ids)} 条有效流，无法选择 {count} 条")
    if count == len(ids):
        return ids
    indices = np.linspace(0, len(ids) - 1, count).round().astype(int)
    return [ids[index] for index in indices]


def centroid_from_csv(csv_path: Path, label: str, max_slices: int, slice_window: float) -> np.ndarray:
    """从实际生成 CSV 重新计算单窗口质心。"""
    flows = parse_labeled_csv(csv_path, max_slices=max_slices, slice_window=slice_window, label_override=label)
    if not flows:
        raise RuntimeError(f"无法从 {csv_path} 解析有效生成流")
    return np.stack([flow_to_temporal_coordinates(flow, slice_window) for flow in flows]).mean(axis=0).astype(np.float32)


def read_behavior_rows(path: Path, min_packets: int):
    """仅读取行为行，用于不加载 payload 地定位流和时间窗口。"""
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") != "behavior":
                continue
            stats = json.loads(row.get("encoding_header") or "{}")
            if int(stats.get("packet_count", 0)) >= min_packets:
                rows.append({"flow_id": str(row["flow_id"]), "timestamp": float(row["timestamp"]), "label": row.get("label", "")})
    return rows


def select_direct_history_seed_ids(
    train_csv: Path,
    label: str,
    count: int,
    min_packets: int,
    used_ids: set[str],
    allow_reuse: bool = False,
) -> list[str]:
    """从全部训练历史按时间均匀选择未使用的种子流。

    直接模式不把上一轮生成结果作为下一轮种子，避免重构误差递归放大。
    每个目标窗口都重新从真实历史中选流，并尽量覆盖不同历史时间段。
    """
    candidates = []
    with train_csv.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") != "behavior":
                continue
            if canonicalize_label(row.get("label")) != label:
                continue
            try:
                stats = json.loads(row.get("encoding_header") or "{}")
            except json.JSONDecodeError:
                stats = {}
            if int(stats.get("packet_count", 0)) < min_packets:
                continue
            flow_id = str(row["flow_id"])
            if flow_id in used_ids and not allow_reuse:
                continue
            candidates.append((float(row["timestamp"]), flow_id))
    candidates.sort(key=lambda item: (item[0], item[1]))
    if len(candidates) < count and allow_reuse:
        # 小型 PCAP 经常没有足够多的互不重复历史流。允许复用时保持
        # 时间均匀抽样，并由后续 CSV 合并步骤重新分配 flow_id。
        ranks = np.arange(count, dtype=int) % len(candidates)
        return [candidates[index][1] for index in ranks]
    if len(candidates) < count:
        raise RuntimeError(
            f"真实历史中只有 {len(candidates)} 条未使用有效流，无法构造 {count} 条直接模式种子"
        )
    if count == len(candidates):
        selected = candidates
    else:
        ranks = np.linspace(0, len(candidates) - 1, count).round().astype(int)
        selected = [candidates[index] for index in ranks]
    return [flow_id for _, flow_id in selected]


def write_selected_flows(source: Path, selected_ids: set[str], output: Path, label_override: str | None = None) -> None:
    """按流完整复制 CSV，并可统一补充标签列。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8", newline="") as fin:
        reader = csv.DictReader(fin)
        fields = list(reader.fieldnames or [])
        if "label" not in fields:
            fields.append("label")
        with output.open("w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=fields)
            writer.writeheader()
            for row in reader:
                if str(row["flow_id"]) not in selected_ids:
                    continue
                if label_override is not None:
                    row["label"] = label_override
                writer.writerow(row)


def combine_csvs(paths: list[Path], output: Path, label: str | None = None) -> int:
    """合并多个流 CSV，重编号 flow_id 并统一保留标签列。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    next_offset = 0
    flow_count = 0
    with output.open("w", encoding="utf-8", newline="") as fout:
        writer = None
        for path in paths:
            with path.open("r", encoding="utf-8", newline="") as fin:
                reader = csv.DictReader(fin)
                fields = list(reader.fieldnames or [])
                if "label" not in fields:
                    fields.append("label")
                if writer is None:
                    writer = csv.DictWriter(fout, fieldnames=fields)
                    writer.writeheader()
                local_ids = set()
                for row in reader:
                    local_id = int(row["flow_id"])
                    local_ids.add(local_id)
                    row["flow_id"] = str(local_id + next_offset)
                    if label is not None:
                        row["label"] = label
                    writer.writerow({field: row.get(field, "") for field in fields})
                if local_ids:
                    next_offset += max(local_ids) + 1
                    flow_count += len(local_ids)
    return flow_count


def select_negative_ids(
    ids_csv: Path,
    desired: int,
    random_state: int,
    min_packets: int,
    mode: str,
    excluded_label: str,
):
    """从 IDS-2017 抽取非目标流，测试尾段不足时向更早数据扩展。"""
    rows = read_behavior_rows(ids_csv, min_packets)
    ordered = sorted(rows, key=lambda row: (row["timestamp"], row["flow_id"]))
    test_start = max(1, int(len(ordered) * 0.8))
    canonical_excluded = canonicalize_label(excluded_label)
    eligible = [
        row for row in ordered
        if canonicalize_label(row.get("label")) != canonical_excluded
    ]
    # 优先保持原有的时间尾段测试逻辑。排除目标标签后数量不足时，再从
    # 更早的非目标流补充，以免通过缩减负类破坏测试集正负类平衡。
    tail_ids = {str(row["flow_id"]) for row in ordered[test_start:]}
    tail_eligible = [row for row in eligible if str(row["flow_id"]) in tail_ids]
    candidate_rows = tail_eligible if len(tail_eligible) >= desired else eligible
    candidates = pd.DataFrame(candidate_rows)
    if candidates.empty:
        raise RuntimeError(f"IDS-2017 没有排除 {canonical_excluded} 后的可用负类流")
    desired = min(desired, len(candidates))
    rng = np.random.default_rng(random_state)
    if mode == "benign_first":
        benign = candidates[
            candidates["label"].map(canonicalize_label) == "BENIGN"
        ]
        benign_take = min(desired, len(benign))
        chosen = (
            rng.choice(benign.index.to_numpy(), size=benign_take, replace=False).tolist()
            if benign_take
            else []
        )
        if len(chosen) < desired:
            remaining = candidates.drop(index=chosen)
            chosen.extend(
                rng.choice(
                    remaining.index.to_numpy(),
                    size=desired - len(chosen),
                    replace=False,
                ).tolist()
            )
        return set(candidates.loc[sorted(chosen), "flow_id"].astype(str))

    chosen = []
    for _, group in candidates.groupby("label", dropna=False, sort=True):
        quota = min(len(group), max(1, int(round(desired * len(group) / len(candidates)))))
        chosen.extend(rng.choice(group.index.to_numpy(), size=quota, replace=False).tolist())
    if len(chosen) > desired:
        chosen = rng.choice(np.asarray(chosen), size=desired, replace=False).tolist()
    elif len(chosen) < desired:
        remaining = np.setdiff1d(candidates.index.to_numpy(), np.asarray(chosen))
        chosen.extend(rng.choice(remaining, size=desired - len(chosen), replace=False).tolist())
    return set(candidates.loc[sorted(chosen), "flow_id"].astype(str))


def sha256(path: Path) -> str:
    """计算文件哈希，便于之后复现实验输入。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()
    if args.horizons <= 0 or args.mix_ratio < 0 or args.mix_ratio > 1:
        raise ValueError("horizons 必须大于 0，mix_ratio 必须在 [0, 1] 内")
    if args.generated_multiplier <= 0:
        raise ValueError("generated_multiplier 必须大于 0")
    label = canonicalize_label(args.label)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    real_rows = read_behavior_rows(Path(args.test_positive_csv), args.min_packets)
    real_rows.sort(key=lambda row: (row["timestamp"], row["flow_id"]))
    if not real_rows:
        raise RuntimeError("原始测试正类为空")
    windows = {}
    for row in real_rows:
        start = math.floor(row["timestamp"] / args.macro_window) * args.macro_window
        windows.setdefault(start, []).append(row)
    selected_windows = sorted(windows)[: args.horizons]
    if len(selected_windows) < args.horizons:
        raise RuntimeError(f"原测试正类只有 {len(selected_windows)} 个窗口，无法构造 {args.horizons} 个伪未来窗口")
    target_counts = [len(windows[start]) for start in selected_windows]
    base_generated_counts = [max(1, int(math.ceil(count * args.mix_ratio))) for count in target_counts]
    generated_counts = [
        max(1, int(math.ceil(count * args.generated_multiplier)))
        for count in base_generated_counts
    ]
    # multiplier 只增加生成正类，真实正类仍按基础比例保留，便于区分
    # “增加合成样本”与“减少真实测试样本”两种影响。
    real_counts = [count - generated for count, generated in zip(target_counts, base_generated_counts)]

    centroid_dir = Path(args.centroid_dir)
    centroids = np.load(centroid_dir / "centroids.npy").astype(np.float32)
    centroid_meta = pd.read_csv(centroid_dir / "centroid_metadata.csv")
    label_meta = centroid_meta[centroid_meta["label"] == label].sort_values("window_start")
    if label_meta.empty:
        raise RuntimeError(f"质心目录中没有标签 {label}")
    history = [centroids[int(index)] for index in label_meta["centroid_index"]]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, checkpoint = load_model(Path(args.model_path), device)
    label_vocab = checkpoint["label_vocab"]
    label_id = int(label_vocab[label])
    work_seed = output_dir / "_seed.csv"
    # 旧模式从最后窗口开始递归；直接模式在每个窗口单独从全部历史选择种子。
    if args.generation_mode == "recursive_relative":
        seed_ids = latest_training_ids(
            Path(args.train_csv), label, args.min_packets,
            args.macro_window, generated_counts[0]
        )
        extract_multiple_flows(Path(args.train_csv), seed_ids, work_seed)
    else:
        seed_ids = []
    generated_csvs = []
    generated_meta = []
    alpha_beta_rows = []
    direct_profile_rows = []
    centroid_target_rows = []
    target_packet_rows = []
    predicted = []
    actual = []
    previous_centroid = history[-1]
    previous_csv = work_seed
    previous_count = len(seed_ids)
    used_direct_seed_ids: set[str] = set()

    for horizon, desired_count in enumerate(generated_counts, start=1):
        predicted_centroid = predict_next_centroid(model, checkpoint, history, label_id, device)
        generated_pcap = output_dir / f"future_window_{horizon:02d}_generated.pcap"
        generated_csv = output_dir / f"future_window_{horizon:02d}_generated.csv"
        if args.generation_mode == "direct":
            # 直接模式只使用预测质心检索历史目标流，不计算 alpha/beta。
            target_flow_id, target_flow_distance = select_nearest_historical_flow(
                Path(args.train_csv), predicted_centroid, label,
                args.min_packets, args.slice_window,
                metric=args.nearest_metric,
            )
            target_curve = extract_link_packet_curve(
                Path(args.train_csv), target_flow_id,
                observation_horizon=float(predicted_centroid.shape[0]) * args.slice_window,
            )
            target_profile = packet_curve_to_slice_profile(
                target_curve, args.slice_window, int(predicted_centroid.shape[0])
            )
            target_packets = np.asarray(
                [item["packet_count"] for item in target_profile], dtype=np.float64
            )
            target_bytes = np.asarray(
                [item["total_bytes"] for item in target_profile], dtype=np.float64
            )
            profile_metrics = temporal_profile_metrics(
                predicted_centroid[:, 1], predicted_centroid[:, 2],
                target_packets, target_bytes,
            )
            direct_seed_ids = select_direct_history_seed_ids(
                Path(args.train_csv), label, desired_count, args.min_packets,
                used_direct_seed_ids, allow_reuse=args.allow_seed_reuse,
            )
            used_direct_seed_ids.update(direct_seed_ids)
            direct_seed = output_dir / f"_direct_seed_h{horizon:02d}.csv"
            extract_multiple_flows(Path(args.train_csv), direct_seed_ids, direct_seed)
            previous_csv = direct_seed
            previous_count = len(direct_seed_ids)
            reconstruct_csv_to_pcap(
                str(previous_csv), str(generated_pcap), absolute_profile=target_profile,
                target_pattern_mode=True, slice_window=args.slice_window,
                intra_slice_mode=args.intra_slice_mode, size_noise_sigma=args.size_noise_sigma,
                time_jitter_ratio=args.time_jitter_ratio, time_jitter_cap=args.time_jitter_cap,
                output_csv=str(generated_csv),
            )
            direct_profile_rows.append({
                "horizon": horizon,
                "target_flow_id": target_flow_id,
                "nearest_metric": args.nearest_metric,
                "nearest_flow_distance": float(target_flow_distance),
                "target_packet_count": int(sum(item["packet_count"] for item in target_profile)),
                "target_link_bytes": int(sum(item["total_bytes"] for item in target_profile)),
                "seed_flow_count": len(direct_seed_ids),
                **profile_metrics,
            })
            for slice_index, item in enumerate(target_profile):
                centroid_target_rows.append({
                    "horizon": horizon,
                    "slice_index": slice_index,
                    "time_seconds": float(predicted_centroid[slice_index, 0]),
                    "predicted_packet_count": float(predicted_centroid[slice_index, 1]),
                    "predicted_link_bytes": float(predicted_centroid[slice_index, 2]),
                    "target_packet_count": int(item["packet_count"]),
                    "target_link_bytes": int(item["total_bytes"]),
                    "packet_difference": float(
                        item["packet_count"] - predicted_centroid[slice_index, 1]
                    ),
                    "link_bytes_difference": float(
                        item["total_bytes"] - predicted_centroid[slice_index, 2]
                    ),
                })
            for packet_index, packet in enumerate(target_curve):
                target_packet_rows.append({
                    "horizon": horizon,
                    "target_flow_id": target_flow_id,
                    "packet_index": packet_index,
                    "arrival_time": float(packet["arrival_time"]),
                    "slice_index": int(float(packet["arrival_time"]) // args.slice_window),
                    "frame_length": int(packet["frame_length"]),
                })
            drift_profile = None
        else:
            if horizon > 1:
                seed_ids = select_csv_flow_ids(previous_csv, desired_count)
                next_seed = output_dir / f"_seed_h{horizon:02d}.csv"
                extract_multiple_flows(previous_csv, seed_ids, next_seed)
                previous_csv = next_seed
            drift_profile = centroid_to_drift_profile(previous_centroid, predicted_centroid)
            reconstruct_csv_to_pcap(
                str(previous_csv), str(generated_pcap), drift_profile=drift_profile,
                relative_profile_mode=True, slice_window=args.slice_window,
                intra_slice_mode=args.intra_slice_mode, size_noise_sigma=args.size_noise_sigma,
                time_jitter_ratio=args.time_jitter_ratio, time_jitter_cap=args.time_jitter_cap,
                output_csv=str(generated_csv),
            )
        actual_centroid = centroid_from_csv(generated_csv, label, args.max_slices, args.slice_window)
        actual_flow_count = len(parse_labeled_csv(
            generated_csv, max_slices=args.max_slices,
            slice_window=args.slice_window, label_override=label
        ))
        if actual_flow_count != desired_count:
            raise RuntimeError(
                f"第 {horizon} 个伪未来窗口重构后只有 {actual_flow_count} 条流，"
                f"期望 {desired_count} 条；请检查种子流和协议可序列化性"
            )
        generated_csvs.append(generated_csv)
        predicted.append(predicted_centroid)
        actual.append(actual_centroid)
        generated_meta.append({
            "horizon": horizon, "target_window_start": selected_windows[horizon - 1],
            "target_real_flow_count": target_counts[horizon - 1],
            "generated_flow_count": desired_count,
            "actual_flow_count": actual_flow_count,
            "source_flow_count": previous_count,
            "predicted_packet_mean": float(predicted_centroid[:, 1].mean()),
            "predicted_link_bytes_mean": float(predicted_centroid[:, 2].mean()),
            "actual_packet_mean": float(actual_centroid[:, 1].mean()),
            "actual_link_bytes_mean": float(actual_centroid[:, 2].mean()),
            "generated_csv": str(generated_csv), "generated_pcap": str(generated_pcap),
        })
        if args.generation_mode == "recursive_relative":
            for slice_index, (alpha, beta) in enumerate(drift_profile):
                alpha_beta_rows.append({
                    "horizon": horizon,
                    "slice_index": slice_index,
                    "alpha": float(alpha),
                    "beta": float(beta),
                    "predicted_packet_count": float(predicted_centroid[slice_index, 1]),
                    "predicted_link_bytes": float(predicted_centroid[slice_index, 2]),
                    "previous_packet_count": float(previous_centroid[slice_index, 1]),
                    "previous_link_bytes": float(previous_centroid[slice_index, 2]),
                })
            history.append(actual_centroid)
            previous_centroid = actual_centroid
            previous_count = desired_count
        else:
            # 下一窗口仍由模型根据真实历史和此前预测质心得到；生成包本身不回灌。
            history.append(predicted_centroid)
            previous_centroid = predicted_centroid

    generated_positive = output_dir / "generated_positive.csv"
    real_positive = output_dir / "real_positive.csv"
    mixed_positive = output_dir / "pseudo_future_positive.csv"
    ids_negative = output_dir / "ids_negative.csv"
    selected_real_paths = []
    for index, window_start in enumerate(selected_windows):
        ids = {row["flow_id"] for row in windows[window_start]}
        keep = sorted(ids)[: real_counts[index]]
        part = output_dir / f"_real_h{index + 1:02d}.csv"
        write_selected_flows(Path(args.test_positive_csv), set(keep), part, label)
        selected_real_paths.append(part)
    combine_csvs(generated_csvs, generated_positive, label)
    combine_csvs(selected_real_paths, real_positive, label)
    combine_csvs([real_positive, generated_positive], mixed_positive, label)
    total_positive = sum(real_counts) + sum(generated_counts)
    negative_count = args.negative_count or total_positive
    negative_ids = select_negative_ids(
        Path(args.ids_csv), negative_count, args.random_state,
        args.min_packets, args.negative_mode, label,
    )
    write_selected_flows(Path(args.ids_csv), negative_ids, ids_negative)
    selected_negative_rows = read_behavior_rows(ids_negative, args.min_packets)
    leaked_target_count = sum(
        canonicalize_label(row.get("label")) == label
        for row in selected_negative_rows
    )
    if leaked_target_count:
        raise RuntimeError(
            f"固定负类仍包含 {leaked_target_count} 条目标标签 {label} 流"
        )

    # 固定测试集同时保存一个合并版本，分类器实际通过 positive/negative 两个文件读取。
    combined_test = output_dir / "pseudo_future_test.csv"
    combine_csvs([mixed_positive, ids_negative], combined_test)
    np.save(output_dir / "predicted_centroids.npy", np.stack(predicted).astype(np.float32))
    np.save(output_dir / "actual_centroids.npy", np.stack(actual).astype(np.float32))
    pd.DataFrame(generated_meta).to_csv(output_dir / "future_window_metadata.csv", index=False)
    if args.generation_mode == "direct":
        pd.DataFrame(direct_profile_rows).to_csv(
            output_dir / "direct_profile_summary.csv", index=False
        )
        pd.DataFrame(centroid_target_rows).to_csv(
            output_dir / "predicted_centroid_vs_target_flow.csv", index=False
        )
        pd.DataFrame(target_packet_rows).to_csv(
            output_dir / "target_flow_packet_curve.csv", index=False
        )
    else:
        pd.DataFrame(alpha_beta_rows).to_csv(output_dir / "alpha_beta_summary.csv", index=False)
    with (output_dir / "generation_config.json").open("w", encoding="utf-8") as handle:
        json.dump(vars(args), handle, ensure_ascii=False, indent=2)
    manifest = {
        "label": label, "horizons": args.horizons, "target_window_starts": selected_windows,
        "target_counts": target_counts, "generated_counts": generated_counts, "real_counts": real_counts,
        "negative_count": len(negative_ids),
        "negative_mode": args.negative_mode,
        "negative_excluded_label": label,
        "negative_label_counts": {
            str(key): int(value)
            for key, value in pd.Series(
                [row["label"] for row in selected_negative_rows]
            ).value_counts(dropna=False).items()
        },
        "test_count": total_positive + len(negative_ids),
        "files": {},
    }
    manifest_paths = [
        generated_positive, real_positive, mixed_positive, ids_negative,
        combined_test, *generated_csvs,
    ]
    if args.generation_mode == "direct":
        manifest_paths.extend([
            output_dir / "direct_profile_summary.csv",
            output_dir / "predicted_centroid_vs_target_flow.csv",
            output_dir / "target_flow_packet_curve.csv",
        ])
    else:
        manifest_paths.append(output_dir / "alpha_beta_summary.csv")
    for path in manifest_paths:
        manifest["files"][path.name] = {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}
    (output_dir / "dataset_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    for path in [
        work_seed,
        *[output_dir / f"_seed_h{h:02d}.csv" for h in range(2, args.horizons + 1)],
        *[output_dir / f"_direct_seed_h{h:02d}.csv" for h in range(1, args.horizons + 1)],
        *selected_real_paths,
    ]:
        path.unlink(missing_ok=True)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
