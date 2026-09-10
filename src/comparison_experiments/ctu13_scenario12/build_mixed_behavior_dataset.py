#!/usr/bin/env python3
"""Build a reproducible attack/IDS-2017 behavior classification split."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
import sys

import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from classification.behavior_vectorizer import load_flows_from_csv, maybe_convert_input, vectorize_flows
from classification.prepare_behavior_augmented_dataset import smote_oversample
from label_utils import canonicalize_label


def parse_args() -> argparse.Namespace:
    """定义两个数据源、时间切分和增强数量等可复现实验参数。"""
    parser = argparse.ArgumentParser(description="构造攻击正类 vs IDS-2017 多标签行为数据集")
    parser.add_argument("--positive_csv", "--ctu_csv", dest="positive_csv", required=True)
    parser.add_argument("--ids_csv", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--augmentation", choices=["none", "smote", "generated"], required=True)
    parser.add_argument("--generated_input")
    parser.add_argument("--target_label", default="Botnet")
    parser.add_argument("--positive_source", default="CTU-13")
    parser.add_argument("--train_ratio", type=float, default=0.6)
    parser.add_argument("--calib_ratio", type=float, default=0.2)
    parser.add_argument("--window_size", type=float, default=60.0)
    parser.add_argument("--max_real_positive", "--max-real-positive", type=int, default=3000)
    parser.add_argument("--augmentation_count", "--augmentation-count", type=int, default=3000)
    parser.add_argument("--max_ids_negative", "--max-ids-negative", type=int, default=10000)
    parser.add_argument(
        "--fixed_test_positive_csv",
        help="可选：固定测试正类项目 CSV；提供后不再从 positive_csv 的末段构造测试正类",
    )
    parser.add_argument(
        "--fixed_test_negative_csv",
        help="可选：固定测试负类项目 CSV；提供后不再从 ids_csv 构造测试负类",
    )
    parser.add_argument(
        "--train_negative_ratio",
        type=float,
        help="可选：训练负类最多保留为真实训练正类数量的指定倍数，不改变校准集和测试集。",
    )
    parser.add_argument("--min_packets", type=int, default=2)
    parser.add_argument("--random_state", type=int, default=42)
    return parser.parse_args()


def temporal_split(meta: pd.DataFrame, train_ratio: float, calib_ratio: float, random_state: int):
    """在单个数据源内部按相对时间划分训练、校准和测试流。"""
    if not 0 < train_ratio < 1 or not 0 <= calib_ratio < 1 or train_ratio + calib_ratio >= 1:
        raise ValueError("train_ratio 和 calib_ratio 必须满足 0 < train_ratio，且两者之和小于 1")
    ordered = meta.sort_values(["relative_time", "flow_id"], kind="stable")
    n = len(ordered)
    train_end = max(1, int(n * train_ratio))
    calib_end = max(train_end + 1, int(n * (train_ratio + calib_ratio)))
    calib_end = min(calib_end, n - 1) if n > 2 else n
    return (
        ordered.iloc[:train_end].copy(),
        ordered.iloc[train_end:calib_end].copy(),
        ordered.iloc[calib_end:].copy(),
    )


def temporal_window_split(meta: pd.DataFrame, train_ratio: float, calib_ratio: float, window_size: float = 60.0):
    """按完整宏观窗口切分正类，确保窗口不会跨越数据集边界。"""
    if not 0 < train_ratio < 1 or not 0 <= calib_ratio < 1 or train_ratio + calib_ratio >= 1:
        raise ValueError("train_ratio 和 calib_ratio 必须满足 0 < train_ratio，且两者之和小于 1")
    ordered = meta.sort_values(["relative_time", "flow_id"], kind="stable").copy()
    ordered["_window_start"] = np.floor(ordered["timestamp"].astype(float) / window_size) * window_size
    counts = ordered.groupby("_window_start", sort=True).size()
    if len(counts) < 3:
        raise RuntimeError("正类有效宏观窗口少于 3 个，无法划分训练、校准和测试集")

    cumulative = counts.cumsum().to_numpy()
    total = int(cumulative[-1])
    train_cut = min(range(1, len(counts) - 1), key=lambda idx: abs(cumulative[idx - 1] - total * train_ratio))
    calib_cut = min(
        range(train_cut + 1, len(counts)),
        key=lambda idx: abs(cumulative[idx - 1] - total * (train_ratio + calib_ratio)),
    )
    windows = counts.index.to_numpy()
    train_last = windows[train_cut - 1]
    calib_last = windows[calib_cut - 1]
    train = ordered[ordered["_window_start"] <= train_last].drop(columns="_window_start")
    calib = ordered[
        (ordered["_window_start"] > train_last) & (ordered["_window_start"] <= calib_last)
    ].drop(columns="_window_start")
    test = ordered[ordered["_window_start"] > calib_last].drop(columns="_window_start")
    return train, calib, test


def load_source(path: Path, label_override: str | None, min_packets: int, source_name: str):
    """读取项目 CSV 并提取 behavior 向量，同时建立来源和二分类元数据。"""
    flows = load_flows_from_csv(path, label_override=label_override)
    x, meta = vectorize_flows(flows, min_packets=min_packets)
    if meta.empty:
        raise RuntimeError(f"{source_name} 未提取到满足 min_packets 的流")
    meta = meta.reset_index(drop=True)
    meta["source"] = source_name
    meta["source_label"] = meta["label"].map(canonicalize_label)
    # 正类数据传入覆盖标签，IDS-2017 不覆盖其原始标签。
    meta["binary_label"] = 1 if label_override else 0
    meta["relative_time"] = meta["timestamp"].astype(float) - float(meta["timestamp"].min())
    return x, meta


def sample_real_positive(meta: pd.DataFrame, max_count: int, random_state: int) -> pd.DataFrame:
    """从真实训练正类中按时间均匀抽取固定数量的种子流。"""
    if max_count <= 0:
        raise ValueError("--max_real_positive 必须大于 0")
    positives = meta[meta["binary_label"] == 1]
    if len(positives) <= max_count:
        return positives
    # 时间均匀采样，避免只保留某个感染阶段。
    ranks = np.linspace(0, len(positives) - 1, max_count).round().astype(int)
    return positives.sort_values("relative_time", kind="stable").iloc[ranks].copy()


def limit_negative_source(meta: pd.DataFrame, max_count: int | None, random_state: int) -> pd.DataFrame:
    """Optionally cap IDS-2017 rows while preserving the original-label mix."""
    if max_count is None or len(meta) <= max_count:
        return meta
    if max_count <= 0:
        raise ValueError("--max_ids_negative 必须大于 0")
    rng = np.random.default_rng(random_state)
    chosen = []
    # 分层抽样保留 DoS、BENIGN、Unknown 等原始标签的大致比例。
    groups = list(meta.groupby("source_label", dropna=False, sort=True))
    for _, group in groups:
        quota = max(1, int(round(max_count * len(group) / len(meta))))
        quota = min(quota, len(group))
        chosen.extend(rng.choice(group.index.to_numpy(), size=quota, replace=False).tolist())
    if len(chosen) > max_count:
        chosen = rng.choice(np.asarray(chosen), size=max_count, replace=False).tolist()
    elif len(chosen) < max_count:
        remaining = np.setdiff1d(meta.index.to_numpy(), np.asarray(chosen))
        extra = rng.choice(remaining, size=min(max_count - len(chosen), len(remaining)), replace=False)
        chosen.extend(extra.tolist())
    return meta.loc[sorted(chosen)].copy()


def limit_training_negatives(
    meta: pd.DataFrame,
    positive_count: int,
    negative_ratio: float | None,
    random_state: int,
) -> pd.DataFrame:
    """按正类规模限制训练负类，同时保留 IDS-2017 原始标签构成。"""
    if negative_ratio is None:
        return meta
    if negative_ratio <= 0:
        raise ValueError("--train_negative_ratio 必须大于 0")
    max_count = max(1, int(round(positive_count * negative_ratio)))
    return limit_negative_source(meta, max_count, random_state)


def add_metadata_defaults(meta: pd.DataFrame, y: np.ndarray) -> pd.DataFrame:
    """补齐训练器和结果分析需要的统一元数据列。"""
    result = meta.copy().reset_index(drop=True)
    result["y"] = y.astype(np.int64)
    for name in ("source_label", "source", "relative_time"):
        if name not in result:
            result[name] = np.nan
    return result


def main() -> None:
    args = parse_args()
    target_label = canonicalize_label(args.target_label)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 两个数据源分别向量化，避免先生成一个更大的混合明细 CSV。
    positive_x, positive_meta = load_source(
        Path(args.positive_csv), target_label, args.min_packets, args.positive_source
    )
    ids_x, ids_meta = load_source(Path(args.ids_csv), None, args.min_packets, "IDS-2017")
    # 二分类负类必须严格排除当前目标标签。DoS 实验的正类和背景候选
    # 来自同一 IDS 文件，若不先过滤，会把真实 DoS 流以负标签参与训练。
    non_target_mask = ids_meta["source_label"] != target_label
    ids_x = ids_x[non_target_mask.to_numpy()]
    ids_meta = ids_meta.loc[non_target_mask].reset_index(drop=True)
    if ids_meta.empty:
        raise RuntimeError(f"IDS-2017 排除目标标签 {target_label} 后没有可用负类")
    ids_meta["binary_label"] = 0
    ids_meta = limit_negative_source(ids_meta, args.max_ids_negative, args.random_state)
    selected_ids = ids_meta.index.to_numpy()
    ids_x = ids_x[selected_ids]
    ids_meta = ids_meta.reset_index(drop=True)

    # 切分边界独立计算，绝对时间戳不会把 2011 和 2017 的数据强行排序到一起。
    positive_train, positive_calib, positive_test = temporal_window_split(
        positive_meta, args.train_ratio, args.calib_ratio, args.window_size
    )
    ids_train, ids_calib, ids_test = temporal_split(ids_meta, args.train_ratio, args.calib_ratio, args.random_state)
    positive_train = sample_real_positive(positive_train, args.max_real_positive, args.random_state)
    ids_train = limit_training_negatives(
        ids_train,
        positive_count=len(positive_train),
        negative_ratio=args.train_negative_ratio,
        random_state=args.random_state + 1,
    )
    train_positive_x = positive_x[positive_train.index.to_numpy()]
    train_ids_x = ids_x[ids_train.index.to_numpy()]
    calib_x = np.concatenate(
        [positive_x[positive_calib.index.to_numpy()], ids_x[ids_calib.index.to_numpy()]], axis=0
    )
    calib_y = np.concatenate(
        [np.ones(len(positive_calib), dtype=np.int64), np.zeros(len(ids_calib), dtype=np.int64)]
    )
    test_x = np.concatenate(
        [positive_x[positive_test.index.to_numpy()], ids_x[ids_test.index.to_numpy()]], axis=0
    )
    test_y = np.concatenate(
        [np.ones(len(positive_test), dtype=np.int64), np.zeros(len(ids_test), dtype=np.int64)]
    )

    if bool(args.fixed_test_positive_csv) != bool(args.fixed_test_negative_csv):
        raise ValueError("固定测试集必须同时提供 --fixed_test_positive_csv 和 --fixed_test_negative_csv")
    if args.fixed_test_positive_csv and args.fixed_test_negative_csv:
        # 训练和校准仍来自原始时序划分；只有最终测试段替换为预先固化的
        # 真实/伪未来混合数据，确保 none、SMOTE、generated 共用完全相同的测试样本。
        fixed_positive_x, fixed_positive_meta = load_source(
            Path(args.fixed_test_positive_csv), target_label, args.min_packets, "fixed-test-positive"
        )
        fixed_negative_x, fixed_negative_meta = load_source(
            Path(args.fixed_test_negative_csv), None, args.min_packets, "fixed-test-negative"
        )
        leaked_target_count = int(
            (fixed_negative_meta["source_label"] == target_label).sum()
        )
        if leaked_target_count:
            raise RuntimeError(
                f"固定测试负类包含 {leaked_target_count} 条目标标签 {target_label} 流"
            )
        test_x = np.concatenate([fixed_positive_x, fixed_negative_x], axis=0)
        test_y = np.concatenate(
            [np.ones(len(fixed_positive_x), dtype=np.int64), np.zeros(len(fixed_negative_x), dtype=np.int64)]
        )
        positive_test = fixed_positive_meta
        ids_test = fixed_negative_meta

    # 三种训练阶段从完全相同的真实正类/IDS-2017 基础训练集开始。
    train_x = np.concatenate([train_positive_x, train_ids_x], axis=0)
    train_y = np.concatenate(
        [np.ones(len(train_positive_x), dtype=np.int64), np.zeros(len(train_ids_x), dtype=np.int64)]
    )
    train_meta = pd.concat([positive_train, ids_train], ignore_index=True)
    augmentation_rows: list[dict] = []

    if args.augmentation == "smote":
        # SMOTE 只在 behavior 向量空间生成正类，负类和真实正类不变。
        added = smote_oversample(train_x, train_y, target_count=None, added_count=args.augmentation_count, random_state=args.random_state)
        train_x = np.concatenate([train_x, added], axis=0)
        train_y = np.concatenate([train_y, np.ones(len(added), dtype=np.int64)], axis=0)
        augmentation_rows = [{"flow_id": f"smote_{i}", "label": target_label, "source": "smote", "source_label": target_label, "binary_label": 1} for i in range(len(added))]
    elif args.augmentation == "generated":
        if not args.generated_input:
            raise ValueError("augmentation=generated 时必须提供 --generated_input")
        # PCAP 输入只在临时目录转换为 CSV，避免把转换中间文件留在结果目录。
        with tempfile.TemporaryDirectory(prefix="attack_generated_") as temp_dir:
            generated_csv = maybe_convert_input(Path(args.generated_input), Path(temp_dir) / "generated_csv")
            generated_flows = load_flows_from_csv(generated_csv, label_override=target_label)
            generated_x, generated_meta = vectorize_flows(generated_flows, min_packets=args.min_packets)
        if generated_meta.empty:
            raise RuntimeError("生成输入未提取到有效流")
        if len(generated_x) < args.augmentation_count:
            raise RuntimeError(
                f"生成输入只有 {len(generated_x)} 条有效流，少于要求的 "
                f"{args.augmentation_count} 条；请增加生成流数量或降低 --augmentation_count"
            )
        if len(generated_x) > args.augmentation_count:
            rng = np.random.default_rng(args.random_state)
            indices = np.sort(rng.choice(len(generated_x), size=args.augmentation_count, replace=False))
            generated_x = generated_x[indices]
            generated_meta = generated_meta.iloc[indices].copy()
        train_x = np.concatenate([train_x, generated_x], axis=0)
        train_y = np.concatenate([train_y, np.ones(len(generated_x), dtype=np.int64)], axis=0)
        generated_meta = generated_meta.reset_index(drop=True)
        generated_meta["source"] = "generated"
        generated_meta["source_label"] = target_label
        generated_meta["binary_label"] = 1
        augmentation_rows = generated_meta.to_dict("records")

    train_meta = pd.concat([train_meta, pd.DataFrame(augmentation_rows)], ignore_index=True)
    train_meta = add_metadata_defaults(train_meta, train_y)
    calib_meta = add_metadata_defaults(pd.concat([positive_calib, ids_calib], ignore_index=True), calib_y)
    test_meta = add_metadata_defaults(pd.concat([positive_test, ids_test], ignore_index=True), test_y)

    # 训练器内部会再次划分 train/validation；这里只打乱训练样本排列，避免顺序偏差。
    rng = np.random.default_rng(args.random_state)
    order = rng.permutation(len(train_y))
    train_x, train_y, train_meta = train_x[order], train_y[order], train_meta.iloc[order].reset_index(drop=True)

    np.save(output_dir / "train_X.npy", train_x.astype(np.float32))
    np.save(output_dir / "train_y.npy", train_y.astype(np.int64))
    np.save(output_dir / "calib_X.npy", calib_x.astype(np.float32))
    np.save(output_dir / "calib_y.npy", calib_y.astype(np.int64))
    np.save(output_dir / "test_X.npy", test_x.astype(np.float32))
    np.save(output_dir / "test_y.npy", test_y.astype(np.int64))
    train_meta.to_csv(output_dir / "train_metadata.csv", index=False)
    calib_meta.to_csv(output_dir / "calib_metadata.csv", index=False)
    test_meta.to_csv(output_dir / "test_metadata.csv", index=False)

    summary = {
        "target_label": target_label,
        "negative_excluded_label": target_label,
        "augmentation": args.augmentation,
        "positive_csv": str(Path(args.positive_csv)),
        "positive_source": args.positive_source,
        "ctu_csv": str(Path(args.positive_csv)) if args.positive_source == "CTU-13" else None,
        "ids_csv": str(Path(args.ids_csv)),
        "train_ratio": args.train_ratio,
        "calib_ratio": args.calib_ratio,
        "window_size": args.window_size,
        "max_real_positive": args.max_real_positive,
        "augmentation_count": 0 if args.augmentation == "none" else args.augmentation_count,
        "min_packets": args.min_packets,
        "max_ids_negative": args.max_ids_negative,
        "fixed_test_positive_csv": str(Path(args.fixed_test_positive_csv)) if args.fixed_test_positive_csv else None,
        "fixed_test_negative_csv": str(Path(args.fixed_test_negative_csv)) if args.fixed_test_negative_csv else None,
        "train_negative_ratio": args.train_negative_ratio,
        "train_count": int(len(train_y)),
        "train_positive_count": int(train_y.sum()),
        "train_negative_count": int((train_y == 0).sum()),
        "calib_count": int(len(calib_y)),
        "test_count": int(len(test_y)),
        "test_positive_count": int(test_y.sum()),
        "test_negative_count": int((test_y == 0).sum()),
        "test_negative_label_counts": {
            str(k): int(v) for k, v in ids_test["source_label"].value_counts(dropna=False).items()
        },
        "feature_dim": int(train_x.shape[1]),
        "ids_source_labels": {str(k): int(v) for k, v in ids_meta["source_label"].value_counts(dropna=False).items()},
    }
    with (output_dir / "dataset_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
