#!/usr/bin/env python3
"""运行 v3 设置的十轮长期漂移对照实验。

none 只训练一次并固定；SMOTE 只从预训练 checkpoint 微调一次并固定；
generated 在每个轮次重新执行“质心预测 -> 余弦检索 -> 流量重构 -> 微调”，
随后只在该轮固定测试窗口上检测。这样逐轮变化反映的是测试窗口漂移和
对应方法的适应能力，而不是重复训练造成的随机波动。
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
REPOSITORY_ROOT = PROJECT_ROOT.parent
DATA_ROOT = Path(os.environ.get("BAC_TL_DATA_ROOT", REPOSITORY_ROOT / "data/raw"))
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from classification.behavior_vectorizer import load_flows_from_csv, vectorize_flows

PYTHON = sys.executable
CTU_PCAP_DEFAULT = DATA_ROOT / "pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"
IDS_CSV_DEFAULT = DATA_ROOT / "csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
BASE_DATASET_DEFAULT = PROJECT_ROOT / "comparison_datasets/ctu13_scenario12/concept_drift_many_windows_v2"
DATASET_DEFAULT = BASE_DATASET_DEFAULT
RESULTS_DEFAULT = PROJECT_ROOT / "comparison_results/ctu13_scenario12/long_term_drift_concept_drift_many_windows_v2_v3"
BUILD = PROJECT_ROOT / "comparison_experiments/ctu13_scenario12/build_mixed_behavior_dataset.py"
TRAIN = PROJECT_ROOT / "src/classification/train_binary_behavior_classifier.py"
DETECT = PROJECT_ROOT / "comparison_experiments/efficiency/detect_precomputed.py"
CENTROID_EXTRACT = PROJECT_ROOT / "src/drift_prediction/extract_window_centroids.py"
CENTROID_DATASET = PROJECT_ROOT / "src/drift_prediction/build_centroid_dataset.py"
CENTROID_TRAIN = PROJECT_ROOT / "src/drift_prediction/train_centroid_transformer.py"
GENERATOR = PROJECT_ROOT / "src/drift_prediction/generate_single_step_from_centroid_prediction.py"


def parse_args() -> argparse.Namespace:
    """定义长期实验输入和与 v3 一致的分类参数。"""
    parser = argparse.ArgumentParser(description="运行 v3 固定模型/逐轮生成长期漂移实验")
    parser.add_argument("--ctu-pcap", default=str(CTU_PCAP_DEFAULT))
    parser.add_argument("--ids-csv", default=str(IDS_CSV_DEFAULT))
    parser.add_argument("--base-dataset-dir", default=str(BASE_DATASET_DEFAULT))
    parser.add_argument("--dataset-dir", default=str(DATASET_DEFAULT))
    parser.add_argument("--results-dir", default=str(RESULTS_DEFAULT))
    parser.add_argument("--train-horizons", type=int, default=12, help="数据集中用于 generated 训练的伪未来窗口数")
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--augmentation-count", type=int, default=3000)
    parser.add_argument("--max-real-positive", type=int, default=3000)
    parser.add_argument("--max-ids-negative", type=int, default=10000)
    parser.add_argument("--centroid-epochs", type=int, default=5)
    parser.add_argument("--pretrain-epochs", type=int, default=10)
    parser.add_argument("--finetune-epochs", type=int, default=10)
    parser.add_argument("--pca-dim", type=int, default=128)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--rebuild-dataset", action="store_true")
    return parser.parse_args()


def run(command: list[str]) -> None:
    """在项目根目录执行命令。"""
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def copy_or_extend_dataset(args: argparse.Namespace) -> Path:
    """校验已构造的连续伪未来窗口，不重新生成或循环复制窗口。"""
    target = Path(args.dataset_dir).resolve()
    required = [target / "future_window_metadata.csv", target / "predicted_centroids.npy"] + [
        target / f"future_window_{args.train_horizons + index:02d}_generated.csv" for index in range(1, args.rounds + 1)
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("连续伪未来测试数据集缺少: " + ", ".join(missing))
    return target


def combine_csvs(paths: list[Path], output: Path, label: str = "Botnet") -> int:
    """合并完整流 CSV，给生成流补充统一标签并重新偏移流编号。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    writer = None
    offset = 0
    flow_count = 0
    with output.open("w", encoding="utf-8", newline="") as out:
        for path in paths:
            with path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                fields = list(reader.fieldnames or [])
                if "label" not in fields:
                    fields.append("label")
                if writer is None:
                    writer = csv.DictWriter(out, fieldnames=fields)
                    writer.writeheader()
                ids: set[int] = set()
                for row in reader:
                    local = int(row["flow_id"])
                    ids.add(local)
                    row["flow_id"] = str(local + offset)
                    row["label"] = label
                    writer.writerow({field: row.get(field, "") for field in writer.fieldnames})
                if ids:
                    offset += max(ids) + 1
                    flow_count += len(ids)
    return flow_count


def valid_flow_rows(path: Path) -> list[tuple[str, str]]:
    """返回 behavior 有效流的 ID 和原始标签。"""
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("layer") != "behavior":
                continue
            try:
                packets = int(json.loads(row.get("encoding_header") or "{}").get("packet_count", 0))
            except (TypeError, ValueError, json.JSONDecodeError):
                packets = 0
            if packets >= 2:
                rows.append((str(row["flow_id"]), row.get("label", "Unknown")))
    return rows


def select_stratified_negative_pool(
    pool: Path,
    desired: int,
    seed: int,
    exclude_label: str | None = "Botnet",
    excluded_ids: set[str] | None = None,
) -> set[str]:
    """按 v3 原始标签比例抽取负类，并排除目标标签和训练流。"""
    rows = [
        (flow_id, label)
        for flow_id, label in valid_flow_rows(pool)
        if (exclude_label is None or label != exclude_label)
        and (excluded_ids is None or flow_id not in excluded_ids)
    ]
    if desired > len(rows):
        raise RuntimeError(f"固定负类池只有 {len(rows)} 条有效流，无法提供 {desired} 条")
    groups: dict[str, list[str]] = {}
    for flow_id, label in rows:
        groups.setdefault(label, []).append(flow_id)
    rng = np.random.default_rng(seed)
    labels = sorted(groups)
    quotas = {label: int(round(desired * len(groups[label]) / len(rows))) for label in labels}
    while sum(quotas.values()) < desired:
        label = max(labels, key=lambda item: len(groups[item]) - quotas[item])
        quotas[label] += 1
    while sum(quotas.values()) > desired:
        label = max(labels, key=lambda item: quotas[item])
        quotas[label] -= 1
    chosen: list[str] = []
    for label in labels:
        chosen.extend(rng.choice(np.asarray(groups[label]), size=quotas[label], replace=False).tolist())
    return set(chosen)


def prepare_test_vectors(positive: Path, negative: Path, out_dir: Path) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """将本轮固定正负 CSV 转换为检测器所需的向量和标签。"""
    pos_x, pos_meta = vectorize_flows(load_flows_from_csv(positive, label_override="Botnet"), min_packets=2)
    neg_x, neg_meta = vectorize_flows(load_flows_from_csv(negative), min_packets=2)
    if pos_x.size == 0 or neg_x.size == 0:
        raise RuntimeError("本轮测试集没有有效正类或负类")
    pos_meta = pos_meta.reset_index(drop=True)
    neg_meta = neg_meta.reset_index(drop=True)
    pos_meta["source"] = "pseudo-future Botnet"
    neg_meta["source"] = "IDS-2017 stratified"
    meta = pd.concat([pos_meta, neg_meta], ignore_index=True)
    x = np.concatenate([pos_x, neg_x]).astype(np.float32)
    y = np.concatenate([np.ones(len(pos_x), dtype=np.int64), np.zeros(len(neg_x), dtype=np.int64)])
    out_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_dir / "X.npy", x)
    np.save(out_dir / "y.npy", y)
    meta.to_csv(out_dir / "metadata.csv", index=False)
    return x, y, meta


def detect(model: Path, test_dir: Path, output: Path) -> dict:
    """调用预计算向量检测器并读取指标。"""
    run([PYTHON, str(DETECT), "--model_path", str(model), "--features", str(test_dir / "X.npy"), "--labels", str(test_dir / "y.npy"), "--metadata", str(test_dir / "metadata.csv"), "--output_dir", str(output)])
    return json.loads((output / "metrics.json").read_text(encoding="utf-8"))


def metric_row(round_index: int, method: str, metrics: dict, train_count: int, positive_count: int, augmentation_count: int) -> dict:
    """将检测结果整理成逐轮表格行。"""
    matrix = metrics["confusion_matrix"]
    return {
        "round": round_index,
        "method": method,
        "train_count": train_count,
        "train_positive_count": 6000 if augmentation_count else 3000,
        "train_negative_count": 6000,
        "test_count": metrics["sample_count"],
        "test_positive_count": positive_count,
        "test_negative_count": metrics["negative_count"],
        "augmentation_count": augmentation_count,
        "threshold": metrics["threshold"],
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "TN": matrix[0][0], "FP": matrix[0][1], "FN": matrix[1][0], "TP": matrix[1][1],
    }


def main() -> None:
    """准备固定模型并逐轮执行三种检测轨迹。"""
    args = parse_args()
    if args.rounds <= 0 or args.augmentation_count <= 0:
        raise ValueError("rounds 和 augmentation-count 必须大于 0")
    dataset = copy_or_extend_dataset(args)
    ctu_pcap, ids_csv, results = Path(args.ctu_pcap).resolve(), Path(args.ids_csv).resolve(), Path(args.results_dir).resolve()
    results.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="ctu13_v3_fixed_long_term_"))
    rows: list[dict] = []
    try:
        input_dir = temp / "input"
        input_dir.mkdir()
        raw_csv, labeled_csv, split_dir = input_dir / "ctu13.csv", input_dir / "ctu13_labeled.csv", input_dir / "time_split"
        run([PYTHON, str(PROJECT_ROOT / "src/UnifiedPcapToCSV.py"), "-i", str(ctu_pcap), "-o", str(raw_csv)])
        run([PYTHON, str(PROJECT_ROOT / "comparison_experiments/ctu13_scenario12/annotate_ctu13_csv.py"), "--input_csv", str(raw_csv), "--output_csv", str(labeled_csv), "--scenario", "12", "--family", "Unknown"])
        run([PYTHON, str(PROJECT_ROOT / "comparison_experiments/ctu13_scenario12/split_ctu_csv_by_time.py"), "--input_csv", str(labeled_csv), "--output_dir", str(split_dir), "--output_prefix", "ctu13", "--train_ratio", "0.6", "--calib_ratio", "0.2", "--macro_window", "60", "--min_packets", "2"])
        train_csv = split_dir / "ctu13_train.csv"
        centroid_dir, centroid_data, centroid_model = temp / "centroid_windows", temp / "centroid_dataset", temp / "centroid_model"
        run([PYTHON, str(CENTROID_EXTRACT), "--input_csv", str(train_csv), "--output_dir", str(centroid_dir), "--macro_window", "60", "--slice_window", "1", "--max_slices", "60", "--min_packets", "2"])
        run([PYTHON, str(CENTROID_DATASET), "--centroid_dir", str(centroid_dir), "--output_dir", str(centroid_data), "--history_mode", "expanding", "--exclude_last_per_label"])
        run([PYTHON, str(CENTROID_TRAIN), "--dataset_dir", str(centroid_data), "--output_dir", str(centroid_model), "--epochs", str(args.centroid_epochs)])
        # 连续测试窗口和预测质心已经由概念漂移数据集预先固定；分类阶段
        # 不重新构造测试 PCAP，generated 训练仍沿用 v3 的单轮重构流程。
        predicted_centroids = np.load(dataset / "predicted_centroids.npy").astype(np.float32)
        if predicted_centroids.shape[0] < args.rounds:
            raise RuntimeError(
                f"预计算质心只有 {predicted_centroids.shape[0]} 个，无法支持 {args.rounds} 轮 generated 微调"
            )

        # 预训练模型和一次性 SMOTE 模型在所有轮次复用。
        pretrain_data, smote_data = temp / "pretrain_data", temp / "smote_data"
        common = ["--positive_csv", str(labeled_csv), "--ids_csv", str(ids_csv), "--target_label", "Botnet", "--positive_source", "CTU-13", "--window_size", "60", "--max_real_positive", str(args.max_real_positive), "--max_ids_negative", str(args.max_ids_negative), "--train_negative_ratio", "2.0", "--random_state", str(args.random_state)]
        run([PYTHON, str(BUILD), *common, "--output_dir", str(pretrain_data), "--augmentation", "none"])
        pretrain_result = temp / "pretrain_result"
        run([PYTHON, str(TRAIN), "--dataset_dir", str(pretrain_data), "--output_dir", str(pretrain_result), "--epochs", str(args.pretrain_epochs), "--pca_dim", str(args.pca_dim), "--skip_test_evaluation"])
        pretrained_model = pretrain_result / "model.pt"
        run([PYTHON, str(BUILD), *common, "--output_dir", str(smote_data), "--augmentation", "smote", "--augmentation_count", str(args.augmentation_count)])
        smote_result = temp / "smote_result"
        run([PYTHON, str(TRAIN), "--dataset_dir", str(smote_data), "--output_dir", str(smote_result), "--epochs", str(args.finetune_epochs), "--pca_dim", str(args.pca_dim), "--init_model", str(pretrained_model), "--skip_test_evaluation"])
        smote_model = smote_result / "model.pt"

        # 最新连续窗口数据集只固定了伪未来正类；测试负类沿用 v3 的
        # IDS-2017 原始标签分层策略，从原始背景池中抽取并在各轮复用。
        test_negative_count = 250
        pretrain_metadata = pd.read_csv(pretrain_data / "train_metadata.csv")
        train_negative_ids = set(
            pretrain_metadata.loc[pretrain_metadata["y"].astype(int) == 0, "flow_id"].astype(str)
        )
        selected_negative_ids = select_stratified_negative_pool(
            ids_csv,
            test_negative_count,
            args.random_state,
            exclude_label="Botnet",
            excluded_ids=train_negative_ids,
        )
        fixed_negative_csv = temp / "fixed_test_negative.csv"
        with ids_csv.open("r", encoding="utf-8", newline="") as source, fixed_negative_csv.open("w", encoding="utf-8", newline="") as target:
            reader = csv.DictReader(source)
            fields = list(reader.fieldnames or [])
            writer = csv.DictWriter(target, fieldnames=fields)
            writer.writeheader()
            for row in reader:
                if str(row.get("flow_id")) in selected_negative_ids:
                    writer.writerow(row)

        for round_index in range(1, args.rounds + 1):
            generated_test_csv = dataset / f"future_window_{args.train_horizons + round_index:02d}_generated.csv"
            positive_csv = generated_test_csv
            negative_csv = fixed_negative_csv
            positive_count = len(valid_flow_rows(positive_csv))
            test_dir = temp / f"round_{round_index:02d}_test"
            _, _, _ = prepare_test_vectors(positive_csv, negative_csv, test_dir)
            none_metrics = detect(pretrained_model, test_dir, temp / f"round_{round_index:02d}_none")
            smote_metrics = detect(smote_model, test_dir, temp / f"round_{round_index:02d}_smote")
            rows.append(metric_row(round_index, "none", none_metrics, 9000, positive_count, 0))
            rows.append(metric_row(round_index, "smote", smote_metrics, 12000, positive_count, args.augmentation_count))

            # 本轮 generated：使用数据集预先固定的本轮预测质心，按 v3
            # 单步流程重构增强流，再从固定预训练模型微调。
            generated_dir = temp / f"round_{round_index:02d}_generation"
            round_centroid = generated_dir / "predicted_centroid.npy"
            generated_dir.mkdir(parents=True, exist_ok=True)
            np.save(round_centroid, predicted_centroids[round_index - 1])
            run([PYTHON, str(GENERATOR), "--input_csv", str(train_csv), "--centroid_dir", str(centroid_dir), "--model_path", str(centroid_model / "model.pt"), "--output_dir", str(generated_dir), "--label", "Botnet", "--num_flows", str(args.augmentation_count), "--seed_scope", "all_history", "--min_packets", "2", "--macro_window", "60", "--slice_window", "1", "--target_profile_mode", "nearest_historical_flow", "--nearest_metric", "cosine", "--intra_slice_mode", "even", "--size_noise_sigma", "0.1", "--time_jitter_ratio", "0.05", "--time_jitter_cap", "0.05", "--random_state", str(args.random_state + round_index), "--predicted-centroid", str(round_centroid)])
            generated_inputs = sorted(generated_dir.glob("generated_single_step_Botnet_*flows.csv"))
            if not generated_inputs:
                raise RuntimeError(f"第 {round_index} 轮没有得到 generated 训练 CSV")
            generated_data = temp / f"round_{round_index:02d}_generated_data"
            run([PYTHON, str(BUILD), *common, "--output_dir", str(generated_data), "--augmentation", "generated", "--generated_input", str(generated_inputs[-1]), "--augmentation_count", str(args.augmentation_count)])
            generated_result = temp / f"round_{round_index:02d}_generated_result"
            run([PYTHON, str(TRAIN), "--dataset_dir", str(generated_data), "--output_dir", str(generated_result), "--epochs", str(args.finetune_epochs), "--pca_dim", str(args.pca_dim), "--init_model", str(pretrained_model), "--skip_test_evaluation"])
            generated_metrics = detect(generated_result / "model.pt", test_dir, temp / f"round_{round_index:02d}_generated")
            rows.append(metric_row(round_index, "generated", generated_metrics, 12000, positive_count, args.augmentation_count))

        result = pd.DataFrame(rows)
        result["_method_order"] = result["method"].map({"none": 0, "smote": 1, "generated": 2}).fillna(99)
        result = result.sort_values(["round", "_method_order"], kind="stable").drop(columns="_method_order").reset_index(drop=True)
        result["single_round_decay"] = ""
        result["cumulative_decay"] = ""
        for method, group in result.groupby("method", sort=False):
            indices = group.index.to_list()
            values = group["f1"].astype(float).to_numpy()
            first = values[0]
            for index, row_index in enumerate(indices):
                if index > 0 and values[index - 1] != 0:
                    result.loc[row_index, "single_round_decay"] = f"{(values[index] - values[index - 1]) / abs(values[index - 1]) * 100:+.2f}%"
                if first != 0:
                    result.loc[row_index, "cumulative_decay"] = f"{(values[index] - first) / abs(first) * 100:+.2f}%"
        output = results / "ctu13_long_term_v3_10rounds.csv"
        result.to_csv(output, index=False)
        manifest = {"dataset_dir": str(dataset), "rounds": args.rounds, "methods": {"none": "one fixed pretraining model", "smote": "one fixed finetuned model", "generated": "per-round precomputed-centroid reconstruction and finetuning from the fixed pretraining model"}, "settings": {"macro_window": 60.0, "slice_window": 1.0, "nearest_metric": "cosine", "intra_slice_mode": "even", "negative_mode": "stratified", "test_positive_source": "precomputed future windows", "test_negative_count": 250, "train_real_positive": args.max_real_positive, "train_negative": 6000, "augmentation_count": args.augmentation_count, "pca_dim": args.pca_dim, "pretrain_epochs": args.pretrain_epochs, "finetune_epochs": args.finetune_epochs, "decay_columns": {"single_round_decay": "(current F1 - previous F1) / abs(previous F1) * 100%", "cumulative_decay": "(current F1 - round-1 F1) / abs(round-1 F1) * 100%"}, "change_sign": "negative means performance decrease; positive means performance increase"}}
        (results / "experiment_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结果：{output}")
    finally:
        shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    main()
