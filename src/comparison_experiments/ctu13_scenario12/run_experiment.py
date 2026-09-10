#!/usr/bin/env python3
"""Run none/SMOTE/generated comparison and keep one readable result CSV."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
BUILD = SCRIPT_DIR / "build_mixed_behavior_dataset.py"
TRAIN = PROJECT_ROOT / "src" / "classification" / "train_binary_behavior_classifier.py"
DETECT = PROJECT_ROOT / "comparison_experiments" / "efficiency" / "detect_precomputed.py"

if str(PROJECT_ROOT / "comparison_experiments" / "efficiency") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "comparison_experiments" / "efficiency"))
from benchmark import run_command


def parse_args() -> argparse.Namespace:
    """定义正式实验的输入、资源位置和三种方法的公共参数。"""
    parser = argparse.ArgumentParser(description="运行攻击正类的两种增强方法对比")
    parser.add_argument("--positive_csv", "--ctu_csv", dest="positive_csv", required=True)
    parser.add_argument("--ids_csv", required=True)
    parser.add_argument("--generated_input", required=True, help="流量重组生成的攻击 PCAP/CSV")
    parser.add_argument("--results_dir", default="comparison_results/ctu13_scenario12")
    parser.add_argument("--output_filename", default="ctu13_scenario12_method_comparison.csv")
    parser.add_argument("--experiment_name", default="ctu13_scenario12_botnet_vs_ids2017_all_labels")
    parser.add_argument("--target_label", default="Botnet")
    parser.add_argument("--target_description", default="CTU-13 scenario 12 P2P Botnet")
    parser.add_argument("--positive_source", default="CTU-13")
    parser.add_argument("--negative_source_description", default="IDS-2017 Wednesday all labels")
    parser.add_argument("--window_size", type=float, default=60.0)
    parser.add_argument("--train_negative_ratio", type=float)
    parser.add_argument("--work_dir", help="保留中间数据；默认使用临时目录并在结束时删除")
    parser.add_argument(
        "--efficiency_dir",
        help="可选：记录每个特征构造、训练和检测子命令的资源指标 JSON",
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--max_real_positive", type=int, default=3000)
    parser.add_argument("--augmentation_count", type=int, default=3000)
    parser.add_argument("--max_ids_negative", type=int, default=10000)
    parser.add_argument("--fixed_test_positive_csv", help="固定测试正类项目 CSV")
    parser.add_argument("--fixed_test_negative_csv", help="固定测试负类项目 CSV")
    parser.add_argument("--pretrain_epochs", type=int, default=10)
    parser.add_argument("--finetune_epochs", type=int, help="微调轮数；未指定时复用 --epochs")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--pca_dim", type=int, default=128)
    parser.add_argument("--random_state", type=int, default=42)
    parser.add_argument(
        "--skip-smote",
        action="store_true",
        help="只运行共同预训练和 generated 微调，不构造 SMOTE 对照组",
    )
    return parser.parse_args()


def run(command: list[str], cwd: Path) -> None:
    """执行子步骤；任一步骤失败都立即终止，避免输出不完整比较表。"""
    subprocess.run(command, cwd=cwd, check=True)


def run_measured(
    command: list[str], cwd: Path, output: Path, method: str, phase: str
) -> None:
    """测量一个子命令并保存指标；失败时仍先写出失败记录再抛错。"""
    measurement = run_command(
        command=command,
        cwd=cwd,
        sample_interval=0.2,
        timeout_seconds=None,
        environment=os.environ.copy(),
    )
    measurement.update({"method": method, "phase": phase, "command": shlex.join(command)})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(measurement, ensure_ascii=False, indent=2), encoding="utf-8")
    if measurement["status"] != "success":
        raise RuntimeError(
            f"效率测量命令失败（{measurement.get('exit_code')}）：{shlex.join(command)}"
        )


def confusion_fields(metrics: dict) -> dict[str, int]:
    """将 [[TN, FP], [FN, TP]] 展开为 CSV 中的四个独立字段。"""
    matrix = metrics.get("confusion_matrix")
    if not isinstance(matrix, list) or len(matrix) != 2 or any(len(row) != 2 for row in matrix):
        raise ValueError("metrics.json 中的 confusion_matrix 不是 2x2 矩阵")
    return {
        "TN": int(matrix[0][0]),
        "FP": int(matrix[0][1]),
        "FN": int(matrix[1][0]),
        "TP": int(matrix[1][1]),
    }


def signed_percent(value: float) -> str:
    """格式化相对变化，始终带正负号并保留两位小数。"""
    return f"{value:+.2f}%"


def main() -> None:
    """依次运行共同预训练、SMOTE 微调和重组流量微调，并汇总最终 CSV。"""
    args = parse_args()
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    owned_work = args.work_dir is None
    if Path(args.output_filename).name != args.output_filename:
        raise ValueError("--output_filename 只能是文件名，不能包含目录")
    work_dir = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="attack_compare_work_"))
    work_dir.mkdir(parents=True, exist_ok=True)
    efficiency_dir = Path(args.efficiency_dir) if args.efficiency_dir else None
    if efficiency_dir is not None:
        efficiency_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    try:
        # 先训练共同基础模型，再从同一个 checkpoint 微调两种增强数据集。
        pretrain_model = None
        finetune_epochs = args.finetune_epochs if args.finetune_epochs is not None else args.epochs
        efficiency_index = 0
        methods = ["none", "generated"] if args.skip_smote else ["none", "smote", "generated"]
        for method in methods:
            dataset_dir = work_dir / method / "dataset"
            result_dir = work_dir / method / "result"
            build_cmd = [
                args.python, str(BUILD),
                "--positive_csv", args.positive_csv,
                "--ids_csv", args.ids_csv,
                "--output_dir", str(dataset_dir),
                "--augmentation", method,
                "--max_real_positive", str(args.max_real_positive),
                "--augmentation_count", str(args.augmentation_count),
                "--target_label", args.target_label,
                "--positive_source", args.positive_source,
                "--window_size", str(args.window_size),
                "--random_state", str(args.random_state),
            ]
            if args.fixed_test_positive_csv:
                build_cmd += ["--fixed_test_positive_csv", args.fixed_test_positive_csv]
            if args.fixed_test_negative_csv:
                build_cmd += ["--fixed_test_negative_csv", args.fixed_test_negative_csv]
            if args.max_ids_negative is not None:
                build_cmd += ["--max_ids_negative", str(args.max_ids_negative)]
            if args.train_negative_ratio is not None:
                build_cmd += ["--train_negative_ratio", str(args.train_negative_ratio)]
            if method == "generated":
                build_cmd += ["--generated_input", args.generated_input]
            if efficiency_dir is None:
                run(build_cmd, PROJECT_ROOT)
            else:
                efficiency_index += 1
                run_measured(
                    build_cmd,
                    PROJECT_ROOT,
                    efficiency_dir / f"{efficiency_index:03d}_{method}_feature_extraction.json",
                    "shared_pretrain" if method == "none" else method,
                    "feature_extraction",
                )

            train_cmd = [
                args.python, str(TRAIN),
                "--dataset_dir", str(dataset_dir),
                "--output_dir", str(result_dir),
                "--epochs", str(args.pretrain_epochs if method == "none" else finetune_epochs),
                "--pca_dim", str(args.pca_dim),
            ]
            if method != "none":
                if pretrain_model is None:
                    raise RuntimeError("增强方法训练前没有得到预训练模型")
                train_cmd += ["--init_model", str(pretrain_model)]
            if efficiency_dir is not None:
                # 将检测拆成独立命令，才能分别统计训练和推理资源。
                train_cmd += ["--skip_test_evaluation"]
                efficiency_index += 1
                run_measured(
                    train_cmd,
                    PROJECT_ROOT,
                    efficiency_dir / f"{efficiency_index:03d}_{method}_model_training.json",
                    "shared_pretrain" if method == "none" else method,
                    "model_training",
                )
                detection_dir = result_dir / "detection"
                detect_cmd = [
                    args.python,
                    str(DETECT),
                    "--model_path", str(result_dir / "model.pt"),
                    "--features", str(dataset_dir / "test_X.npy"),
                    "--labels", str(dataset_dir / "test_y.npy"),
                    "--metadata", str(dataset_dir / "test_metadata.csv"),
                    "--output_dir", str(detection_dir),
                ]
                efficiency_index += 1
                run_measured(
                    detect_cmd,
                    PROJECT_ROOT,
                    efficiency_dir / f"{efficiency_index:03d}_{method}_model_detection.json",
                    "shared_pretrain" if method == "none" else method,
                    "model_detection",
                )
                metrics_path = detection_dir / "metrics.json"
                predictions_path = detection_dir / "predictions.csv"
            else:
                run(train_cmd, PROJECT_ROOT)
                metrics_path = result_dir / "metrics.json"
                predictions_path = result_dir / "test_predictions.csv"

            if method == "none":
                pretrain_model = result_dir / "model.pt"

            with metrics_path.open("r", encoding="utf-8") as handle:
                metrics = json.load(handle)
            predictions = pd.read_csv(predictions_path)
            summary = json.loads((dataset_dir / "dataset_summary.json").read_text(encoding="utf-8"))
            y_true = predictions["y_true"].to_numpy()
            y_pred = predictions["y_pred"].to_numpy()
            row = {
                "experiment": args.experiment_name,
                "method": method,
                "training_stage": "pretrain" if method == "none" else "finetune",
                "pretrain_epochs": args.pretrain_epochs,
                "finetune_epochs": finetune_epochs,
                "initialized_from_pretrain": method != "none",
                "target": args.target_description,
                "negative_source": args.negative_source_description,
                "train_count": summary["train_count"],
                "train_positive_count": summary["train_positive_count"],
                "train_negative_count": summary["train_negative_count"],
                "test_count": summary["test_count"],
                "test_positive_count": summary["test_positive_count"],
                "test_negative_count": summary["test_negative_count"],
                "augmentation_count": summary.get("augmentation_count", 0) if method != "none" else 0,
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            }
            row.update(confusion_fields(metrics))
            # none 同时作为共同预训练 checkpoint 和“无增强直接测试”的基线结果，
            # 因此也写入最终 CSV，便于量化增强带来的变化。
            rows.append(row)

        generated_row = next(row for row in rows if row["method"] == "generated")

        def make_change_row(baseline_row: dict, baseline_method: str) -> dict:
            """构造 generated 相对指定基线的百分比变化行。"""
            change_row = {
                "experiment": generated_row["experiment"],
                "method": f"generated_vs_{baseline_method}",
                "target": generated_row["target"],
                "negative_source": generated_row["negative_source"],
                "accuracy": "",
                "precision": "",
                "recall": "",
                "f1": "",
                "TN": "",
                "FP": "",
                "FN": "",
                "TP": "",
                "augmentation_count": "",
            }
            for metric in ("accuracy", "precision", "recall", "f1"):
                baseline_value = float(baseline_row[metric])
                change = (
                    (float(generated_row[metric]) - baseline_value) / abs(baseline_value) * 100.0
                    if baseline_value
                    else 0.0
                )
                change_row[metric] = signed_percent(change)
            return change_row

        # 以无增强预训练模型作为新增基线，记录 generated 的提升或下降比例。
        none_row = next(row for row in rows if row["method"] == "none")
        rows.append(make_change_row(none_row, "none"))

        # 正式方法对比包含 SMOTE 时，继续记录 generated 相对 SMOTE 的变化。
        if not args.skip_smote:
            smote_row = next(row for row in rows if row["method"] == "smote")
            rows.append(make_change_row(smote_row, "smote"))

        # 只保留方法、数据规模、核心指标、四格混淆矩阵和新增数量。
        preferred_columns = [
            "experiment", "method", "target", "negative_source",
            "train_count", "train_positive_count", "train_negative_count",
            "test_count", "test_positive_count", "test_negative_count",
            "accuracy", "precision", "recall", "f1", "TN", "FP", "FN", "TP",
            "augmentation_count",
        ]
        columns = preferred_columns
        output_csv = results_dir / args.output_filename
        output_rows = [{key: row.get(key, "") for key in columns} for row in rows]
        with output_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(output_rows)
        print(f"最终结果: {output_csv}")
    finally:
        if owned_work:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
