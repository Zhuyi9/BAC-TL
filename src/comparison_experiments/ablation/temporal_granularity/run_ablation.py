#!/usr/bin/env python3
"""运行 CTU-13 场景 12 的时序粒度单因素消融实验。

每一组只改变流内切片粒度，``max_slices`` 固定为 60。模型预测下一窗口质心后，
从历史训练流中检索最接近质心的一条真实流，并以其逐包曲线重塑种子流。
中间工作目录在汇总后删除，最终只写一个可直接阅读的 CSV。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
RUN_FULL = PROJECT_ROOT / "comparison_experiments/ctu13_scenario12/run_full_experiment.sh"
COSINE = SCRIPT_DIR / "compute_sequence_cosine.py"

DEFAULT_GRANULARITIES = [
    0.001,
    0.01,
    0.1,
    0.2,
    0.5,
    1.0,
    2.0,
    3.0,
    4.0,
    5.0,
    6.0,
    8.0,
    10.0,
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行 CTU-13 时序粒度消融实验")
    parser.add_argument("--ctu-pcap", required=True)
    parser.add_argument("--ids-csv", required=True)
    parser.add_argument(
        "--results-dir",
        default="comparison_results/ablation/temporal_granularity",
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--granularities", nargs="+", type=float, default=DEFAULT_GRANULARITIES)
    parser.add_argument("--max-real-positive", type=int, default=3000)
    parser.add_argument("--max-ids-negative", type=int, default=10000)
    parser.add_argument("--centroid-epochs", type=int, default=5)
    parser.add_argument("--pretrain-epochs", type=int, default=10)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--pca-dim", type=int, default=128)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--intra-slice-mode",
        choices=["even", "random", "jitter"],
        default="even",
    )
    parser.add_argument("--size-noise-sigma", type=float, default=0.10)
    parser.add_argument("--time-jitter-ratio", type=float, default=0.05)
    parser.add_argument("--time-jitter-cap", type=float, default=0.05)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if any(value <= 0 for value in args.granularities):
        raise ValueError("所有切片粒度必须大于 0")
    if min(args.size_noise_sigma, args.time_jitter_ratio, args.time_jitter_cap) < 0:
        raise ValueError("片内扰动参数不能为负数")
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    root_work = Path(tempfile.mkdtemp(prefix="temporal_granularity_"))
    rows: list[dict] = []
    try:
        for index, granularity in enumerate(args.granularities, start=1):
            tag = f"{granularity:g}s".replace(".", "p")
            run_work = root_work / f"run_{index:02d}_{tag}"
            run_work.mkdir(parents=True)
            run_results = run_work / "results"
            command = [
                "bash", str(RUN_FULL),
                "--ctu-pcap", args.ctu_pcap,
                "--ids-csv", args.ids_csv,
                "--results-dir", str(run_results),
                "--work-dir", str(run_work / "pipeline"),
                "--keep-work",
                "--skip-smote",
                "--generation-target-mode", "nearest_historical_flow",
                "--intra-slice-mode", args.intra_slice_mode,
                "--size-noise-sigma", str(args.size_noise_sigma),
                "--time-jitter-ratio", str(args.time_jitter_ratio),
                "--time-jitter-cap", str(args.time_jitter_cap),
                "--slice-window", str(granularity),
                "--max-real-positive", str(args.max_real_positive),
                "--max-ids-negative", str(args.max_ids_negative),
                "--centroid-epochs", str(args.centroid_epochs),
                "--pretrain-epochs", str(args.pretrain_epochs),
                "--epochs", str(args.epochs),
                "--pca-dim", str(args.pca_dim),
                "--random-state", str(args.random_state),
            ]
            print(f"[{index}/{len(args.granularities)}] slice_window={granularity}s", flush=True)
            pipeline_env = os.environ.copy()
            pipeline_env["PYTHON"] = args.python
            subprocess.run(command, cwd=PROJECT_ROOT, check=True, env=pipeline_env)

            pipeline = run_work / "pipeline"
            generated_paths = sorted((pipeline / "generated").glob("generated_single_step_Botnet_*flows.csv"))
            if not generated_paths:
                raise FileNotFoundError("生成阶段没有合并 CSV")
            target_curve = pipeline / "generated" / "target_packet_curve.json"
            if not target_curve.exists():
                raise FileNotFoundError("生成阶段没有输出历史目标流逐包曲线")
            cosine = json.loads(
                subprocess.check_output(
                    [
                        args.python, str(COSINE),
                        "--generated-csv", str(generated_paths[-1]),
                        "--target-curve", str(target_curve),
                    ],
                    cwd=PROJECT_ROOT,
                    text=True,
                )
            )
            comparison = pd.read_csv(run_results / "ctu13_scenario12_method_comparison.csv")
            method_row = comparison[comparison["method"] == "generated"]
            if method_row.empty:
                raise RuntimeError("结果 CSV 中缺少方法 generated")
            values = method_row.iloc[0].to_dict()
            row = {
                "intra_slice_mode": args.intra_slice_mode,
                "slice_window_s": granularity,
                "max_slices": 60,
                "effective_horizon_s": granularity * 60.0,
                "train_count": values.get("train_count", ""),
                "test_count": values.get("test_count", ""),
                "test_positive_count": values.get("test_positive_count", ""),
                "test_negative_count": values.get("test_negative_count", ""),
                "used_generated_count": values.get("augmentation_count", ""),
                "prediction_target_distance": cosine["nearest_flow_distance"],
                "packet_length_cosine": cosine["packet_length_cosine"],
                "packet_curve_cosine": cosine["packet_curve_cosine"],
            }
            for key in ("accuracy", "precision", "recall", "f1", "TN", "FP", "FN", "TP"):
                row[key] = values.get(key, "")
            rows.append(row)
    finally:
        shutil.rmtree(root_work, ignore_errors=True)

    columns = [
        "intra_slice_mode", "slice_window_s", "max_slices", "effective_horizon_s",
        "train_count", "test_count", "test_positive_count", "test_negative_count",
        "used_generated_count", "prediction_target_distance",
        "packet_length_cosine", "packet_curve_cosine",
        "accuracy", "precision", "recall", "f1", "TN", "FP", "FN", "TP",
    ]
    output = results_dir / "temporal_granularity_comparison.csv"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in columns} for row in rows)
    print(f"最终结果: {output}")


if __name__ == "__main__":
    main()
