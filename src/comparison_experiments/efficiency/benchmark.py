#!/usr/bin/env python3
"""Run reproducible command-level efficiency benchmarks.

The runner intentionally uses only the Python standard library. On POSIX systems,
``wait4`` provides process CPU time and peak RSS, while periodic ``ps`` snapshots
include descendant processes in the sampled CPU and memory measurements.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any


METRIC_FIELDS = [
    "wall_time_s",
    "user_cpu_time_s",
    "system_cpu_time_s",
    "total_cpu_time_s",
    "avg_cpu_core_utilization_pct",
    "sampled_avg_cpu_pct",
    "sampled_peak_cpu_pct",
    "avg_rss_mb",
    "peak_rss_mb",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure time, CPU, memory, and output size for comparison experiments."
    )
    parser.add_argument("--config", required=True, help="JSON benchmark configuration.")
    parser.add_argument(
        "--results-root",
        default="comparison_results/efficiency",
        help="Root directory for efficiency results.",
    )
    parser.add_argument("--repetitions", type=int, help="Override configured repetitions.")
    parser.add_argument(
        "--warmup-repetitions",
        type=int,
        help="Override configured warmup repetitions.",
    )
    return parser.parse_args()


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config.get("methods"), list) or not config["methods"]:
        raise ValueError("config.methods must be a non-empty list")
    return config


def safe_id(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_" else "_" for char in value)
    cleaned = cleaned.strip("_")
    if not cleaned:
        raise ValueError(f"Invalid empty identifier derived from {value!r}")
    return cleaned


def expand_text(value: str, context: dict[str, Any]) -> str:
    result = value
    for _ in range(10):
        previous = result
        result = result.format_map({key: str(item) for key, item in context.items()})
        if result == previous:
            break
    return result


def expand_command(command: list[Any], context: dict[str, Any]) -> list[str]:
    if not isinstance(command, list) or not command:
        raise ValueError("Every command must be a non-empty JSON array")
    return [expand_text(str(part), context) for part in command]


def process_tree_snapshot(root_pid: int) -> tuple[float, float] | None:
    """Return summed process-tree CPU percent and RSS KB from one ps snapshot."""
    try:
        completed = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,%cpu=,rss="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    rows: dict[int, tuple[int, float, float]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            rows[pid] = (ppid, float(parts[2]), float(parts[3]))
        except ValueError:
            continue

    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _, _) in rows.items():
            if ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True

    visible = [rows[pid] for pid in descendants if pid in rows]
    if not visible:
        return None
    return sum(row[1] for row in visible), sum(row[2] for row in visible)


def ru_maxrss_mb(usage: Any) -> float:
    raw = float(getattr(usage, "ru_maxrss", 0.0))
    if sys.platform == "darwin":
        return raw / (1024.0 * 1024.0)
    return raw / 1024.0


def terminate_process_group(process: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            pid, _, _ = os.wait4(process.pid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == process.pid:
            return
        time.sleep(0.1)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_command(
    command: list[str],
    cwd: Path,
    sample_interval: float,
    timeout_seconds: float | None,
    environment: dict[str, str],
) -> dict[str, Any]:
    start = time.monotonic()
    cpu_samples: list[float] = []
    rss_samples_mb: list[float] = []
    usage = None
    timed_out = False

    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        start_new_session=True,
    )

    status = None
    while status is None:
        snapshot = process_tree_snapshot(process.pid)
        if snapshot is not None:
            cpu_pct, rss_kb = snapshot
            cpu_samples.append(cpu_pct)
            rss_samples_mb.append(rss_kb / 1024.0)

        if hasattr(os, "wait4"):
            try:
                waited_pid, wait_status, wait_usage = os.wait4(process.pid, os.WNOHANG)
            except ChildProcessError:
                waited_pid = process.pid
                wait_status = 0
                wait_usage = None
            if waited_pid == process.pid:
                status = wait_status
                usage = wait_usage
                process.returncode = os.waitstatus_to_exitcode(wait_status)
        else:
            return_code = process.poll()
            if return_code is not None:
                status = return_code

        elapsed = time.monotonic() - start
        if status is None and timeout_seconds is not None and elapsed > timeout_seconds:
            timed_out = True
            terminate_process_group(process)
            try:
                waited_pid, wait_status, wait_usage = os.wait4(process.pid, 0)
                if waited_pid == process.pid:
                    usage = wait_usage
                    process.returncode = os.waitstatus_to_exitcode(wait_status)
            except ChildProcessError:
                process.returncode = -signal.SIGTERM
            status = process.returncode

        if status is None:
            time.sleep(sample_interval)

    wall_time = max(time.monotonic() - start, 1e-9)
    user_cpu = float(getattr(usage, "ru_utime", 0.0))
    system_cpu = float(getattr(usage, "ru_stime", 0.0))
    total_cpu = user_cpu + system_cpu
    exact_peak_rss = ru_maxrss_mb(usage) if usage is not None else 0.0
    sampled_peak_rss = max(rss_samples_mb, default=0.0)

    return {
        "status": "timeout" if timed_out else "success" if process.returncode == 0 else "failed",
        "exit_code": process.returncode,
        "wall_time_s": wall_time,
        "user_cpu_time_s": user_cpu,
        "system_cpu_time_s": system_cpu,
        "total_cpu_time_s": total_cpu,
        "avg_cpu_core_utilization_pct": total_cpu / wall_time * 100.0,
        "sampled_avg_cpu_pct": statistics.fmean(cpu_samples) if cpu_samples else 0.0,
        "sampled_peak_cpu_pct": max(cpu_samples, default=0.0),
        "avg_rss_mb": statistics.fmean(rss_samples_mb) if rss_samples_mb else exact_peak_rss,
        "peak_rss_mb": max(exact_peak_rss, sampled_peak_rss),
        "sample_count": len(cpu_samples),
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def aggregate_commands(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        key = (
            row["experiment_id"],
            row["method_id"],
            row["method_name"],
            row["phase_id"],
            row["phase_name"],
            row["repetition"],
            row["is_warmup"],
        )
        groups[key].append(row)

    phase_rows = []
    for key, items in groups.items():
        status = "success" if all(item["status"] == "success" for item in items) else "failed"
        phase_rows.append(
            {
                "experiment_id": key[0],
                "method_id": key[1],
                "method_name": key[2],
                "phase_id": key[3],
                "phase_name": key[4],
                "repetition": key[5],
                "is_warmup": key[6],
                "status": status,
                "command_count": len(items),
                "wall_time_s": sum(item["wall_time_s"] for item in items),
                "user_cpu_time_s": sum(item["user_cpu_time_s"] for item in items),
                "system_cpu_time_s": sum(item["system_cpu_time_s"] for item in items),
                "total_cpu_time_s": sum(item["total_cpu_time_s"] for item in items),
                "avg_cpu_core_utilization_pct": (
                    sum(item["total_cpu_time_s"] for item in items)
                    / max(sum(item["wall_time_s"] for item in items), 1e-9)
                    * 100.0
                ),
                "sampled_avg_cpu_pct": statistics.fmean(
                    item["sampled_avg_cpu_pct"] for item in items
                ),
                "sampled_peak_cpu_pct": max(item["sampled_peak_cpu_pct"] for item in items),
                "avg_rss_mb": statistics.fmean(item["avg_rss_mb"] for item in items),
                "peak_rss_mb": max(item["peak_rss_mb"] for item in items),
            }
        )
    return phase_rows


def add_total_rows(phase_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in phase_rows:
        key = (
            row["experiment_id"],
            row["method_id"],
            row["method_name"],
            row["repetition"],
            row["is_warmup"],
        )
        groups[key].append(row)

    totals = []
    for key, items in groups.items():
        wall = sum(item["wall_time_s"] for item in items)
        cpu = sum(item["total_cpu_time_s"] for item in items)
        totals.append(
            {
                "experiment_id": key[0],
                "method_id": key[1],
                "method_name": key[2],
                "phase_id": "total",
                "phase_name": "总开销",
                "repetition": key[3],
                "is_warmup": key[4],
                "status": "success" if all(item["status"] == "success" for item in items) else "failed",
                "command_count": sum(item["command_count"] for item in items),
                "wall_time_s": wall,
                "user_cpu_time_s": sum(item["user_cpu_time_s"] for item in items),
                "system_cpu_time_s": sum(item["system_cpu_time_s"] for item in items),
                "total_cpu_time_s": cpu,
                "avg_cpu_core_utilization_pct": cpu / max(wall, 1e-9) * 100.0,
                "sampled_avg_cpu_pct": statistics.fmean(item["sampled_avg_cpu_pct"] for item in items),
                "sampled_peak_cpu_pct": max(item["sampled_peak_cpu_pct"] for item in items),
                "avg_rss_mb": statistics.fmean(item["avg_rss_mb"] for item in items),
                "peak_rss_mb": max(item["peak_rss_mb"] for item in items),
            }
        )
    return phase_rows + totals


def summarize_phases(phase_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in phase_rows:
        if row["is_warmup"] or row["status"] != "success":
            continue
        groups[(row["method_id"], row["method_name"], row["phase_id"], row["phase_name"])].append(row)

    summaries = []
    for (method_id, method_name, phase_id, phase_name), items in groups.items():
        summary: dict[str, Any] = {
            "method_id": method_id,
            "method_name": method_name,
            "phase_id": phase_id,
            "phase_name": phase_name,
            "successful_repetitions": len(items),
        }
        for metric in METRIC_FIELDS:
            values = [float(item[metric]) for item in items]
            summary[f"{metric}_median"] = statistics.median(values)
        summaries.append(summary)
    phase_order = {
        "feature_extraction": 0,
        "data_preparation": 0,
        "model_training": 1,
        "model_detection": 2,
        "total": 99,
    }
    return sorted(
        summaries,
        key=lambda row: (
            row["method_id"],
            phase_order.get(row["phase_id"], 50),
            row["phase_id"],
        ),
    )


def write_pair_csv_files(
    experiment_dir: Path,
    methods: list[dict[str, Any]],
    summary_rows: list[dict[str, Any]],
) -> list[Path]:
    result_paths = []
    fields = [
        "comparison_item",
        "baseline_method",
        "proposed_method",
        "baseline_wall_time_s",
        "proposed_wall_time_s",
        "wall_time_improvement_pct",
        "wall_time_change",
        "baseline_cpu_time_s",
        "proposed_cpu_time_s",
        "cpu_time_reduction_pct",
        "cpu_time_change",
        "baseline_avg_cpu_pct",
        "proposed_avg_cpu_pct",
        "avg_cpu_reduction_pct",
        "avg_cpu_change",
        "baseline_peak_rss_mb",
        "proposed_peak_rss_mb",
        "peak_rss_reduction_pct",
        "peak_rss_change",
    ]
    for first, second in combinations(methods, 2):
        first_info = {"id": safe_id(str(first["id"])), "name": str(first.get("display_name", first["id"]))}
        second_info = {"id": safe_id(str(second["id"])), "name": str(second.get("display_name", second["id"]))}
        method_ids = [first_info["id"], second_info["id"]]
        selected = [row for row in summary_rows if row["method_id"] in method_ids]
        summary_index = {(row["method_id"], row["phase_id"]): row for row in selected}
        phase_ids = []
        for row in selected:
            if row["phase_id"] not in phase_ids:
                phase_ids.append(row["phase_id"])

        output_rows = []
        for phase_id in phase_ids:
            baseline = summary_index.get((first_info["id"], phase_id))
            compared = summary_index.get((second_info["id"], phase_id))
            if baseline is None or compared is None:
                continue

            def representative(row: dict[str, Any], metric: str) -> float:
                return float(row[f"{metric}_median"])

            def reduction_pct(metric: str) -> float | str:
                denominator = representative(baseline, metric)
                if denominator == 0.0:
                    return "N/A"
                return (denominator - representative(compared, metric)) / denominator * 100.0

            def change_text(metric: str, lower_word: str, higher_word: str) -> str:
                value = reduction_pct(metric)
                if value == "N/A":
                    return "无法计算"
                numeric = float(value)
                if abs(numeric) < 1e-9:
                    return "持平"
                if numeric > 0:
                    return f"{lower_word}{numeric:.2f}%"
                return f"{higher_word}{abs(numeric):.2f}%"

            output_rows.append(
                {
                    "comparison_item": baseline["phase_name"],
                    "baseline_method": first_info["name"],
                    "proposed_method": second_info["name"],
                    "baseline_wall_time_s": representative(baseline, "wall_time_s"),
                    "proposed_wall_time_s": representative(compared, "wall_time_s"),
                    "wall_time_improvement_pct": reduction_pct("wall_time_s"),
                    "wall_time_change": change_text("wall_time_s", "耗时降低", "耗时增加"),
                    "baseline_cpu_time_s": representative(baseline, "total_cpu_time_s"),
                    "proposed_cpu_time_s": representative(compared, "total_cpu_time_s"),
                    "cpu_time_reduction_pct": reduction_pct("total_cpu_time_s"),
                    "cpu_time_change": change_text("total_cpu_time_s", "CPU时间降低", "CPU时间增加"),
                    "baseline_avg_cpu_pct": representative(baseline, "avg_cpu_core_utilization_pct"),
                    "proposed_avg_cpu_pct": representative(compared, "avg_cpu_core_utilization_pct"),
                    "avg_cpu_reduction_pct": reduction_pct("avg_cpu_core_utilization_pct"),
                    "avg_cpu_change": change_text("avg_cpu_core_utilization_pct", "平均CPU降低", "平均CPU增加"),
                    "baseline_peak_rss_mb": representative(baseline, "peak_rss_mb"),
                    "proposed_peak_rss_mb": representative(compared, "peak_rss_mb"),
                    "peak_rss_reduction_pct": reduction_pct("peak_rss_mb"),
                    "peak_rss_change": change_text("peak_rss_mb", "峰值内存降低", "峰值内存增加"),
                }
            )

        filename = f"{first_info['id']}_vs_{second_info['id']}_efficiency_comparison.csv"
        result_path = experiment_dir / filename
        write_csv(result_path, output_rows, fields)
        result_paths.append(result_path)
    return result_paths


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    project_root = Path(__file__).resolve().parents[2]
    experiment_name = safe_id(str(config.get("experiment_name", config_path.stem)))
    results_root = Path(args.results_root)
    if not results_root.is_absolute():
        results_root = project_root / results_root
    results_root.mkdir(parents=True, exist_ok=True)

    temporary_workspace = tempfile.TemporaryDirectory(prefix=f"flow_gene_{experiment_name}_")
    workspace_dir = Path(temporary_workspace.name)
    artifacts_dir = workspace_dir / "artifacts"
    artifacts_dir.mkdir()

    repetitions = args.repetitions if args.repetitions is not None else int(config.get("repetitions", 1))
    warmups = (
        args.warmup_repetitions
        if args.warmup_repetitions is not None
        else int(config.get("warmup_repetitions", 0))
    )
    if repetitions <= 0 or warmups < 0:
        raise ValueError("repetitions must be positive and warmup_repetitions cannot be negative")
    sample_interval = max(float(config.get("sample_interval_seconds", 0.2)), 0.05)
    timeout_seconds = config.get("timeout_seconds")
    timeout_seconds = float(timeout_seconds) if timeout_seconds is not None else None

    base_context: dict[str, Any] = {
        "project_root": project_root,
        "experiment_id": experiment_name,
        "experiment_dir": workspace_dir,
        "artifacts_dir": artifacts_dir,
        "python": sys.executable,
    }
    base_context.update(config.get("variables", {}))
    for key, value in list(base_context.items()):
        if isinstance(value, str):
            base_context[key] = expand_text(value, base_context)

    methods = config["methods"]
    if len(methods) < 2:
        temporary_workspace.cleanup()
        raise ValueError("Efficiency comparison requires at least two methods")

    raw_rows: list[dict[str, Any]] = []
    total_rounds = warmups + repetitions
    for round_index in range(total_rounds):
        is_warmup = round_index < warmups
        repetition = round_index + 1 if is_warmup else round_index - warmups + 1
        ordered_methods = methods if round_index % 2 == 0 else list(reversed(methods))
        for method in ordered_methods:
            method_id = safe_id(str(method["id"]))
            method_name = str(method.get("display_name", method_id))
            repeat_kind = "warmup" if is_warmup else "repeat"
            repeat_dir = artifacts_dir / method_id / f"{repeat_kind}_{repetition:02d}"
            repeat_dir.mkdir(parents=True, exist_ok=True)
            context = dict(base_context)
            context.update(
                {
                    "method_id": method_id,
                    "method_dir": artifacts_dir / method_id,
                    "repeat": repetition,
                    "repeat_dir": repeat_dir,
                }
            )
            environment = os.environ.copy()
            for key, value in config.get("environment", {}).items():
                environment[str(key)] = expand_text(str(value), context)
            for key, value in method.get("environment", {}).items():
                environment[str(key)] = expand_text(str(value), context)

            for phase in method.get("phases", []):
                phase_id = safe_id(str(phase["id"]))
                phase_name = str(phase.get("display_name", phase_id))
                phase_context = dict(context)
                phase_context["phase_id"] = phase_id
                phase_context["phase_dir"] = repeat_dir / phase_id
                Path(phase_context["phase_dir"]).mkdir(parents=True, exist_ok=True)
                for command_index, command_spec in enumerate(phase.get("commands", []), start=1):
                    command = expand_command(command_spec, phase_context)
                    printable = shlex.join(command)
                    print(
                        f"[{method_id}][{repeat_kind}={repetition}][{phase_id}][cmd={command_index}] {printable}",
                        flush=True,
                    )
                    measurement = run_command(
                        command=command,
                        cwd=project_root,
                        sample_interval=sample_interval,
                        timeout_seconds=float(phase.get("timeout_seconds", timeout_seconds))
                        if phase.get("timeout_seconds", timeout_seconds) is not None
                        else None,
                        environment=environment,
                    )
                    row = {
                        "experiment_id": experiment_name,
                        "method_id": method_id,
                        "method_name": method_name,
                        "phase_id": phase_id,
                        "phase_name": phase_name,
                        "repetition": repetition,
                        "is_warmup": is_warmup,
                        "command_index": command_index,
                        "command": printable,
                        **measurement,
                    }
                    raw_rows.append(row)
                    if measurement["status"] != "success":
                        exit_code = measurement["exit_code"]
                        temporary_workspace.cleanup()
                        raise RuntimeError(
                            f"Efficiency command failed with exit code {exit_code}: {printable}"
                        )

    phase_rows = add_total_rows(aggregate_commands(raw_rows))
    summary_rows = summarize_phases(phase_rows)
    result_paths = write_pair_csv_files(results_root, methods, summary_rows)
    temporary_workspace.cleanup()

    for result_path in result_paths:
        print(f"Result CSV: {result_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
