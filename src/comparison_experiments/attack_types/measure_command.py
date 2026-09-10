#!/usr/bin/env python3
"""运行单条实验命令并记录墙钟、CPU 和内存开销。"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
EFFICIENCY_DIR = PROJECT_ROOT / "comparison_experiments" / "efficiency"
if str(EFFICIENCY_DIR) not in sys.path:
    sys.path.insert(0, str(EFFICIENCY_DIR))

from benchmark import run_command


def parse_args() -> argparse.Namespace:
    """定义资源输出位置、阶段名称和待执行命令。"""
    parser = argparse.ArgumentParser(description="测量一条实验子命令的资源开销")
    parser.add_argument("--output", required=True, help="单条测量 JSON 输出路径")
    parser.add_argument("--phase", required=True, help="feature_extraction/model_training 等")
    parser.add_argument("--method", required=True, help="smote/generated/shared_pretrain")
    parser.add_argument("--sample-interval", type=float, default=0.2)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    """执行命令、写入测量结果；命令失败时保留失败指标并返回相同错误码。"""
    args = parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("缺少待执行命令")

    measurement = run_command(
        command=command,
        cwd=PROJECT_ROOT,
        sample_interval=max(args.sample_interval, 0.05),
        timeout_seconds=None,
        environment=os.environ.copy(),
    )
    measurement.update(
        {
            "phase": args.phase,
            "method": args.method,
            "command": shlex.join(command),
        }
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(measurement, ensure_ascii=False, indent=2), encoding="utf-8")
    if measurement["status"] != "success":
        return int(measurement.get("exit_code") or 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
