#!/usr/bin/env bash
# 按 v3 设置运行十轮长期漂移实验。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
exec "${PYTHON}" "${SCRIPT_DIR}/run_v3_fixed_long_term.py" "$@"
