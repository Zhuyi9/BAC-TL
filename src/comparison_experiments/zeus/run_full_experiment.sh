#!/usr/bin/env bash
# Zeus 攻击流增强实验入口。
# 具体的数据处理、质心预测和分类对比逻辑由共享入口统一实现。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_ENTRY="${SCRIPT_DIR}/../attack_types/run_full_experiment.sh"

exec "${SHARED_ENTRY}" --attack zeus "$@"
