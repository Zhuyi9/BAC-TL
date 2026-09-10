#!/usr/bin/env bash
# Run even allocation first, then constrained jitter, keeping separate results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RESULTS_ROOT="${PROJECT_ROOT}/comparison_results/ablation/temporal_granularity"

mkdir -p "${RESULTS_ROOT}/even" "${RESULTS_ROOT}/jitter"

echo "[1/2] 运行片内平均分配时序粒度消融实验"
"${SCRIPT_DIR}/run_ablation.sh" "$@" \
    --results-dir "${RESULTS_ROOT}/even"

echo "[2/2] 运行片内微小抖动时序粒度消融实验"
"${SCRIPT_DIR}/run_ablation_jitter.sh" "$@"

echo "两种方式均已完成"
echo "平均分配结果：${RESULTS_ROOT}/even/temporal_granularity_comparison.csv"
echo "微小抖动结果：${RESULTS_ROOT}/jitter/temporal_granularity_comparison.csv"
