#!/usr/bin/env bash
# Run temporal-granularity ablation with constrained within-slice jitter.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"

exec "${PYTHON}" "${SCRIPT_DIR}/run_ablation.py" "$@" \
    --intra-slice-mode jitter \
    --results-dir "${PROJECT_ROOT}/comparison_results/ablation/temporal_granularity/jitter"
