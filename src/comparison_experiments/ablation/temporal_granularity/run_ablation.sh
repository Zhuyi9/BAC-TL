#!/usr/bin/env bash
# Run the CTU-13 scenario 12 temporal-granularity ablation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
exec "${PYTHON}" "${SCRIPT_DIR}/run_ablation.py" "$@" --intra-slice-mode even
