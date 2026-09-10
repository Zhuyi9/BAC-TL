#!/usr/bin/env bash
# IDS-2017 DoS 实验入口。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_ENTRY="${SCRIPT_DIR}/../attack_types/run_full_experiment.sh"

exec "${SHARED_ENTRY}" --attack dos "$@"
