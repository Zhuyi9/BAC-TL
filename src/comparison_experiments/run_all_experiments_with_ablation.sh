#!/usr/bin/env bash
# 线性运行五组正式攻击实验和 CTU-13 时序粒度消融实验。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
PYTHON="${PYTHON:-python3}"
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
CTU_PCAP="${DATA_ROOT}/pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"
SCAN_PCAP="${DATA_ROOT}/pcap/scan/web_scan.pcap"
XSS_PCAP="${DATA_ROOT}/pcap/xss/XSS.pcap"
ZEUS_PCAP="${DATA_ROOT}/pcap/trojan/Malware/Zeus.pcap"
KEEP_WORK=0

usage() {
    cat <<'EOF'
用法：
  comparison_experiments/run_all_experiments_with_ablation.sh [选项]

执行顺序：DoS -> CTU-13 场景 12 -> Scan -> XSS -> Zeus -> 时序粒度消融。

选项：
  --ids-csv PATH             IDS-2017 已标注流 CSV
  --ctu-pcap PATH            CTU-13 场景 12 Botnet PCAP
  --scan-pcap PATH           Scan 正类 PCAP
  --xss-pcap PATH            XSS 正类 PCAP
  --zeus-pcap PATH           Zeus 正类 PCAP
  --epochs N                 分类器微调轮数（默认 10）
  --pretrain-epochs N        分类器预训练轮数（默认 10）
  --centroid-epochs N        质心 Transformer 轮数（默认 5）
  --pca-dim N                分类器 PCA 维度（默认 128）
  --max-real-positive N      真实训练正类上限（默认 3000）
  --max-ids-negative N       IDS-2017 背景流上限（默认 10000）
  --random-state N           随机种子（默认 42）
  --keep-work                保留五组正式实验的中间工作目录
  -h, --help                显示帮助
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "参数 $1 需要一个值" >&2
        usage >&2
        exit 2
    fi
}

COMMON_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ids-csv)
            require_value "$@"; IDS_CSV="$2"; shift 2 ;;
        --ctu-pcap)
            require_value "$@"; CTU_PCAP="$2"; shift 2 ;;
        --scan-pcap)
            require_value "$@"; SCAN_PCAP="$2"; shift 2 ;;
        --xss-pcap)
            require_value "$@"; XSS_PCAP="$2"; shift 2 ;;
        --zeus-pcap)
            require_value "$@"; ZEUS_PCAP="$2"; shift 2 ;;
        --epochs|--pretrain-epochs|--centroid-epochs|--pca-dim|--max-real-positive|--max-ids-negative|--random-state)
            require_value "$@"; COMMON_ARGS+=("$1" "$2"); shift 2 ;;
        --keep-work)
            KEEP_WORK=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

if ! command -v "${PYTHON}" >/dev/null 2>&1; then
    echo "找不到可执行 Python：${PYTHON}" >&2
    exit 1
fi
if [[ ! -f "${IDS_CSV}" ]]; then
    echo "找不到 IDS-2017 CSV：${IDS_CSV}" >&2
    exit 1
fi
if [[ ! -f "${CTU_PCAP}" ]]; then
    echo "找不到 CTU-13 PCAP：${CTU_PCAP}" >&2
    exit 1
fi
for ATTACK_INPUT in "${SCAN_PCAP}" "${XSS_PCAP}" "${ZEUS_PCAP}"; do
    if [[ ! -f "${ATTACK_INPUT}" ]]; then
        echo "找不到攻击 PCAP：${ATTACK_INPUT}" >&2
        exit 1
    fi
done

cd "${PROJECT_ROOT}"
export PYTHON

run_formal() {
    local name="$1"
    shift
    local script="${SCRIPT_DIR}/${name}/run_full_experiment.sh"
    local args=("$@" --ids-csv "${IDS_CSV}")
    if [[ "${#COMMON_ARGS[@]}" -gt 0 ]]; then
        args+=("${COMMON_ARGS[@]}")
    fi
    if [[ "${KEEP_WORK}" -eq 1 ]]; then
        args+=(--keep-work)
    fi
    echo
    echo "========== 开始 ${name} 实验 =========="
    "${script}" "${args[@]}"
    echo "========== 完成 ${name} 实验 =========="
}

run_formal dos
run_formal ctu13_scenario12 --ctu-pcap "${CTU_PCAP}"
run_formal scan --positive-pcap "${SCAN_PCAP}"
run_formal xss --positive-pcap "${XSS_PCAP}"
run_formal zeus --positive-pcap "${ZEUS_PCAP}"

echo
echo "========== 开始时序粒度消融实验（仅 generated） =========="
ABLATION_ARGS=(--ctu-pcap "${CTU_PCAP}" --ids-csv "${IDS_CSV}")
if [[ "${#COMMON_ARGS[@]}" -gt 0 ]]; then
    ABLATION_ARGS+=("${COMMON_ARGS[@]}")
fi
PYTHON="${PYTHON}" "${SCRIPT_DIR}/ablation/temporal_granularity/run_ablation.sh" "${ABLATION_ARGS[@]}"
echo "========== 完成时序粒度消融实验 =========="

echo
echo "全部实验完成。结果目录：${PROJECT_ROOT}/comparison_results"
echo "时序粒度消融结果：${PROJECT_ROOT}/comparison_results/ablation/temporal_granularity/temporal_granularity_comparison.csv"
