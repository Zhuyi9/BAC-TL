#!/usr/bin/env bash
# 使用已固化伪未来测试集运行 none/SMOTE/generated 三种分类方法。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
PYTHON="${PYTHON:-python3}"
DATASET_DIR="${PROJECT_ROOT}/comparison_datasets/ctu13_scenario12/pseudo_future_v1"
CTU_CSV=""
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
GENERATED_INPUT=""
RESULTS_DIR="${PROJECT_ROOT}/comparison_results/ctu13_scenario12/pseudo_future_v1"

usage() {
    cat <<'EOF'
用法：
  run_fixed_test_comparison.sh --ctu-csv PATH --generated-input PATH [选项]

--ctu-csv PATH          已标注 CTU-13 全量 CSV
--generated-input PATH  仅用于训练增强的 generated CSV 或 PCAP
--dataset-dir PATH      固化伪未来目录
--ids-csv PATH          IDS-2017 CSV
--results-dir PATH      结果目录
--max-real-positive N   训练真实正类上限，默认 3000
--augmentation-count N  generated/SMOTE 增强数量，默认 3000
--pca-dim N             PCA 维度，默认 128
--pretrain-epochs N     预训练轮数，默认 10
--epochs N              微调轮数，默认 10
EOF
}

MAX_REAL_POSITIVE=3000
AUGMENTATION_COUNT=3000
PCA_DIM=128
PRETRAIN_EPOCHS=10
EPOCHS=10
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ctu-csv) CTU_CSV="$2"; shift 2 ;;
        --generated-input) GENERATED_INPUT="$2"; shift 2 ;;
        --dataset-dir) DATASET_DIR="$2"; shift 2 ;;
        --ids-csv) IDS_CSV="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --max-real-positive) MAX_REAL_POSITIVE="$2"; shift 2 ;;
        --augmentation-count) AUGMENTATION_COUNT="$2"; shift 2 ;;
        --pca-dim) PCA_DIM="$2"; shift 2 ;;
        --pretrain-epochs) PRETRAIN_EPOCHS="$2"; shift 2 ;;
        --epochs) EPOCHS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done
: "${CTU_CSV:?缺少 --ctu-csv}"
: "${GENERATED_INPUT:?缺少 --generated-input}"

mkdir -p "${RESULTS_DIR}"
if [[ "${GENERATED_INPUT##*.}" == "csv" ]]; then
    GENERATED_VALID_COUNT="$(${PYTHON} -c 'import csv,json,sys; f=open(sys.argv[1],newline="",encoding="utf-8"); r=csv.DictReader(f); print(sum(1 for row in r if row.get("layer")=="behavior" and int(json.loads(row.get("encoding_header") or "{}").get("packet_count",0))>=2)); f.close()' "${GENERATED_INPUT}")"
    if [[ "${GENERATED_VALID_COUNT}" -le 0 ]]; then
        echo "训练 generated 输入没有满足 min_packets=2 的有效流" >&2
        exit 1
    fi
    if [[ "${AUGMENTATION_COUNT}" -gt "${GENERATED_VALID_COUNT}" ]]; then
        echo "训练 generated 只有 ${GENERATED_VALID_COUNT} 条有效流；SMOTE/generated 增强数量统一调整为 ${GENERATED_VALID_COUNT}" >&2
        AUGMENTATION_COUNT="${GENERATED_VALID_COUNT}"
    fi
fi
"${PYTHON}" "${SCRIPT_DIR}/../run_experiment.py" \
    --ctu_csv "${CTU_CSV}" \
    --ids_csv "${IDS_CSV}" \
    --generated_input "${GENERATED_INPUT}" \
    --results_dir "${RESULTS_DIR}" \
    --max_real_positive "${MAX_REAL_POSITIVE}" \
    --augmentation_count "${AUGMENTATION_COUNT}" \
    --pretrain_epochs "${PRETRAIN_EPOCHS}" \
    --epochs "${EPOCHS}" \
    --pca_dim "${PCA_DIM}" \
    --fixed_test_positive_csv "${DATASET_DIR}/pseudo_future_positive.csv" \
    --fixed_test_negative_csv "${DATASET_DIR}/ids_negative.csv"

echo "伪未来固定测试集对比结果：${RESULTS_DIR}/ctu13_scenario12_method_comparison.csv"
