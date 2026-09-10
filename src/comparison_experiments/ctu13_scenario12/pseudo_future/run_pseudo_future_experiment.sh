#!/usr/bin/env bash
# 生成并固化 CTU-13 场景 12 的递归伪未来测试集。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
PYTHON="${PYTHON:-python3}"
OUTPUT_DIR="${PROJECT_ROOT}/comparison_datasets/ctu13_scenario12/pseudo_future_v1"
CTU_PCAP="${DATA_ROOT}/pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pseudo_future.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

usage() {
    cat <<'EOF'
用法：
  run_pseudo_future_experiment.sh [选项]

默认使用 CTU-13 场景 12 和 IDS-2017 Wednesday 流 CSV，输出到：
  comparison_datasets/ctu13_scenario12/pseudo_future_v1

选项：
  --ctu-pcap PATH       CTU-13 场景 12 PCAP
  --ids-csv PATH        IDS-2017 流 CSV
  --output-dir PATH     固定数据集输出目录
  --horizons N          伪未来窗口数，默认 3
  --mix-ratio X         每个窗口生成正类比例，默认 0.5
  --random-state N      负类抽样随机种子，默认 42
  --keep-work           保留中间转换文件（写入 output-dir/_work）
EOF
}

KEEP_WORK=0
HORIZONS=3
MIX_RATIO=0.5
RANDOM_STATE=42
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ctu-pcap) CTU_PCAP="$2"; shift 2 ;;
        --ids-csv) IDS_CSV="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --horizons) HORIZONS="$2"; shift 2 ;;
        --mix-ratio) MIX_RATIO="$2"; shift 2 ;;
        --random-state) RANDOM_STATE="$2"; shift 2 ;;
        --keep-work) KEEP_WORK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

mkdir -p "${WORK_DIR}/input" "${OUTPUT_DIR}"
RAW_CSV="${WORK_DIR}/input/ctu13_s12_botnet.csv"
LABELED_CSV="${WORK_DIR}/input/ctu13_s12_botnet_labeled.csv"
SPLIT_DIR="${WORK_DIR}/input/time_split"
CENTROID_DIR="${WORK_DIR}/centroid_windows"
DATASET_DIR="${WORK_DIR}/centroid_dataset"
MODEL_DIR="${WORK_DIR}/centroid_model"

"${PYTHON}" "${PROJECT_ROOT}/src/UnifiedPcapToCSV.py" -i "${CTU_PCAP}" -o "${RAW_CSV}"
"${PYTHON}" "${SCRIPT_DIR}/../annotate_ctu13_csv.py" \
    --input_csv "${RAW_CSV}" --output_csv "${LABELED_CSV}" --scenario 12 --family Unknown
"${PYTHON}" "${SCRIPT_DIR}/../split_ctu_csv_by_time.py" \
    --input_csv "${LABELED_CSV}" --output_dir "${SPLIT_DIR}" \
    --output_prefix ctu13 --train_ratio 0.6 --calib_ratio 0.2 --macro_window 60 --min_packets 2
"${PYTHON}" "${PROJECT_ROOT}/src/drift_prediction/extract_window_centroids.py" \
    --input_csv "${SPLIT_DIR}/ctu13_train.csv" --output_dir "${CENTROID_DIR}" \
    --macro_window 60 --slice_window 1 --max_slices 60 --min_packets 2
"${PYTHON}" "${PROJECT_ROOT}/src/drift_prediction/build_centroid_dataset.py" \
    --centroid_dir "${CENTROID_DIR}" --output_dir "${DATASET_DIR}" \
    --history_mode expanding --exclude_last_per_label
"${PYTHON}" "${PROJECT_ROOT}/src/drift_prediction/train_centroid_transformer.py" \
    --dataset_dir "${DATASET_DIR}" --output_dir "${MODEL_DIR}" --epochs 5

ARGS=(
    --train_csv "${SPLIT_DIR}/ctu13_train.csv"
    --test_positive_csv "${SPLIT_DIR}/ctu13_test.csv"
    --ids_csv "${IDS_CSV}"
    --centroid_dir "${CENTROID_DIR}"
    --model_path "${MODEL_DIR}/model.pt"
    --output_dir "${OUTPUT_DIR}"
    --horizons "${HORIZONS}"
    --mix_ratio "${MIX_RATIO}"
    --random_state "${RANDOM_STATE}"
)
"${PYTHON}" "${SCRIPT_DIR}/generate_pseudo_future_dataset.py" "${ARGS[@]}"

if [[ "${KEEP_WORK}" -eq 1 ]]; then
    rm -rf "${OUTPUT_DIR}/_work"
    cp -R "${WORK_DIR}" "${OUTPUT_DIR}/_work"
fi

echo "固定伪未来测试集已生成：${OUTPUT_DIR}/pseudo_future_test.csv"
echo "数据清单：${OUTPUT_DIR}/dataset_manifest.json"
