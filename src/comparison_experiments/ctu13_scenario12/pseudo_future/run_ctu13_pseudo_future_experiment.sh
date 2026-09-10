#!/usr/bin/env bash
# 先构造伪未来固定测试集，再完成 CTU-13 场景 12 分类对比。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
PYTHON="${PYTHON:-python3}"
CTU_PCAP="${DATA_ROOT}/pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
DATASET_DIR="${PROJECT_ROOT}/comparison_datasets/ctu13_scenario12/pseudo_future_v1"
RESULTS_DIR="${PROJECT_ROOT}/comparison_results/ctu13_scenario12/pseudo_future_v1"
HORIZONS=3
MIX_RATIO=0.5
RANDOM_STATE=42
MAX_REAL_POSITIVE=3000
AUGMENTATION_COUNT=3000
PCA_DIM=128
PRETRAIN_EPOCHS=10
EPOCHS=10
KEEP_WORK=0

usage() {
    cat <<'EOF'
用法：
  run_ctu13_pseudo_future_experiment.sh [选项]

流程：先构造 3 个递归伪未来窗口，再在共享固定测试集上运行 none、SMOTE、generated。

选项：
  --ctu-pcap PATH          CTU-13 场景 12 PCAP
  --ids-csv PATH           IDS-2017 流 CSV
  --dataset-dir PATH       固定数据集目录
  --results-dir PATH       分类结果目录
  --horizons N             伪未来窗口数，默认 3
  --mix-ratio X            每个窗口生成正类比例，默认 0.5
  --augmentation-count N  训练 generated/SMOTE 数量，默认 3000
  --max-real-positive N   训练真实正类上限，默认 3000
  --pca-dim N              PCA 维度，默认 128
  --pretrain-epochs N      预训练轮数，默认 10
  --epochs N               微调轮数，默认 10
  --keep-work              实验结束后保留训练转换、质心和模型中间文件
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "参数 $1 需要一个值" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ctu-pcap) require_value "$@"; CTU_PCAP="$2"; shift 2 ;;
        --ids-csv) require_value "$@"; IDS_CSV="$2"; shift 2 ;;
        --dataset-dir) require_value "$@"; DATASET_DIR="$2"; shift 2 ;;
        --results-dir) require_value "$@"; RESULTS_DIR="$2"; shift 2 ;;
        --horizons) require_value "$@"; HORIZONS="$2"; shift 2 ;;
        --mix-ratio) require_value "$@"; MIX_RATIO="$2"; shift 2 ;;
        --augmentation-count) require_value "$@"; AUGMENTATION_COUNT="$2"; shift 2 ;;
        --max-real-positive) require_value "$@"; MAX_REAL_POSITIVE="$2"; shift 2 ;;
        --pca-dim) require_value "$@"; PCA_DIM="$2"; shift 2 ;;
        --pretrain-epochs) require_value "$@"; PRETRAIN_EPOCHS="$2"; shift 2 ;;
        --epochs) require_value "$@"; EPOCHS="$2"; shift 2 ;;
        --keep-work) KEEP_WORK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ ! -f "${CTU_PCAP}" || ! -f "${IDS_CSV}" ]]; then
    echo "CTU-13 PCAP 或 IDS-2017 CSV 不存在" >&2
    exit 1
fi

echo "[1/3] 构造递归伪未来固定测试集"
PSEUDO_ARGS=(--ctu-pcap "${CTU_PCAP}" --ids-csv "${IDS_CSV}" --output-dir "${DATASET_DIR}" --horizons "${HORIZONS}" --mix-ratio "${MIX_RATIO}" --random-state "${RANDOM_STATE}" --keep-work)
"${SCRIPT_DIR}/run_pseudo_future_experiment.sh" "${PSEUDO_ARGS[@]}"

WORK_ROOT="${DATASET_DIR}/_work"
TRAIN_CSV="${WORK_ROOT}/input/ctu13_s12_botnet_labeled.csv"
TRAIN_CSV_INPUT="${WORK_ROOT}/input/time_split/ctu13_train.csv"
CENTROID_DIR="${WORK_ROOT}/centroid_windows"
CENTROID_MODEL_DIR="${WORK_ROOT}/centroid_model"
TRAIN_GENERATION_DIR="${DATASET_DIR}/training_generation"

if [[ ! -f "${TRAIN_CSV}" || ! -f "${CENTROID_MODEL_DIR}/model.pt" ]]; then
    echo "请使用 --keep-work 运行，以保留分类所需的训练 CSV 和质心模型" >&2
    exit 1
fi

echo "[2/3] 生成仅用于训练微调的 CTU-13 generated 流"
rm -rf "${TRAIN_GENERATION_DIR}"
mkdir -p "${TRAIN_GENERATION_DIR}"
"${PYTHON}" "${PROJECT_ROOT}/src/drift_prediction/generate_single_step_from_centroid_prediction.py" \
    --input_csv "${TRAIN_CSV_INPUT}" --centroid_dir "${CENTROID_DIR}" \
    --model_path "${CENTROID_MODEL_DIR}/model.pt" --output_dir "${TRAIN_GENERATION_DIR}" \
    --label Botnet --num_flows "${AUGMENTATION_COUNT}" --seed_scope all_history \
    --min_packets 2 --macro_window 60 --slice_window 1 \
    --target_profile_mode nearest_historical_flow --intra_slice_mode even --random_state "${RANDOM_STATE}"
TRAIN_GENERATED_INPUT="$(find "${TRAIN_GENERATION_DIR}" -maxdepth 1 -type f -name 'generated_single_step_Botnet_*flows.csv' | sort | tail -n 1)"
if [[ -z "${TRAIN_GENERATED_INPUT}" || ! -f "${TRAIN_GENERATED_INPUT}" ]]; then
    echo "训练 generated 流没有生成合并 CSV" >&2
    exit 1
fi

echo "[3/3] 在固定伪未来测试集上完成 CTU-13 对比"
"${SCRIPT_DIR}/run_fixed_test_comparison.sh" \
    --ctu-csv "${TRAIN_CSV}" --generated-input "${TRAIN_GENERATED_INPUT}" \
    --dataset-dir "${DATASET_DIR}" --ids-csv "${IDS_CSV}" --results-dir "${RESULTS_DIR}" \
    --max-real-positive "${MAX_REAL_POSITIVE}" --augmentation-count "${AUGMENTATION_COUNT}" \
    --pca-dim "${PCA_DIM}" --pretrain-epochs "${PRETRAIN_EPOCHS}" --epochs "${EPOCHS}"

echo "固定测试数据：${DATASET_DIR}/pseudo_future_test.csv"
echo "分类结果：${RESULTS_DIR}/ctu13_scenario12_method_comparison.csv"

if [[ "${KEEP_WORK}" -eq 0 ]]; then
    rm -rf "${DATASET_DIR}/_work" "${DATASET_DIR}/training_generation"
    echo "训练转换中间文件已清理；固定数据集和最终结果已保留。"
fi
