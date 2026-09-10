#!/usr/bin/env bash
# Run Zeus, Scan, or XSS through the same pretrain/fine-tune comparison pipeline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
SHARED_DIR="${PROJECT_ROOT}/comparison_experiments/ctu13_scenario12"
MEASURE_SCRIPT="${SCRIPT_DIR}/measure_command.py"
EFFICIENCY_SUMMARY_SCRIPT="${SCRIPT_DIR}/write_efficiency_csv.py"

PYTHON="${PYTHON:-python3}"
ATTACK=""
POSITIVE_PCAP=""
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
RESULTS_DIR=""
WORK_DIR=""
KEEP_WORK=0
MAX_REAL_POSITIVE=3000
AUGMENTATION_COUNT=0
MAX_IDS_NEGATIVE=10000
TRAIN_NEGATIVE_RATIO=2.0
CENTROID_EPOCHS=5
CLASSIFIER_EPOCHS=10
PRETRAIN_EPOCHS=10
PCA_DIM=128
RANDOM_STATE=42
MACRO_WINDOW_OVERRIDE=""
TARGET_PROFILE_MODE="nearest_historical_flow"

usage() {
    cat <<'EOF'
用法：
  run_full_experiment.sh --attack dos|zeus|scan|xss [选项]

可选参数：
  --positive-pcap PATH       覆盖该攻击类型的默认 PCAP
  --ids-csv PATH             IDS-2017 负类 CSV
  --results-dir PATH         覆盖最终结果目录
  --work-dir PATH            指定中间工作目录
  --keep-work                保留中间文件，便于排查
  --macro-window N           覆盖默认宏观窗口秒数
  --generation-target-mode M 生成目标：nearest_historical_flow 或 absolute_centroid（默认 nearest_historical_flow）
  --max-real-positive N      真实训练正类上限（默认 3000）
  --augmentation-count N     覆盖上一窗口决定的增强数量
  --max-ids-negative N       IDS-2017 总体抽样上限（默认 10000）
  --train-negative-ratio N   训练负类/真实正类上限比例（默认 2.0）
  --centroid-epochs N        质心 Transformer 轮数（默认 5）
  --pretrain-epochs N        基础分类器预训练轮数（默认 10）
  --epochs N                 两种方法的微调轮数（默认 10）
  --pca-dim N                PCA 维度（默认 128）
  --random-state N           随机种子（默认 42）
  -h, --help                 显示帮助

示例：
  comparison_experiments/attack_types/run_full_experiment.sh --attack zeus
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "${2}" ]]; then
        echo "参数 $1 需要一个值" >&2
        usage >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --attack) require_value "$@"; ATTACK="$2"; shift 2 ;;
        --positive-pcap) require_value "$@"; POSITIVE_PCAP="$2"; shift 2 ;;
        --ids-csv) require_value "$@"; IDS_CSV="$2"; shift 2 ;;
        --results-dir) require_value "$@"; RESULTS_DIR="$2"; shift 2 ;;
        --work-dir) require_value "$@"; WORK_DIR="$2"; shift 2 ;;
        --keep-work) KEEP_WORK=1; shift ;;
        --macro-window) require_value "$@"; MACRO_WINDOW_OVERRIDE="$2"; shift 2 ;;
        --generation-target-mode) require_value "$@"; TARGET_PROFILE_MODE="$2"; shift 2 ;;
        --max-real-positive) require_value "$@"; MAX_REAL_POSITIVE="$2"; shift 2 ;;
        --augmentation-count) require_value "$@"; AUGMENTATION_COUNT="$2"; shift 2 ;;
        --max-ids-negative) require_value "$@"; MAX_IDS_NEGATIVE="$2"; shift 2 ;;
        --train-negative-ratio) require_value "$@"; TRAIN_NEGATIVE_RATIO="$2"; shift 2 ;;
        --centroid-epochs) require_value "$@"; CENTROID_EPOCHS="$2"; shift 2 ;;
        --pretrain-epochs) require_value "$@"; PRETRAIN_EPOCHS="$2"; shift 2 ;;
        --epochs) require_value "$@"; CLASSIFIER_EPOCHS="$2"; shift 2 ;;
        --pca-dim) require_value "$@"; PCA_DIM="$2"; shift 2 ;;
        --random-state) require_value "$@"; RANDOM_STATE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "${ATTACK}" ]]; then
    echo "缺少 --attack" >&2
    usage >&2
    exit 2
fi

case "${ATTACK}" in
    dos|DoS|DOS)
        ATTACK="dos"
        DEFAULT_PCAP=""
        TARGET_LABEL="DoS"
        DATASET_NAME="IDS-2017 Wednesday DoS"
        TARGET_DESCRIPTION="IDS-2017 DoS traffic"
        MACRO_WINDOW=60
        ;;
    zeus|Zeus|ZEUS)
        ATTACK="zeus"
        DEFAULT_PCAP="${DATA_ROOT}/pcap/trojan/Malware/Zeus.pcap"
        TARGET_LABEL="Zeus"
        DATASET_NAME="Trojan Malware PCAP"
        TARGET_DESCRIPTION="Zeus malware traffic"
        MACRO_WINDOW=60
        ;;
    scan|Scan|SCAN)
        ATTACK="scan"
        DEFAULT_PCAP="${DATA_ROOT}/pcap/scan/web_scan.pcap"
        TARGET_LABEL="Scan"
        DATASET_NAME="Web Scan PCAP"
        TARGET_DESCRIPTION="Web scan attack traffic"
        MACRO_WINDOW=30
        ;;
    xss|Xss|XSS)
        ATTACK="xss"
        DEFAULT_PCAP="${DATA_ROOT}/pcap/xss/XSS.pcap"
        TARGET_LABEL="XSS"
        DATASET_NAME="XSS PCAP"
        TARGET_DESCRIPTION="XSS web attack traffic"
        MACRO_WINDOW=60
        ;;
    *)
        echo "不支持的攻击类型：${ATTACK}；可选 dos、zeus、scan、xss" >&2
        exit 2
        ;;
esac

if [[ -n "${MACRO_WINDOW_OVERRIDE}" ]]; then
    MACRO_WINDOW="${MACRO_WINDOW_OVERRIDE}"
fi
if [[ -z "${POSITIVE_PCAP}" && -n "${DEFAULT_PCAP}" ]]; then
    POSITIVE_PCAP="${DEFAULT_PCAP}"
fi
if [[ -z "${RESULTS_DIR}" ]]; then
    RESULTS_DIR="${PROJECT_ROOT}/comparison_results/attack_types/${ATTACK}"
fi

if [[ "${TARGET_PROFILE_MODE}" != "nearest_historical_flow" && "${TARGET_PROFILE_MODE}" != "absolute_centroid" ]]; then
    echo "--generation-target-mode 必须是 nearest_historical_flow 或 absolute_centroid" >&2
    exit 2
fi

cd "${PROJECT_ROOT}"
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
    echo "找不到可执行 Python：${PYTHON}" >&2
    exit 1
fi
if [[ "${ATTACK}" != "dos" && ! -f "${POSITIVE_PCAP}" ]]; then
    echo "找不到正类 PCAP：${POSITIVE_PCAP}" >&2
    exit 1
fi
if [[ ! -f "${IDS_CSV}" ]]; then
    echo "找不到 IDS-2017 CSV：${IDS_CSV}" >&2
    exit 1
fi

if [[ -z "${WORK_DIR}" ]]; then
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${ATTACK}_attack.XXXXXX")"
    OWN_WORK_DIR=1
else
    mkdir -p "${WORK_DIR}"
    OWN_WORK_DIR=0
fi

cleanup() {
    if [[ "${KEEP_WORK}" -eq 0 && "${OWN_WORK_DIR}" -eq 1 ]]; then
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT

INPUT_DIR="${WORK_DIR}/input"
SPLIT_DIR="${INPUT_DIR}/time_split"
CENTROID_WINDOWS_DIR="${WORK_DIR}/centroid_windows"
CENTROID_DATASET_DIR="${WORK_DIR}/centroid_dataset"
CENTROID_MODEL_DIR="${WORK_DIR}/centroid_model"
GENERATED_DIR="${WORK_DIR}/generated"
METRICS_DIR="${WORK_DIR}/efficiency_metrics"
RAW_CSV="${INPUT_DIR}/${ATTACK}.csv"
LABELED_CSV="${INPUT_DIR}/${ATTACK}_labeled.csv"
NEGATIVE_CSV="${IDS_CSV}"
TRAIN_CSV="${SPLIT_DIR}/${ATTACK}_train.csv"
OUTPUT_FILENAME="${ATTACK}_method_comparison.csv"
EFFICIENCY_OUTPUT_FILENAME="${ATTACK}_efficiency_comparison.csv"
MEASURE_INDEX=0

mkdir -p "${INPUT_DIR}" "${METRICS_DIR}"

measure_phase() {
    local phase="$1"
    local method="$2"
    shift 2
    MEASURE_INDEX=$((MEASURE_INDEX + 1))
    "${PYTHON}" "${MEASURE_SCRIPT}" \
        --output "${METRICS_DIR}/outer_${MEASURE_INDEX}_${method}_${phase}.json" \
        --phase "${phase}" \
        --method "${method}" \
        -- "${PYTHON}" "$@"
}

if [[ "${ATTACK}" == "dos" ]]; then
    echo "[1/6] 从 IDS-2017 流级标签筛选 DoS 正类和非 DoS 背景"
    measure_phase feature_extraction generated "${SCRIPT_DIR}/filter_labeled_flows.py" \
        --input_csv "${IDS_CSV}" --output_csv "${LABELED_CSV}" --label "${TARGET_LABEL}"
    measure_phase feature_extraction generated "${SCRIPT_DIR}/filter_labeled_flows.py" \
        --input_csv "${IDS_CSV}" --output_csv "${INPUT_DIR}/dos_negative.csv" --label "${TARGET_LABEL}" --exclude
    NEGATIVE_CSV="${INPUT_DIR}/dos_negative.csv"
else
    echo "[1/6] 转换 ${TARGET_LABEL} PCAP"
    measure_phase feature_extraction generated src/UnifiedPcapToCSV.py -i "${POSITIVE_PCAP}" -o "${RAW_CSV}"

    echo "[2/6] 添加 ${TARGET_LABEL} 正类标签"
    measure_phase feature_extraction generated "${SCRIPT_DIR}/annotate_attack_csv.py" \
        --input_csv "${RAW_CSV}" \
        --output_csv "${LABELED_CSV}" \
        --label "${TARGET_LABEL}" \
        --dataset "${DATASET_NAME}" \
        --attack_key "${ATTACK}"
fi

echo "[3/6] 按完整 ${MACRO_WINDOW} 秒窗口切分正类"
measure_phase feature_extraction generated "${SHARED_DIR}/split_ctu_csv_by_time.py" \
    --input_csv "${LABELED_CSV}" \
    --output_dir "${SPLIT_DIR}" \
    --output_prefix "${ATTACK}" \
    --train_ratio 0.6 \
    --calib_ratio 0.2 \
    --macro_window "${MACRO_WINDOW}" \
    --min_packets 2
rm -f "${RAW_CSV}"

echo "[4/6] 训练质心模型并预测一个下一窗口"
measure_phase feature_extraction generated src/drift_prediction/extract_window_centroids.py \
    --input_csv "${TRAIN_CSV}" \
    --output_dir "${CENTROID_WINDOWS_DIR}" \
    --macro_window "${MACRO_WINDOW}" \
    --slice_window 1 \
    --max_slices 60 \
    --min_packets 2
measure_phase feature_extraction generated src/drift_prediction/build_centroid_dataset.py \
    --centroid_dir "${CENTROID_WINDOWS_DIR}" \
    --output_dir "${CENTROID_DATASET_DIR}" \
    --history_mode expanding \
    --exclude_last_per_label
measure_phase model_training generated src/drift_prediction/train_centroid_transformer.py \
    --dataset_dir "${CENTROID_DATASET_DIR}" \
    --output_dir "${CENTROID_MODEL_DIR}" \
    --epochs "${CENTROID_EPOCHS}"

SEED_FLOW_COUNT="$("${PYTHON}" -c 'import pandas as pd,sys; m=pd.read_csv(sys.argv[1]); s=m[m["label"]==sys.argv[2]]; print(int((s["window_start"]==s["window_start"].max()).sum()))' "${CENTROID_WINDOWS_DIR}/flow_bank.csv" "${TARGET_LABEL}")"
if [[ "${SEED_FLOW_COUNT}" -le 0 ]]; then
    echo "训练区间最后窗口没有有效 ${TARGET_LABEL} 种子流" >&2
    exit 1
fi
if [[ "${AUGMENTATION_COUNT}" -le 0 ]]; then
    # DoS 的最后窗口可能包含大量短流；默认限制为真实正类上限，
    # 避免增强样本量远大于预训练正类而主导微调。
    if [[ "${ATTACK}" == "dos" ]]; then
        AUGMENTATION_COUNT="${MAX_REAL_POSITIVE}"
        if [[ "${AUGMENTATION_COUNT}" -gt "${SEED_FLOW_COUNT}" ]]; then
            AUGMENTATION_COUNT="${SEED_FLOW_COUNT}"
        fi
    else
        AUGMENTATION_COUNT="${SEED_FLOW_COUNT}"
    fi
fi
if [[ "${AUGMENTATION_COUNT}" -gt "${SEED_FLOW_COUNT}" ]]; then
    echo "--augmentation-count 不能超过上一窗口有效流数 ${SEED_FLOW_COUNT}" >&2
    exit 1
fi
echo "生成参数：seed_flows=${SEED_FLOW_COUNT}, generated_flows=${AUGMENTATION_COUNT}"

measure_phase traffic_generation generated src/drift_prediction/generate_single_step_from_centroid_prediction.py \
    --input_csv "${TRAIN_CSV}" \
    --centroid_dir "${CENTROID_WINDOWS_DIR}" \
    --model_path "${CENTROID_MODEL_DIR}/model.pt" \
    --output_dir "${GENERATED_DIR}" \
    --label "${TARGET_LABEL}" \
    --num_flows "${AUGMENTATION_COUNT}" \
    --macro_window "${MACRO_WINDOW}" \
    --min_packets 2 \
    --target_profile_mode "${TARGET_PROFILE_MODE}" \
    --random_state "${RANDOM_STATE}"

GENERATED_CSV="${GENERATED_DIR}/generated_single_step_${TARGET_LABEL}_${AUGMENTATION_COUNT}flows.csv"
if [[ ! -f "${GENERATED_CSV}" ]]; then
    echo "生成阶段没有输出合并 CSV：${GENERATED_CSV}" >&2
    exit 1
fi
GENERATED_VALID_COUNT="$("${PYTHON}" -c 'import csv,json,sys; f=open(sys.argv[1],newline="",encoding="utf-8"); r=csv.DictReader(f); print(sum(1 for x in r if x["layer"]=="behavior" and int(json.loads(x["encoding_header"]).get("packet_count",0))>=2)); f.close()' "${GENERATED_CSV}")"
if [[ "${GENERATED_VALID_COUNT}" -le 0 ]]; then
    echo "生成 CSV 中没有满足 min_packets=2 的有效流" >&2
    exit 1
fi
EFFECTIVE_AUGMENTATION_COUNT="${AUGMENTATION_COUNT}"
if [[ "${GENERATED_VALID_COUNT}" -lt "${AUGMENTATION_COUNT}" ]]; then
    EFFECTIVE_AUGMENTATION_COUNT="${GENERATED_VALID_COUNT}"
    echo "有效生成流为 ${GENERATED_VALID_COUNT}；两种增强方法同步采用该数量。"
fi

echo "[5/6] 比较 SMOTE 与流量重组微调"
"${PYTHON}" "${SHARED_DIR}/run_experiment.py" \
    --positive_csv "${LABELED_CSV}" \
    --ids_csv "${NEGATIVE_CSV}" \
    --generated_input "${GENERATED_CSV}" \
    --results_dir "${RESULTS_DIR}" \
    --output_filename "${OUTPUT_FILENAME}" \
    --experiment_name "${ATTACK}_vs_ids2017_all_labels" \
    --target_label "${TARGET_LABEL}" \
    --target_description "${TARGET_DESCRIPTION}" \
    --positive_source "${DATASET_NAME}" \
    --window_size "${MACRO_WINDOW}" \
    --max_real_positive "${MAX_REAL_POSITIVE}" \
    --augmentation_count "${EFFECTIVE_AUGMENTATION_COUNT}" \
    --max_ids_negative "${MAX_IDS_NEGATIVE}" \
    --train_negative_ratio "${TRAIN_NEGATIVE_RATIO}" \
    --epochs "${CLASSIFIER_EPOCHS}" \
    --pretrain_epochs "${PRETRAIN_EPOCHS}" \
    --pca_dim "${PCA_DIM}" \
    --random_state "${RANDOM_STATE}" \
    --efficiency_dir "${METRICS_DIR}"

"${PYTHON}" "${EFFICIENCY_SUMMARY_SCRIPT}" \
    --metrics-dir "${METRICS_DIR}" \
    --attack "${TARGET_LABEL}" \
    --output "${RESULTS_DIR}/${EFFICIENCY_OUTPUT_FILENAME}"

echo "[6/6] 完成"
echo "最终结果：${RESULTS_DIR}/${OUTPUT_FILENAME}"
echo "效率结果：${RESULTS_DIR}/${EFFICIENCY_OUTPUT_FILENAME}"
if [[ "${KEEP_WORK}" -eq 1 || "${OWN_WORK_DIR}" -eq 0 ]]; then
    echo "中间工作目录：${WORK_DIR}"
else
    echo "中间工作目录已清理"
fi
