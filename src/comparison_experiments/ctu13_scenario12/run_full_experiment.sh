#!/usr/bin/env bash
# Run the complete CTU-13 scenario 12 P2P experiment from raw PCAP to one result CSV.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MEASURE_SCRIPT="${PROJECT_ROOT}/comparison_experiments/attack_types/measure_command.py"
EFFICIENCY_SUMMARY_SCRIPT="${PROJECT_ROOT}/comparison_experiments/attack_types/write_efficiency_csv.py"

PYTHON="${PYTHON:-python3}"
RESULTS_DIR="${PROJECT_ROOT}/comparison_results/ctu13_scenario12"
WORK_DIR=""
KEEP_WORK=0
MAX_REAL_POSITIVE=3000
AUGMENTATION_COUNT=0
MAX_IDS_NEGATIVE=10000
CENTROID_EPOCHS=5
CLASSIFIER_EPOCHS=10
PRETRAIN_EPOCHS=10
PCA_DIM=128
RANDOM_STATE=42
SLICE_WINDOW=1
GENERATION_TARGET_MODE="nearest_historical_flow"
INTRA_SLICE_MODE="even"
SIZE_NOISE_SIGMA="0.10"
TIME_JITTER_RATIO="0.05"
TIME_JITTER_CAP="0.05"
SKIP_SMOTE=0
EFFICIENCY_OUTPUT_FILENAME="ctu13_scenario12_efficiency_comparison.csv"

usage() {
    cat <<'EOF'
用法：
  run_full_experiment.sh --ctu-pcap PATH --ids-csv PATH [选项]

必需参数：
  --ctu-pcap PATH          CTU-13 场景 12 的 botnet-capture PCAP
  --ids-csv PATH           IDS-2017 已标注流 CSV

可选参数：
  --results-dir PATH       最终结果目录（默认 comparison_results/ctu13_scenario12）
  --work-dir PATH          指定中间工作目录；未指定时使用临时目录
  --keep-work              流程结束后保留中间文件，便于排查
  --max-real-positive N    预训练使用的真实 CTU-13 正类上限（默认 3000）
  --augmentation-count N  可选，覆盖按上一窗口流数计算的增强数量（默认自动使用）
  --max-ids-negative N     IDS-2017 负类总量上限并分层抽样（默认 10000）
  --centroid-epochs N      质心 Transformer 训练轮数（默认 5）
  --pretrain-epochs N      基础分类器预训练轮数（默认 10）
  --epochs N               最终分类器训练轮数（默认 10）
  --pca-dim N              分类器 PCA 维度，0 表示不降维（默认 128）
  --slice-window SECONDS   流内时间切片粒度（默认 1 秒）
  --generation-target-mode MODE
                           nearest_historical_flow（默认）或 absolute_centroid
  --intra-slice-mode MODE  even/random（随机分配，默认兼容名称为 even）或 jitter
  --size-noise-sigma X     jitter包长权重扰动标准差（默认 0.10）
  --time-jitter-ratio X    jitter时间标准差占切片比例（默认 0.05）
  --time-jitter-cap SEC    jitter时间标准差上限秒数（默认 0.05）
  --skip-smote              消融实验使用：跳过 SMOTE 对照组
  --random-state N         随机种子（默认 42）
  -h, --help               显示帮助

示例：
  ./run_full_experiment.sh \
    --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
    --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
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
        --ctu-pcap)
            require_value "$@"
            CTU_PCAP="$2"
            shift 2
            ;;
        --ids-csv)
            require_value "$@"
            IDS_CSV="$2"
            shift 2
            ;;
        --results-dir)
            require_value "$@"
            RESULTS_DIR="$2"
            shift 2
            ;;
        --work-dir)
            require_value "$@"
            WORK_DIR="$2"
            shift 2
            ;;
        --keep-work)
            KEEP_WORK=1
            shift
            ;;
        --max-real-positive)
            require_value "$@"
            MAX_REAL_POSITIVE="$2"
            shift 2
            ;;
        --augmentation-count)
            require_value "$@"
            AUGMENTATION_COUNT="$2"
            shift 2
            ;;
        --max-ids-negative)
            require_value "$@"
            MAX_IDS_NEGATIVE="$2"
            shift 2
            ;;
        --epochs)
            require_value "$@"
            CLASSIFIER_EPOCHS="$2"
            shift 2
            ;;
        --centroid-epochs)
            require_value "$@"
            CENTROID_EPOCHS="$2"
            shift 2
            ;;
        --pretrain-epochs)
            require_value "$@"
            PRETRAIN_EPOCHS="$2"
            shift 2
            ;;
        --pca-dim)
            require_value "$@"
            PCA_DIM="$2"
            shift 2
            ;;
        --random-state)
            require_value "$@"
            RANDOM_STATE="$2"
            shift 2
            ;;
        --slice-window)
            require_value "$@"
            SLICE_WINDOW="$2"
            shift 2
            ;;
        --generation-target-mode)
            require_value "$@"
            GENERATION_TARGET_MODE="$2"
            shift 2
            ;;
        --intra-slice-mode)
            require_value "$@"
            INTRA_SLICE_MODE="$2"
            shift 2
            ;;
        --size-noise-sigma)
            require_value "$@"
            SIZE_NOISE_SIGMA="$2"
            shift 2
            ;;
        --time-jitter-ratio)
            require_value "$@"
            TIME_JITTER_RATIO="$2"
            shift 2
            ;;
        --time-jitter-cap)
            require_value "$@"
            TIME_JITTER_CAP="$2"
            shift 2
            ;;
        --skip-smote)
            SKIP_SMOTE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "未知参数：$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

: "${CTU_PCAP:?缺少 --ctu-pcap}"
: "${IDS_CSV:?缺少 --ids-csv}"

if ! awk "BEGIN { exit !(${SLICE_WINDOW} > 0) }"; then
    echo "--slice-window 必须大于 0" >&2
    exit 2
fi
if [[ "${GENERATION_TARGET_MODE}" != "absolute_centroid" && "${GENERATION_TARGET_MODE}" != "nearest_historical_flow" ]]; then
    echo "--generation-target-mode 必须是 absolute_centroid 或 nearest_historical_flow" >&2
    exit 2
fi
if [[ "${INTRA_SLICE_MODE}" != "even" && "${INTRA_SLICE_MODE}" != "random" && "${INTRA_SLICE_MODE}" != "jitter" ]]; then
    echo "--intra-slice-mode 必须是 even、random 或 jitter" >&2
    exit 2
fi
for VALUE_NAME in SIZE_NOISE_SIGMA TIME_JITTER_RATIO TIME_JITTER_CAP; do
    VALUE="${!VALUE_NAME}"
    if ! awk "BEGIN { exit !(${VALUE} >= 0) }"; then
        echo "--${VALUE_NAME//_/-} 必须大于或等于 0" >&2
        exit 2
    fi
done

if ! command -v "${PYTHON}" >/dev/null 2>&1; then
    echo "找不到可执行 Python：${PYTHON}。可通过 PYTHON=/path/to/python 指定。" >&2
    exit 1
fi

if [[ -z "${WORK_DIR}" ]]; then
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ctu13_scenario12.XXXXXX")"
    OWN_WORK_DIR=1
else
    mkdir -p "${WORK_DIR}"
    OWN_WORK_DIR=0
fi

cleanup() {
    # 默认只清理本脚本创建的工作目录；--keep-work 用于失败排查。
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
CLASSIFIER_WORK_DIR="${WORK_DIR}/classifier"
METRICS_DIR="${WORK_DIR}/efficiency_metrics"
LABELED_CTU_CSV="${INPUT_DIR}/ctu13_s12_botnet_labeled.csv"
RAW_CTU_CSV="${INPUT_DIR}/ctu13_s12_botnet.csv"
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

echo "[1/6] 将 CTU-13 PCAP 转换为项目 CSV"
measure_phase feature_extraction generated "${PROJECT_ROOT}/src/UnifiedPcapToCSV.py" \
    -i "${CTU_PCAP}" \
    -o "${RAW_CTU_CSV}"

echo "[2/6] 添加 CTU-13 Botnet 标签和场景元数据"
measure_phase feature_extraction generated "${SCRIPT_DIR}/annotate_ctu13_csv.py" \
    --input_csv "${RAW_CTU_CSV}" \
    --output_csv "${LABELED_CTU_CSV}" \
    --scenario 12 \
    --family Unknown

echo "[3/6] 按流起始时间切分 CTU-13，隔离生成模型的测试阶段"
measure_phase feature_extraction generated "${SCRIPT_DIR}/split_ctu_csv_by_time.py" \
    --input_csv "${LABELED_CTU_CSV}" \
    --output_dir "${SPLIT_DIR}" \
    --train_ratio 0.6 \
    --calib_ratio 0.2 \
    --macro_window 60 \
    --min_packets 2

# 原始未标注 CSV 已不再需要，减少工作区占用。
rm -f "${RAW_CTU_CSV}"

echo "[4/6] 在 CTU-13 训练部分训练质心预测模型并单步生成 Botnet 流"
measure_phase feature_extraction generated "${PROJECT_ROOT}/src/drift_prediction/extract_window_centroids.py" \
    --input_csv "${SPLIT_DIR}/ctu13_train.csv" \
    --output_dir "${CENTROID_WINDOWS_DIR}" \
    --macro_window 60 \
    --slice_window "${SLICE_WINDOW}" \
    --max_slices 60 \
    --min_packets 2
measure_phase feature_extraction generated "${PROJECT_ROOT}/src/drift_prediction/build_centroid_dataset.py" \
    --centroid_dir "${CENTROID_WINDOWS_DIR}" \
    --output_dir "${CENTROID_DATASET_DIR}" \
    --history_mode expanding \
    --exclude_last_per_label
measure_phase model_training generated "${PROJECT_ROOT}/src/drift_prediction/train_centroid_transformer.py" \
    --dataset_dir "${CENTROID_DATASET_DIR}" \
    --output_dir "${CENTROID_MODEL_DIR}" \
    --epochs "${CENTROID_EPOCHS}"
# 生成法只使用训练区间最后一个完整宏观窗口的流；增强数量默认等于该窗口流数。
SEED_FLOW_COUNT="$("${PYTHON}" -c 'import pandas as pd,sys; m=pd.read_csv(sys.argv[1]); s=m[m["label"]=="Botnet"]; print(int((s["window_start"]==s["window_start"].max()).sum()))' "${CENTROID_WINDOWS_DIR}/flow_bank.csv")"
if [[ "${SEED_FLOW_COUNT}" -le 0 ]]; then
    echo "训练区间最后窗口没有有效 Botnet 种子流" >&2
    exit 1
fi
if [[ "${AUGMENTATION_COUNT}" -le 0 ]]; then
    AUGMENTATION_COUNT="${SEED_FLOW_COUNT}"
fi
if [[ "${AUGMENTATION_COUNT}" -gt "${SEED_FLOW_COUNT}" ]]; then
    echo "--augmentation-count 不能超过上一窗口有效流数 ${SEED_FLOW_COUNT}" >&2
    exit 1
fi
echo "生成参数：seed_flows=${SEED_FLOW_COUNT}, mode=single_step, target=${AUGMENTATION_COUNT}"
measure_phase traffic_generation generated "${PROJECT_ROOT}/src/drift_prediction/generate_single_step_from_centroid_prediction.py" \
    --input_csv "${SPLIT_DIR}/ctu13_train.csv" \
    --centroid_dir "${CENTROID_WINDOWS_DIR}" \
    --model_path "${CENTROID_MODEL_DIR}/model.pt" \
    --output_dir "${GENERATED_DIR}" \
    --label Botnet \
    --num_flows "${SEED_FLOW_COUNT}" \
    --min_packets 2 \
    --slice_window "${SLICE_WINDOW}" \
    --target_profile_mode "${GENERATION_TARGET_MODE}" \
    --intra_slice_mode "${INTRA_SLICE_MODE}" \
    --size_noise_sigma "${SIZE_NOISE_SIGMA}" \
    --time_jitter_ratio "${TIME_JITTER_RATIO}" \
    --time_jitter_cap "${TIME_JITTER_CAP}" \
    --random_state "${RANDOM_STATE}"

GENERATED_CSV="${GENERATED_DIR}/generated_single_step_Botnet_${SEED_FLOW_COUNT}flows.csv"
if [[ ! -f "${GENERATED_CSV}" ]]; then
    echo "生成阶段没有输出合并 CSV：${GENERATED_CSV}" >&2
    exit 1
fi

# 按分类器相同的 min_packets=2 规则计算有效生成流，保证两种增强方法数量一致。
GENERATED_VALID_COUNT="$("${PYTHON}" -c 'import csv,json,sys; f=open(sys.argv[1],newline="",encoding="utf-8"); r=csv.DictReader(f); print(sum(1 for x in r if x["layer"]=="behavior" and int(json.loads(x["encoding_header"]).get("packet_count",0))>=2)); f.close()' "${GENERATED_CSV}")"
if [[ "${GENERATED_VALID_COUNT}" -le 0 ]]; then
    echo "合并生成 CSV 中没有满足 min_packets=2 的有效流" >&2
    exit 1
fi
EFFECTIVE_AUGMENTATION_COUNT="${AUGMENTATION_COUNT}"
if [[ "${GENERATED_VALID_COUNT}" -lt "${AUGMENTATION_COUNT}" ]]; then
    EFFECTIVE_AUGMENTATION_COUNT="${GENERATED_VALID_COUNT}"
    echo "警告：有效生成流只有 ${GENERATED_VALID_COUNT} 条；SMOTE 和生成法都改用该数量进行公平比较。"
fi

echo "[5/6] 运行共同预训练、SMOTE 和流量重组生成两种增强微调实验"
RUN_ARGS=(
    --ctu_csv "${LABELED_CTU_CSV}"
    --ids_csv "${IDS_CSV}"
    --generated_input "${GENERATED_CSV}"
    --results_dir "${RESULTS_DIR}"
    --max_real_positive "${MAX_REAL_POSITIVE}"
    --augmentation_count "${EFFECTIVE_AUGMENTATION_COUNT}"
    --epochs "${CLASSIFIER_EPOCHS}"
    --pretrain_epochs "${PRETRAIN_EPOCHS}"
    --pca_dim "${PCA_DIM}"
    --random_state "${RANDOM_STATE}"
    --efficiency_dir "${METRICS_DIR}"
    --work_dir "${CLASSIFIER_WORK_DIR}"
)
if [[ -n "${MAX_IDS_NEGATIVE}" ]]; then
    RUN_ARGS+=(--max_ids_negative "${MAX_IDS_NEGATIVE}")
fi
if [[ "${SKIP_SMOTE}" -eq 1 ]]; then
    RUN_ARGS+=(--skip-smote)
fi
"${PYTHON}" "${SCRIPT_DIR}/run_experiment.py" "${RUN_ARGS[@]}"

echo "[6/6] 完成"
echo "最终结果：${RESULTS_DIR}/ctu13_scenario12_method_comparison.csv"
"${PYTHON}" "${EFFICIENCY_SUMMARY_SCRIPT}" \
    --metrics-dir "${METRICS_DIR}" \
    --attack "Botnet" \
    --output "${RESULTS_DIR}/${EFFICIENCY_OUTPUT_FILENAME}"
echo "效率结果：${RESULTS_DIR}/${EFFICIENCY_OUTPUT_FILENAME}"
if [[ "${KEEP_WORK}" -eq 1 || "${OWN_WORK_DIR}" -eq 0 ]]; then
    echo "中间工作目录：${WORK_DIR}"
else
    echo "中间工作目录已清理"
fi
