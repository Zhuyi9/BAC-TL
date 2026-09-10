#!/usr/bin/env bash
# 将 pseudo_future cosine v3 方法推广到 DoS、Scan、XSS 和 Zeus。
# DoS 使用 BENIGN-first 非目标负类，其余组保留非目标标签分层抽样。
# 每个攻击类型使用独立的临时工作目录、固定伪未来数据集和结果目录。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPOSITORY_ROOT="$(cd "${PROJECT_ROOT}/.." && pwd)"
DATA_ROOT="${BAC_TL_DATA_ROOT:-${REPOSITORY_ROOT}/data/raw}"
PYTHON="${PYTHON:-python3}"
IDS_CSV="${DATA_ROOT}/csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv"
ATTACKS=(dos scan xss zeus)
HORIZONS=3
MIX_RATIO=0.5
RANDOM_STATE=42
MAX_REAL_POSITIVE=3000
AUGMENTATION_COUNT=0
MAX_IDS_NEGATIVE=10000
TRAIN_NEGATIVE_RATIO=2.0
CENTROID_EPOCHS=5
PRETRAIN_EPOCHS=10
CLASSIFIER_EPOCHS=10
PCA_DIM=128
KEEP_WORK=0
DATASET_ROOT="${PROJECT_ROOT}/comparison_datasets/attack_types"
RESULT_ROOT="${PROJECT_ROOT}/comparison_results/attack_types"

usage() {
    cat <<'EOF'
用法：
  run_pseudo_future_experiments.sh [选项]

按顺序运行 DoS、Scan、XSS、Zeus 四组 pseudo-future cosine 实验。

选项：
  --ids-csv PATH              IDS-2017 流 CSV
  --attacks LIST              逗号分隔的子集，例如 scan,xss
  --horizons N                每组最多构造的伪未来窗口数，默认 3
  --mix-ratio X               测试窗口中 generated 正类比例，默认 0.5
  --max-real-positive N       真实训练正类上限，默认 3000
  --augmentation-count N     训练 generated/SMOTE 数量；0 表示自动按有效流数
  --max-ids-negative N        IDS-2017 负类候选上限，默认 10000
  --train-negative-ratio X    训练负类/真实正类比例，默认 2.0
  --dataset-root PATH         固定伪未来数据集根目录
  --result-root PATH          分类结果根目录
  --centroid-epochs N         质心 Transformer 轮数，默认 5
  --pretrain-epochs N         分类器预训练轮数，默认 10
  --epochs N                  分类器微调轮数，默认 10
  --pca-dim N                 PCA 维度，默认 128
  --random-state N            采样随机种子，默认 42
  --keep-work                 保留每组中间转换和模型文件
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "${2}" ]]; then
        echo "参数 $1 需要一个值" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ids-csv) require_value "$@"; IDS_CSV="$2"; shift 2 ;;
        --attacks) require_value "$@"; IFS=',' read -r -a ATTACKS <<< "$2"; shift 2 ;;
        --horizons) require_value "$@"; HORIZONS="$2"; shift 2 ;;
        --mix-ratio) require_value "$@"; MIX_RATIO="$2"; shift 2 ;;
        --max-real-positive) require_value "$@"; MAX_REAL_POSITIVE="$2"; shift 2 ;;
        --augmentation-count) require_value "$@"; AUGMENTATION_COUNT="$2"; shift 2 ;;
        --max-ids-negative) require_value "$@"; MAX_IDS_NEGATIVE="$2"; shift 2 ;;
        --train-negative-ratio) require_value "$@"; TRAIN_NEGATIVE_RATIO="$2"; shift 2 ;;
        --dataset-root) require_value "$@"; DATASET_ROOT="$2"; shift 2 ;;
        --result-root) require_value "$@"; RESULT_ROOT="$2"; shift 2 ;;
        --centroid-epochs) require_value "$@"; CENTROID_EPOCHS="$2"; shift 2 ;;
        --pretrain-epochs) require_value "$@"; PRETRAIN_EPOCHS="$2"; shift 2 ;;
        --epochs) require_value "$@"; CLASSIFIER_EPOCHS="$2"; shift 2 ;;
        --pca-dim) require_value "$@"; PCA_DIM="$2"; shift 2 ;;
        --random-state) require_value "$@"; RANDOM_STATE="$2"; shift 2 ;;
        --keep-work) KEEP_WORK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
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
if ! "${PYTHON}" - "${HORIZONS}" "${MIX_RATIO}" <<'PY'
import sys
horizons, ratio = int(sys.argv[1]), float(sys.argv[2])
if horizons <= 0 or not 0.0 <= ratio <= 1.0:
    raise ValueError
PY
then
    echo "--horizons 必须大于 0，--mix-ratio 必须在 [0,1] 内" >&2
    exit 2
fi

cd "${PROJECT_ROOT}"

count_windows() {
    # 只统计有效 behavior 流所在的完整宏观窗口，避免请求不存在的未来窗口。
    "${PYTHON}" - "$1" "$2" <<'PY'
import csv, json, math, sys
path, window = sys.argv[1], float(sys.argv[2])
windows = set()
with open(path, encoding="utf-8", newline="") as handle:
    for row in csv.DictReader(handle):
        if row.get("layer") != "behavior":
            continue
        try:
            packets = int(json.loads(row.get("encoding_header") or "{}").get("packet_count", 0))
            timestamp = float(row["timestamp"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if packets >= 2:
            windows.add(math.floor(timestamp / window) * window)
print(len(windows))
PY
}

count_valid_flows() {
    "${PYTHON}" - "$1" <<'PY'
import csv, json, sys
count = 0
with open(sys.argv[1], encoding="utf-8", newline="") as handle:
    for row in csv.DictReader(handle):
        if row.get("layer") != "behavior":
            continue
        try:
            packets = int(json.loads(row.get("encoding_header") or "{}").get("packet_count", 0))
        except (TypeError, ValueError, json.JSONDecodeError):
            packets = 0
        count += packets >= 2
print(count)
PY
}

run_one() {
    local attack="$1"
    local label pcap dataset_name description macro negative_mode negative_description
    case "${attack}" in
        dos)
            label="DoS"; pcap=""; dataset_name="IDS-2017 Wednesday DoS";
            description="IDS-2017 DoS traffic"; macro=60; negative_mode="benign_first";
            negative_description="IDS-2017 Wednesday BENIGN-first non-DoS labels" ;;
        scan)
            label="Scan"; pcap="${DATA_ROOT}/pcap/scan/web_scan.pcap";
            dataset_name="Web Scan PCAP"; description="Web scan attack traffic"; macro=30; negative_mode="stratified";
            negative_description="IDS-2017 Wednesday stratified non-target labels" ;;
        xss)
            label="XSS"; pcap="${DATA_ROOT}/pcap/xss/XSS.pcap";
            dataset_name="XSS PCAP"; description="XSS web attack traffic"; macro=60; negative_mode="stratified";
            negative_description="IDS-2017 Wednesday stratified non-target labels" ;;
        zeus)
            label="Zeus"; pcap="${DATA_ROOT}/pcap/trojan/Malware/Zeus.pcap";
            dataset_name="Trojan Malware PCAP"; description="Zeus malware traffic"; macro=60; negative_mode="stratified";
            negative_description="IDS-2017 Wednesday stratified non-target labels" ;;
        *) echo "不支持的攻击类型：${attack}" >&2; exit 2 ;;
    esac

    local dataset_dir="${DATASET_ROOT}/${attack}/pseudo_future_cosine_stratified_v3"
    local results_dir="${RESULT_ROOT}/${attack}/pseudo_future_cosine_stratified_v3"
    local work_dir
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/${attack}_pseudo_future.XXXXXX")"
    local input_dir="${work_dir}/input"
    local split_dir="${input_dir}/time_split"
    local centroid_dir="${work_dir}/centroid_windows"
    local centroid_dataset="${work_dir}/centroid_dataset"
    local centroid_model="${work_dir}/centroid_model"
    local generated_dir="${work_dir}/training_generation"
    local efficiency_dir="${work_dir}/efficiency_metrics"
    # 目标目录只保存本次固定数据集和最终 CSV；清除上一次同名运行的残留文件。
    rm -rf "${dataset_dir}" "${results_dir}"
    mkdir -p "${input_dir}" "${efficiency_dir}" "${dataset_dir}" "${results_dir}"

    local raw_csv="${input_dir}/${attack}.csv"
    local labeled_csv="${input_dir}/${attack}_labeled.csv"
    local train_csv test_csv
    if [[ "${attack}" == "dos" ]]; then
        echo "[${attack}] 从 IDS-2017 筛选 DoS 正类"
        "${PYTHON}" "${SCRIPT_DIR}/filter_labeled_flows.py" \
            --input_csv "${IDS_CSV}" --output_csv "${labeled_csv}" --label "${label}"
    else
        if [[ ! -f "${pcap}" ]]; then
            echo "找不到 ${attack} 正类 PCAP：${pcap}" >&2
            return 1
        fi
        echo "[${attack}] PCAP 转换并添加 ${label} 标签"
        "${PYTHON}" src/UnifiedPcapToCSV.py -i "${pcap}" -o "${raw_csv}"
        "${PYTHON}" "${SCRIPT_DIR}/annotate_attack_csv.py" \
            --input_csv "${raw_csv}" --output_csv "${labeled_csv}" \
            --label "${label}" --dataset "${dataset_name}" --attack_key "${attack}"
    fi

    echo "[${attack}] 按 ${macro} 秒完整窗口切分"
    "${PYTHON}" "${PROJECT_ROOT}/comparison_experiments/ctu13_scenario12/split_ctu_csv_by_time.py" \
        --input_csv "${labeled_csv}" --output_dir "${split_dir}" --output_prefix "${attack}" \
        --train_ratio 0.6 --calib_ratio 0.2 --macro_window "${macro}" --min_packets 2
    train_csv="${split_dir}/${attack}_train.csv"
    test_csv="${split_dir}/${attack}_test.csv"
    local max_slices
    max_slices="$("${PYTHON}" -c 'import math,sys; print(max(1, int(math.ceil(float(sys.argv[1])))))' "${macro}")"
    local test_windows
    test_windows="$(count_windows "${test_csv}" "${macro}")"
    local effective_horizons="${HORIZONS}"
    if [[ "${test_windows}" -lt "${effective_horizons}" ]]; then
        effective_horizons="${test_windows}"
    fi
    if [[ "${effective_horizons}" -le 0 ]]; then
        echo "${attack} 测试段没有可用的完整时间窗口，无法构造伪未来数据集" >&2
        return 1
    fi
    local valid_train
    valid_train="$(count_valid_flows "${train_csv}")"
    if [[ "${valid_train}" -le 0 ]]; then
        echo "${attack} 训练段没有满足 min_packets=2 的有效流" >&2
        return 1
    fi
    local effective_aug="${AUGMENTATION_COUNT}"
    if [[ "${effective_aug}" -le 0 || "${effective_aug}" -gt "${valid_train}" ]]; then
        effective_aug="${valid_train}"
        if [[ "${effective_aug}" -gt "${MAX_REAL_POSITIVE}" ]]; then
            effective_aug="${MAX_REAL_POSITIVE}"
        fi
    fi
    if [[ "${effective_aug}" -le 0 ]]; then
        echo "${attack} 无法确定有效增强数量" >&2
        return 1
    fi

    echo "[${attack}] 训练 ${macro} 秒窗口质心模型（${effective_horizons} 个伪未来窗口）"
    "${PYTHON}" src/drift_prediction/extract_window_centroids.py \
        --input_csv "${train_csv}" --output_dir "${centroid_dir}" \
        --macro_window "${macro}" --slice_window 1 --max_slices "${max_slices}" --min_packets 2
    local centroid_window_count
    centroid_window_count="$("${PYTHON}" -c 'import pandas as pd,sys; print(pd.read_csv(sys.argv[1])["window_start"].nunique())' "${centroid_dir}/centroid_metadata.csv")"
    if [[ "${centroid_window_count}" -lt 4 ]]; then
        echo "${attack} 训练段只有 ${centroid_window_count} 个宏观窗口；至少需要 4 个窗口才能顺序训练质心 Transformer" >&2
        return 1
    fi
    "${PYTHON}" src/drift_prediction/build_centroid_dataset.py \
        --centroid_dir "${centroid_dir}" --output_dir "${centroid_dataset}" \
        --history_mode expanding --exclude_last_per_label
    "${PYTHON}" src/drift_prediction/train_centroid_transformer.py \
        --dataset_dir "${centroid_dataset}" --output_dir "${centroid_model}" \
        --epochs "${CENTROID_EPOCHS}"

    echo "[${attack}] 构造固定伪未来测试集（direct + cosine + ${negative_mode} + random）"
    "${PYTHON}" "${PROJECT_ROOT}/comparison_experiments/ctu13_scenario12/pseudo_future/generate_pseudo_future_dataset.py" \
        --train_csv "${train_csv}" --test_positive_csv "${test_csv}" --ids_csv "${IDS_CSV}" \
        --centroid_dir "${centroid_dir}" --model_path "${centroid_model}/model.pt" \
        --output_dir "${dataset_dir}" --label "${label}" --horizons "${effective_horizons}" \
        --macro_window "${macro}" --slice_window 1 --max_slices "${max_slices}" --min_packets 2 \
        --mix_ratio "${MIX_RATIO}" --random_state "${RANDOM_STATE}" \
        --generation_mode direct --nearest_metric cosine --negative_mode "${negative_mode}" \
        --intra_slice_mode random --size_noise_sigma 0.1 --time_jitter_ratio 0.05 --time_jitter_cap 0.05 \
        --allow_seed_reuse

    echo "[${attack}] 生成训练阶段的 ${effective_aug} 条 generated 流"
    mkdir -p "${generated_dir}"
    "${PYTHON}" src/drift_prediction/generate_single_step_from_centroid_prediction.py \
        --input_csv "${train_csv}" --centroid_dir "${centroid_dir}" \
        --model_path "${centroid_model}/model.pt" --output_dir "${generated_dir}" \
        --label "${label}" --num_flows "${effective_aug}" --seed_scope all_history \
        --min_packets 2 --macro_window "${macro}" --slice_window 1 \
        --target_profile_mode nearest_historical_flow --nearest_metric cosine \
        --intra_slice_mode random --random_state "${RANDOM_STATE}"
    local generated_input
    generated_input="$(find "${generated_dir}" -maxdepth 1 -type f -name "generated_single_step_${label}_*flows.csv" | sort | tail -n 1)"
    if [[ -z "${generated_input}" || ! -f "${generated_input}" ]]; then
        echo "${attack} 没有找到训练 generated CSV" >&2
        return 1
    fi
    local generated_valid
    generated_valid="$(count_valid_flows "${generated_input}")"
    if [[ "${generated_valid}" -le 0 ]]; then
        echo "${attack} 训练 generated 没有有效流" >&2
        return 1
    fi
    if [[ "${generated_valid}" -lt "${effective_aug}" ]]; then
        effective_aug="${generated_valid}"
    fi

    echo "[${attack}] 运行 none、SMOTE、generated 分类对比"
    "${PYTHON}" "${PROJECT_ROOT}/comparison_experiments/ctu13_scenario12/run_experiment.py" \
        --positive_csv "${labeled_csv}" --ids_csv "${IDS_CSV}" \
        --generated_input "${generated_input}" --results_dir "${results_dir}" \
        --output_filename "${attack}_method_comparison.csv" \
        --experiment_name "${attack}_pseudo_future_cosine_stratified_v3" \
        --target_label "${label}" --target_description "${description}" \
        --positive_source "${dataset_name}" --negative_source_description "${negative_description}" \
        --window_size "${macro}" --max_real_positive "${MAX_REAL_POSITIVE}" \
        --augmentation_count "${effective_aug}" --max_ids_negative "${MAX_IDS_NEGATIVE}" \
        --train_negative_ratio "${TRAIN_NEGATIVE_RATIO}" --epochs "${CLASSIFIER_EPOCHS}" \
        --pretrain_epochs "${PRETRAIN_EPOCHS}" --pca_dim "${PCA_DIM}" \
        --random_state "${RANDOM_STATE}" --fixed_test_positive_csv "${dataset_dir}/pseudo_future_positive.csv" \
        --fixed_test_negative_csv "${dataset_dir}/ids_negative.csv" --efficiency_dir "${efficiency_dir}"
    "${PYTHON}" "${SCRIPT_DIR}/write_efficiency_csv.py" \
        --metrics-dir "${efficiency_dir}" --attack "${label}" \
        --output "${results_dir}/${attack}_efficiency_comparison.csv"
    echo "${attack} 结果：${results_dir}/${attack}_method_comparison.csv"
    echo "${attack} 效率：${results_dir}/${attack}_efficiency_comparison.csv"

    if [[ "${KEEP_WORK}" -eq 0 ]]; then
        rm -rf "${work_dir}"
    else
        echo "${attack} 中间工作目录：${work_dir}"
    fi
}

for attack in "${ATTACKS[@]}"; do
    run_one "${attack}"
done

echo "全部 pseudo-future cosine 实验完成。"
