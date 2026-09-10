#!/usr/bin/env bash
set -euo pipefail

# orchestrator.sh
# 自动化管线：拆分大 pcap -> 并行转换为 CSV -> 合并 CSV -> 后处理（打标签、提取特征）
# 依赖：editcap (Wireshark), GNU parallel (可选), python3 和项目内脚本

usage(){
  cat <<EOF
Usage: $0 --pcap big.pcap [--outdir out_dir] [--packets-per-chunk 100000 --jobs 4]

Options:
  --pcap                输入大 pcap 文件路径
  --outdir              输出目录名（默认 ./csv_output；如果指定名称则创建 ./csv_output/<name>）
  --packets-per-chunk   每个拆分 pcap 包数量（默认 100000）
  --jobs                并行任务数（默认 4）
  --keep-chunks         保留中间拆分的 pcap 与 csv（默认删除以节省空间）
  --help
EOF
}

PCAP=""
OUTDIR="./csv_output"
OUTDIR_SUBDIR=""
DEFAULT_ROOT="./csv_output"
PACKETS=100000
JOBS=4
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap) PCAP="$2"; shift 2;;
    --outdir) OUTDIR_SUBDIR="$2"; shift 2;;
    --packets-per-chunk) PACKETS="$2"; shift 2;;
    --jobs) JOBS="$2"; shift 2;;
    --keep-chunks) KEEP=1; shift 1;;
    --help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ -z "$PCAP" ]]; then
  usage; exit 1
fi

if [[ -n "$OUTDIR_SUBDIR" ]]; then
  if [[ "$OUTDIR_SUBDIR" = /* ]]; then
    OUTDIR="$OUTDIR_SUBDIR"
  else
    OUTDIR="$DEFAULT_ROOT/$OUTDIR_SUBDIR"
  fi
fi

mkdir -p "$OUTDIR"
CHUNKS_DIR="$OUTDIR/pcap_chunks"
CSV_DIR="$OUTDIR/csv_chunks"
LOG_DIR="$OUTDIR/logs"
MERGED_CSV="$OUTDIR/merged.csv"

if ! python3 -c 'import dpkt' >/dev/null 2>&1; then
  echo "错误：python3 环境缺少 dpkt。请运行：python3 -m pip install dpkt"
  exit 1
fi

mkdir -p "$CHUNKS_DIR" "$CSV_DIR" "$LOG_DIR"

# echo "[1] 使用 editcap 将 $PCAP 拆分为每 ${PACKETS} 包一个文件（目录: ${CHUNKS_DIR}）"
# if ! command -v editcap >/dev/null 2>&1; then
#   echo "错误：找不到 editcap，请安装 Wireshark 工具集。"; exit 1
# fi

# editcap -c "$PACKETS" "$PCAP" "$CHUNKS_DIR/chunk_%04d.pcap"

# echo "[2] 并行将每个拆分的 pcap 转换为结构化 CSV（目录: ${CSV_DIR}）"

# if command -v parallel >/dev/null 2>&1; then
#   echo "(提示) 已检测到 GNU parallel，但为了兼容当前环境，采用安全的内部并发循环。"
# fi
# find "$CHUNKS_DIR" -name 'chunk_*.pcap' -print0 | while IFS= read -r -d '' pcapfile; do
#   base=$(basename "$pcapfile" .pcap)
#   out_csv="$CSV_DIR/$base.csv"
#   out_log="$LOG_DIR/$base.log"
#   python3 src/UnifiedPcapToCSV.py --input "$pcapfile" --output "$out_csv" > "$out_log" 2>&1 &
#   while [[ $(jobs -rp | wc -l) -ge "$JOBS" ]]; do
#     sleep 1
#   done
#  done
# wait

echo "[3] 合并所有 CSV 并重写 flow_id，确保 merged.csv 中的 flow_id 全局唯一"
python3 scripts/merge_chunk_csvs.py --input-dir "$CSV_DIR" --output "$MERGED_CSV"

# echo "[4] 运行标签映射（label_mapping.py）"
# python3 src/label_mapping.py --official_csv path/to/CIC_official.csv --my_csv "$MERGED_CSV" --output_csv "$OUTDIR/merged_labeled.csv"

# echo "[5] 运行特征提取（extract_features.py）"
# python3 src/extract_features.py --input_csv "$OUTDIR/merged_labeled.csv" --output_dir "$OUTDIR/features" --macro_window 60 --micro_slice 1 --seq_length 60

if [[ $KEEP -eq 0 ]]; then
  echo "清理中间文件..."
  rm -rf "$CHUNKS_DIR" "$CSV_DIR"
fi

echo "管线完成。输出文件位置："
echo "  合并 CSV: $MERGED_CSV"
echo "  打标签 CSV: $OUTDIR/merged_labeled.csv"
echo "  特征目录: $OUTDIR/features"

exit 0
