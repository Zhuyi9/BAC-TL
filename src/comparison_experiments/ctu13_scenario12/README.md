# CTU-13 场景 12 跨数据集增强实验

本目录内部执行三种训练阶段，但最终结果只比较两种增强方法：

1. `none`：只使用少量真实 CTU-13 Botnet 流，作为共同的预训练模型，并作为无增强直接测试基线写入最终对比表；
2. `smote`：在同一批真实 Botnet 行为向量上使用 SMOTE；
3. `generated`：加入由 CTU-13 Botnet 流重组生成的样本。

## 一键运行完整流程

从项目根目录执行：

```bash
chmod +x comparison_experiments/ctu13_scenario12/run_full_experiment.sh
comparison_experiments/ctu13_scenario12/run_full_experiment.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

脚本按以下顺序执行：PCAP 转换、Botnet 标注、完整宏观窗口切分、质心模型训练、单步预测并
合并 Botnet 流、`none/SMOTE/generated` 三阶段分类训练和最终结果汇总。默认中间文件
使用临时目录并自动删除；只保留：

```text
comparison_results/ctu13_scenario12/ctu13_scenario12_method_comparison.csv
comparison_results/ctu13_scenario12/ctu13_scenario12_efficiency_comparison.csv
```

排查失败时加 `--keep-work`，脚本会打印中间工作目录。正式运行建议使用 Python 3.13：

```bash
PYTHON=python3 comparison_experiments/ctu13_scenario12/run_full_experiment.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

正类是 CTU-13 场景 12 的公开 Botnet-only PCAP。README 明确记录该 Bot 使用 P2P
协议，并且样本名称未确定（`Unknown`）。负类是
`csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv` 中的全部
IDS-2017 流量，原始标签保留，但二分类时统一设为 0。因此 DoS、BENIGN、Unknown
等都作为负类，不应把这个实验解释为同一网络环境中的 CTU-13 场景内检测。

当前文件的流级统计为 `100001` 条流：`BENIGN=18517`、`DoS=81456`、
`Unknown=28`。按 `min_packets=2` 过滤后会排除 1798 条单包流；如果不传
`--max_ids_negative`，其余负类都会参与切分。

## 1. 给 CTU-13 CSV 加标签

```bash
python3 comparison_experiments/ctu13_scenario12/annotate_ctu13_csv.py \
  --input_csv data/ctu13_scenario12/ctu13_s12_botnet.csv \
  --output_csv data/ctu13_scenario12/ctu13_s12_botnet_labeled.csv \
  --scenario 12 \
  --family Unknown
```

`UnifiedPcapToCSV.py` 先将 PCAP 转换为 `ctu13_s12_botnet.csv`。标注脚本以流为单位
把所有记录标记为 `Botnet`，并增加 `source_label`、`binary_label`、`dataset`、
`scenario`、`family` 字段。

场景 12 的原始 PCAP 转换示例：

```bash
mkdir -p comparison_work/ctu13_scenario12/input
python3 src/UnifiedPcapToCSV.py \
  -i pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  -o comparison_work/ctu13_scenario12/input/ctu13_s12_botnet.csv
python3 comparison_experiments/ctu13_scenario12/annotate_ctu13_csv.py \
  --input_csv comparison_work/ctu13_scenario12/input/ctu13_s12_botnet.csv \
  --output_csv comparison_work/ctu13_scenario12/input/ctu13_s12_botnet_labeled.csv \
  --scenario 12 --family Unknown
```

## 2. 构造三种分类数据集

下面命令只生成数据集，不训练模型。预训练阶段使用
`--max_real_positive 3000` 和约 `6000` 条训练负类；SMOTE 与生成方法在此基础上
各自增加上一完整时间窗口的有效流数量（场景 12 当前约 131--132 条），数量保持一致。

```bash
python3 comparison_experiments/ctu13_scenario12/build_mixed_behavior_dataset.py \
  --ctu_csv data/ctu13_scenario12/ctu13_s12_botnet_labeled.csv \
  --ids_csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv \
  --output_dir comparison_work/ctu13_scenario12/none \
  --augmentation none \
  --max_real_positive 3000
```

SMOTE 和生成方法只需把 `--augmentation` 改为 `smote` 或 `generated`。生成方法还需
提供重组生成并合并后的 CSV：

```bash
  --generated_input path/to/generated_single_step_Botnet_132flows.csv \
  --augmentation_count 132
```

`generated_input` 中满足 `min_packets` 的有效流数量必须不少于
`augmentation_count`；脚本会从中固定抽取指定数量，保证与 SMOTE 新增数量一致。

## 3. 生成 CTU-13 Botnet 增强流

生成模型只使用 CTU-13 训练部分的 `Botnet` 流，不使用 IDS-2017 负类。当前流程只
预测训练区间最后一个完整窗口后的一个下一窗口，不将预测结果递归作为后续输入。种子
数量等于该上一窗口的有效流数（当前约 132 条），每条种子只重组一次。
所有中间目录都建议放在 `comparison_work`，不要放到结果目录：

```bash
python3 comparison_experiments/ctu13_scenario12/split_ctu_csv_by_time.py \
  --input_csv comparison_work/ctu13_scenario12/input/ctu13_s12_botnet_labeled.csv \
  --output_dir comparison_work/ctu13_scenario12/input/time_split
python3 src/drift_prediction/extract_window_centroids.py \
  --input_csv comparison_work/ctu13_scenario12/input/time_split/ctu13_train.csv \
  --output_dir comparison_work/ctu13_scenario12/centroid_windows \
  --macro_window 60 --slice_window 1 --max_slices 60 --min_packets 2
python3 src/drift_prediction/build_centroid_dataset.py \
  --centroid_dir comparison_work/ctu13_scenario12/centroid_windows \
  --output_dir comparison_work/ctu13_scenario12/centroid_dataset \
  --history_mode expanding --exclude_last_per_label
python3 src/drift_prediction/train_centroid_transformer.py \
  --dataset_dir comparison_work/ctu13_scenario12/centroid_dataset \
  --output_dir comparison_work/ctu13_scenario12/centroid_model \
  --epochs 5
python3 src/drift_prediction/generate_single_step_from_centroid_prediction.py \
  --input_csv comparison_work/ctu13_scenario12/input/time_split/ctu13_train.csv \
  --centroid_dir comparison_work/ctu13_scenario12/centroid_windows \
  --model_path comparison_work/ctu13_scenario12/centroid_model/model.pt \
  --output_dir comparison_work/ctu13_scenario12/generated \
  --label Botnet --num_flows 0 --min_packets 2
```

生成脚本输出的 `generated_single_step_Botnet_<上一窗口流数>flows.csv` 作为
`run_experiment.py` 的 `--generated_input`。脚本还会在分类前统计实际有效生成流；若
重组后因控制流过滤导致数量少于目标，SMOTE 和生成法会同时采用实际有效数量，保证
比较样本数一致。生成完成并确认最终比较 CSV 写入后，`comparison_work/ctu13_scenario12`
可以整体删除。

训练、校准、测试均按每个数据源自身的相对时间划分：CTU-13 和 IDS-2017 各自按
`60%/20%/20%` 划分，再分别合并对应部分。CTU-13 的边界只在完整 60 秒宏观窗口之间
切分；质心预测器也按唯一 `target_window_start` 的时间顺序切分，绝不把同一目标窗口
拆到不同集合。绝对时间戳不参与跨数据源排序，避免 2011 年和 2017 年的时间差造成错误切分。

测试集负类不再额外重采样，沿用 IDS-2017 时间切分后的原始标签数量。当前数据下，
过滤 `min_packets=2` 后通常约为 `BENIGN=223、DoS=1777`；该分布会写入
`dataset_summary.json`，便于解释总体指标。

## 4. 训练

```bash
python3 src/classification/train_binary_behavior_classifier.py \
  --dataset_dir comparison_work/ctu13_scenario12/smote \
  --output_dir comparison_work/ctu13_scenario12/smote_result \
  --epochs 10 --pca_dim 128
```

正式增强方法对比使用统一入口（生成 CSV 后，将下面的 `N` 替换为生成摘要中的上一窗口
种子流数量；一键脚本会自动完成这个替换以及有效流数量校正）：

```bash
python3 comparison_experiments/ctu13_scenario12/run_experiment.py \
  --ctu_csv comparison_work/ctu13_scenario12/input/ctu13_s12_botnet_labeled.csv \
  --ids_csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv \
  --generated_input path/to/generated_single_step_Botnet_Nflows.csv \
  --results_dir comparison_results/ctu13_scenario12 \
  --max_real_positive 3000 --augmentation_count N --max_ids_negative 10000 \
  --epochs 10 --pca_dim 128
```

运行器先按 `none` 训练基础分类器预训练模型，再按 `smote -> generated` 顺序加载该
模型并微调。预训练模型和两个微调模型使用同一标准化/PCA 参数；分类训练仅使用
`WeightedRandomSampler` 平衡批次，损失函数为标准 `BCEWithLogitsLoss`。默认工作目录是
临时目录，结束时自动删除；结果目录只写入 `ctu13_scenario12_method_comparison.csv`，
其中包含 `none`、`smote`、`generated` 三行，以及单独的 `generated_vs_none` 和
`generated_vs_smote` 涨幅行。混淆矩阵
以 `TN`、`FP`、`FN`、`TP` 四列保存；最终 CSV 从原来的 `threshold` 位置开始只保留
`augmentation_count`（新增数据量）。

最终比较结果建议只保留：

```text
comparison_results/ctu13_scenario12/ctu13_scenario12_method_comparison.csv
```

数据集、模型、预测明细和训练历史属于中间文件，正式运行器完成后应删除；若需要
复核，可通过命令行参数显式保留工作目录。

## 5. 结果解释

主结果是 `CTU-13 Botnet` 对 `IDS-2017 全部标签`。结果表中还应按
`source_label` 统计误报，例如 BENIGN、DoS、PortScan 等，避免只看总体 Accuracy。
这个实验使用跨数据集负类，结论应表述为跨数据集增强效果，而不是 CTU-13 同域背景
流量检测性能。
