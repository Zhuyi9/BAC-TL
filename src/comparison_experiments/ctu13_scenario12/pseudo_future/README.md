# CTU-13 场景 12 伪未来测试集

该目录把训练阶段的质心预测转化为一个可重复使用的受控概念漂移测试集。
默认递归生成 3 个未来窗口。第一个窗口由训练段最后一组真实流重构，之后
以上一轮生成 CSV 重新计算的实际质心作为下一轮历史状态。训练增强流使用
最近历史目标流的片内模式：种子流较短时在源包耗尽处停止，较长时对目标流
末尾两个非空片做线性外推。每条流保留自己的包数，目标只影响时间片内的
包数、到达时间和链路层帧长度分布，再按 1 秒片内重构。

## 生成固定数据集

```bash
./comparison_experiments/ctu13_scenario12/pseudo_future/run_pseudo_future_experiment.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

若随后要直接运行固定测试集对比，请加上 `--keep-work`，这样训练/校准用的
标注 CTU CSV 会保存在输出目录的 `_work/input/ctu13_s12_botnet_labeled.csv`。

默认输出目录为 `comparison_datasets/ctu13_scenario12/pseudo_future_v1`。其中：

- `future_window_01/02/03_generated.csv`：递归生成的三个伪未来窗口；
- `generated_positive.csv`：三个窗口的生成正类；
- `real_positive.csv`：前三个真实测试窗口中未被生成流替换的正类；
- `pseudo_future_positive.csv`：混合后的固定测试正类；
- `ids_negative.csv`：从 IDS-2017 时间测试段分层抽样的负类；
- `pseudo_future_test.csv`：上述文件的合并查看版本；
- `future_window_metadata.csv`、`alpha_beta_summary.csv`：窗口、质心和漂移比例记录；
- `predicted_centroids.npy`、`actual_centroids.npy`：预测质心和重构后实际质心；
- `dataset_manifest.json`：文件大小和 SHA-256，保证之后运行使用同一份数据。

默认前三个真实测试窗口的正类数量为 153、148、92，因此会分别混合
77/76、74/74、46/46 条生成/真实流，共 393 条正类；负类默认抽取 393 条。

## 使用固定测试集运行分类对比

`run_fixed_test_comparison.sh` 要求另行提供仅用于训练增强的 generated 输入，
以避免把伪未来测试流泄漏回训练集：

```bash
./comparison_experiments/ctu13_scenario12/pseudo_future/run_fixed_test_comparison.sh \
  --ctu-csv comparison_datasets/ctu13_scenario12/pseudo_future_v1/_work/input/ctu13_s12_botnet_labeled.csv \
  --generated-input /path/to/training_generated.csv
```

脚本会把 `pseudo_future_positive.csv` 和 `ids_negative.csv` 传给现有数据集构造器的
固定测试参数，`none`、`SMOTE` 和 `generated` 三个方法共享同一测试集。

也可以直接运行一键脚本完成“构造伪未来数据集 + 生成训练增强流 + CTU-13
分类对比”：

```bash
./comparison_experiments/ctu13_scenario12/pseudo_future/run_ctu13_pseudo_future_experiment.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

一键脚本默认清理训练转换中间文件，只保留固定测试数据和分类结果；调试或
需要之后复用训练模型时加 `--keep-work`。
