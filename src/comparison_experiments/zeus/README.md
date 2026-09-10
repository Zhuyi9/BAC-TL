# Zeus 攻击流增强实验

该目录是 Zeus 实验的独立使用入口，实验方法与 CTU-13 场景 12 保持一致：先用真实
Zeus 正类流和 IDS-2017 背景流训练共同的预训练分类器，再分别使用 SMOTE 和流量重组
生成流进行微调，最后只比较这两种增强方法。

## 数据与参数

- 正类 PCAP：`pcap/trojan/Malware/Zeus.pcap`
- 正类标签：`Zeus`
- 默认宏观时间窗口：60 秒
- 默认负类：`csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv`
- 结果文件：`comparison_results/attack_types/zeus/zeus_method_comparison.csv`
- 效率文件：`comparison_results/attack_types/zeus/zeus_efficiency_comparison.csv`

正类 PCAP 先转换为流级 CSV 并按时间顺序切分为训练、校准和测试部分。质心模型只使用
训练部分，预测训练末尾之后的一个窗口；生成流数量等于训练集最后一个完整窗口中的
有效 Zeus 流数。SMOTE 与生成方法使用相同的新增数量和同一个预训练模型。

## 运行

从项目根目录运行：

```bash
comparison_experiments/zeus/run_full_experiment.sh
```

也可以覆盖输入或训练参数：

```bash
comparison_experiments/zeus/run_full_experiment.sh \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv \
  --centroid-epochs 5 --pca-dim 128
```

默认中间数据和模型写入临时目录，流程结束后自动清理；正式结果目录只保留方法对比 CSV
和效率 CSV。效率 CSV 记录特征提取、质心/分类模型训练、模型检测以及流量生成各阶段的
时间、CPU 占用率和内存使用量。排查错误时可追加 `--keep-work` 保留中间工作目录。
