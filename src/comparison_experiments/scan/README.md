# Scan 攻击流增强实验

该目录是 Scan 实验的独立使用入口。流程先建立真实 Scan 与 IDS-2017 背景组成的共同
预训练分类器，然后用 SMOTE 和基于时间窗口预测的流量重组方法分别增加正类流并微调，
最终结果只保留两种方法的对比。

## 数据与参数

- 正类 PCAP：`pcap/scan/web_scan.pcap`
- 正类标签：`Scan`
- 默认宏观时间窗口：30 秒
- 默认负类：`csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv`
- 结果文件：`comparison_results/attack_types/scan/scan_method_comparison.csv`
- 效率文件：`comparison_results/attack_types/scan/scan_efficiency_comparison.csv`

原始 Scan 捕获持续时间较短。默认使用 30 秒窗口，以便在严格时间顺序切分后保留足够
的连续质心训练样本；如需与其他实验一致，可通过 `--macro-window 60` 覆盖。

## 运行

从项目根目录运行：

```bash
comparison_experiments/scan/run_full_experiment.sh
```

参数可按需覆盖：

```bash
comparison_experiments/scan/run_full_experiment.sh \
  --macro-window 60 \
  --max-real-positive 3000 \
  --centroid-epochs 5
```

中间 CSV、质心数据、模型和预测文件默认全部写入临时目录并在结束时删除。最终只写入
`comparison_results/attack_types/scan/scan_method_comparison.csv` 和效率 CSV；后者按阶段
记录时间、CPU 占用率和内存使用量，并单独列出流量生成成本。使用
`--keep-work` 可在失败排查时保留中间目录。
