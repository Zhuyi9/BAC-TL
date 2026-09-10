# DoS 攻击流增强实验

该目录是最初 IDS-2017 DoS 实验的独立入口。脚本从
`csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv` 中按 flow 的
behavior 标签拆出 DoS 正类和非 DoS 背景流，然后执行时间窗口预测、流量重组、SMOTE 和
分类检测对比。默认新增的生成流量数量限制为真实正类上限（默认 3000），避免最后一个
窗口的短流数量过大而主导微调；可通过 `--augmentation-count N` 显式覆盖。

运行：

```bash
comparison_experiments/dos/run_full_experiment.sh
```

最终结果：

```text
comparison_results/attack_types/dos/dos_method_comparison.csv
comparison_results/attack_types/dos/dos_efficiency_comparison.csv
```

中间文件默认放入临时目录并自动清理；使用 `--keep-work` 可保留中间文件排查错误。
