# XSS 攻击流增强实验

该目录是 XSS 实验的独立使用入口。真实 XSS 流与 IDS-2017 背景流先用于共同预训练，
随后分别加入等量的 SMOTE 样本或时间窗口预测后重组生成的 XSS 流，并在相同测试集上
比较微调效果。

## 数据与参数

- 正类 PCAP：`pcap/xss/XSS.pcap`
- 正类标签：`XSS`
- 默认宏观时间窗口：60 秒
- 默认负类：`csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv`
- 结果文件：`comparison_results/attack_types/xss/xss_method_comparison.csv`
- 效率文件：`comparison_results/attack_types/xss/xss_efficiency_comparison.csv`

XSS PCAP 的有效流数量少于 3000，因此训练正类使用实际可用规模，训练负类默认限制为
真实训练正类的两倍。生成数量按训练集最后一个完整窗口的有效流数决定，不能强行扩增到
3000；SMOTE 与生成方法仍保持完全相同的新增数量。

## 运行

从项目根目录运行：

```bash
comparison_experiments/xss/run_full_experiment.sh
```

可以覆盖数据源和训练设置：

```bash
comparison_experiments/xss/run_full_experiment.sh \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv \
  --centroid-epochs 5 --epochs 10
```

运行期间的转换 CSV、时间切片、质心模型和分类模型都放在临时目录，成功后自动删除。
`comparison_results/attack_types/xss/xss_method_comparison.csv` 和效率 CSV 是该实验的正式
输出；效率 CSV 记录特征提取、模型训练、模型检测和流量生成各阶段的时间、CPU 占用率与
内存使用量。出现错误时可使用 `--keep-work` 保留中间目录。
