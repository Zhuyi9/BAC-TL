# Zeus、Scan、XSS 攻击增强实验

本目录把三类攻击 PCAP 接入与 CTU-13 场景 12 相同的实验方法：真实正类和 IDS-2017
负类先训练共同基础分类器；质心模型根据严格时间顺序预测一个下一窗口；重组生成法和
SMOTE 增加相同数量的正类样本，并分别从同一个预训练 checkpoint 微调。

## 直接运行

从项目根目录执行以下任意一条命令：

```bash
comparison_experiments/attack_types/run_full_experiment.sh --attack dos
comparison_experiments/attack_types/run_full_experiment.sh --attack zeus
comparison_experiments/attack_types/run_full_experiment.sh --attack scan
comparison_experiments/attack_types/run_full_experiment.sh --attack xss
```

入口默认使用：

| 参数 | Zeus | Scan | XSS |
|---|---|---|---|
| 正类 PCAP | `pcap/trojan/Malware/Zeus.pcap` | `pcap/scan/web_scan.pcap` | `pcap/xss/XSS.pcap` |
| 正类标签 | `Zeus` | `Scan` | `XSS` |
| 宏观窗口 | 60 秒 | 30 秒 | 60 秒 |
| 细粒度切片 | 1 秒 | 1 秒 | 1 秒 |

Scan 的原始捕获只有约 532 秒。使用 30 秒窗口是为了提供足够的连续质心样本；若沿用
60 秒窗口，整个捕获只有约 10 个宏观窗口，严格时间切分后的 Transformer 训练样本过少。

DoS 实验使用同一份 IDS-2017 CSV：脚本先按 behavior 行的 `DoS` 标签筛选完整 DoS 流作为
正类，再筛选非 DoS 流作为背景负类，因此不会把 BENIGN 流误标为正类。DoS 的输出目录为
`comparison_results/attack_types/dos/`。

IDS-2017 负类默认使用：

```text
csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

可通过 `--ids-csv` 和 `--positive-pcap` 覆盖默认输入。完整参数见：

```bash
comparison_experiments/attack_types/run_full_experiment.sh --help
```

## 数据规模策略

真实训练正类最多保留 3000 条。训练负类最多保留为实际真实训练正类的 2 倍，因此：

- Zeus、Scan 正类足够时使用约 `3000:6000`；
- XSS 正类不足 3000 时使用实际训练正类，并自动配套两倍训练负类；
- 该限制只作用于训练负类，不删减 IDS-2017 的校准集和测试集；
- SMOTE 和重组生成法始终使用同一真实基础训练集和同一新增数量。

可用 `--train-negative-ratio` 修改训练负类比例。`--max-ids-negative` 仍控制 IDS-2017
进入时间切分前的总体上限，默认 10000。

## 时间序列处理

正类按照完整宏观窗口切成 `60%/20%/20%` 的训练、校准和测试集。质心数据集会检测
相邻窗口间隔：只要中间缺失了宏观窗口，就拆成两段独立序列，不跨空档构造历史样本。
生成阶段也只使用以训练集最新窗口结尾的连续真实历史，并且只预测一个下一窗口。

## 最终结果

默认中间文件使用临时目录并自动删除。每类攻击只保留一个最终 CSV：

```text
comparison_results/attack_types/zeus/zeus_method_comparison.csv
comparison_results/attack_types/scan/scan_method_comparison.csv
comparison_results/attack_types/xss/xss_method_comparison.csv
```

CSV 包含 `none`（无增强预训练基线）、`smote`、`generated`、`generated_vs_none` 和
`generated_vs_smote` 行；混淆矩阵使用
`TN/FP/FN/TP` 独立列，最后一列是 `augmentation_count`。

排查失败时使用 `--keep-work`，脚本会打印中间工作目录。正式结果仍属于跨数据集实验，
应解释为目标攻击相对于 IDS-2017 非目标流量的增强效果，而不是同一采集环境内的检测性能。

每次运行还会在对应结果目录写入效率 CSV：

```text
comparison_results/attack_types/zeus/zeus_efficiency_comparison.csv
comparison_results/attack_types/scan/scan_efficiency_comparison.csv
comparison_results/attack_types/xss/xss_efficiency_comparison.csv
```

文件按 `method` 和 `phase` 汇总三项指标：`time_s`（墙钟时间）、`cpu_usage_pct`（CPU
占用率）和 `memory_mb`（峰值 RSS 内存）。`feature_extraction` 包含 PCAP 转换、流特征构造
和数据集构造；`model_training` 包含质心模型及分类器训练；`model_detection` 是使用
预计算测试向量的分类推理；`traffic_generation` 单独记录预测与流量重组成本。共同的
预训练阶段标记为 `shared_pretrain`，两种增强方法分别标记为 `smote`、`generated`。
