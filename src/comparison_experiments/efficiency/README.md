# SMOTE 与流量重组生成方法效率对比

## 对比内容

该实验比较：

1. `smote`：当前项目中的正类随机线性插值实现；
2. `traffic_generation`：使用流量重组生成样本的提出方法。

两种方法使用相同的 3000 条真实 DoS、10064 条增强正例、真实负例、756 维行为特征、
MLP 参数和 6900 条真实目标窗口检测 flow。

效率对比项包括：

| 对比项 | 统计范围 |
|---|---|
| 特征提取与增强数据构造 | 真实流量向量化，以及 SMOTE 插值或生成 PCAP 解析与向量化 |
| 模型训练 | 标准化、PCA、MLP 训练和验证，不包含最终测试 |
| 模型检测 | 模型加载、标准化、PCA 和对预计算测试向量的 MLP 推理 |
| 总开销 | 上述三个阶段的合计 |

每个对比项记录墙钟时间、CPU 时间、平均 CPU 和峰值 RSS 内存。最终结果使用正式重复
测量的中位数，并计算提出方法相对 SMOTE 降低或增加的百分比。

## 文件结构

```text
comparison_experiments/efficiency/
  benchmark.py
  detect_precomputed.py
  configs/
    smote_vs_traffic_generation.json

comparison_results/efficiency/
  smote_vs_traffic_generation_efficiency_comparison.csv
```

运行过程中需要的数据集、模型和预测文件只写入系统临时目录。运行成功、失败或程序退出后，
临时目录都会被清理。结果目录不保存日志、模型、中间 CSV、NumPy 数组或元数据文件。

## 运行

本机应使用依赖完整的 Anaconda base 解释器：

```bash
cd /path/to/BAC-TL/src

python3 \
  comparison_experiments/efficiency/benchmark.py \
  --config comparison_experiments/efficiency/configs/smote_vs_traffic_generation.json
```

配置默认执行 1 次预热和 5 次正式重复。需要调整时可以使用：

```bash
--repetitions 3 --warmup-repetitions 1
```

任意阶段出错时，底层命令的输出会直接显示在终端，运行器随后抛出异常且不会写入残缺的
结果 CSV。成功后只生成：

```text
comparison_results/efficiency/smote_vs_traffic_generation_efficiency_comparison.csv
```

再次运行同一对方法时会覆盖该文件，保证结果目录中始终只有这一份当前结果。
