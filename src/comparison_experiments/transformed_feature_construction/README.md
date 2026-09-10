# 基于变换特征的网络流量仿构实验

该实验使用 20 组互不重复的“目标流--种子流”配对。目标流的逐时间片包数和完整 Ethernet 帧长度总和作为变换后的目标行为特征；种子流提供真实五元组、协议字段模板和应用层载荷。仿构流继承种子流的协议上下文，并按目标行为特征重新分配数据包、帧长度和片内到达时刻。种子载荷按通信方向顺序一次性消费，不循环复用；当某一方向的可用载荷不足时，最后一个包仅写入剩余真实载荷，随后截断该条仿构流。

默认从同一输入 PCAP 自动挑选 40 条较长的 TCP 或 UDP 流，并按编号相邻配对。若需要指定协议，可使用 `--protocol TCP` 或 `--protocol UDP`。

```bash
./comparison_experiments/transformed_feature_construction/run_transformed_feature_experiment.sh \
  --input-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --slice-window 1.0
```

结果默认写入 `comparison_results/transformed_feature_construction/`：

- `target_flows/`：20 条用于提供目标行为的原始流；
- `seed_flows/`：20 条用于提供真实载荷和协议上下文的种子流；
- `constructed_flows/`：与配对编号一一对应的仿构流；
- `target_behavior_features.csv`：每一对目标流的逐时间片包数和总帧长度；
- `per_flow_metrics.csv`：逐配对的行为相似度、逐包结构相似度、可解析性和资源消耗；
- `average_metrics.csv`：所有配对的平均结果；
- `experiment_manifest.json`：输入、参数、结果文件和配对关系。

其中“联合行为余弦相似度”先对包数和字节量分别按目标/仿构流共同最大值归一化，再展平计算余弦相似度，避免总字节量的数值尺度掩盖包数行为。逐包指标以目标流为参照，在两条流的共同包数边界内计算。

资源消耗覆盖目标行为特征提取与 PCAP 仿构，不包括输入 PCAP 的拆流和种子流到统一 CSV 的一次性格式转换。CPU 和内存均针对当前实验进程采样；内存记录为仿构区间的峰值 RSS。
