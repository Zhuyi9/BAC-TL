# 逐包原始特征网络流量还原实验

该实验从输入 PCAP 中选择 20 条较长的 TCP/UDP 流，保存原始流子集，使用项目逐包特征格式转换后，再调用现有重组器还原为 PCAP。重构只加入默认 ±0.5% 的包间隔抖动，不启用漂移重塑、载荷填充、TCP 分片或时间缩放。

运行：

```bash
./comparison_experiments/traffic_reconstruction/run_reconstruction_experiment.sh \
  --input-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap
```

默认输出到 `comparison_results/traffic_reconstruction/`：

- `original_20_flows.pcap`：选出的原始 20 条流；
- `original_flows/flow_001.pcap` 等：按编号拆分的原始单流 PCAP；
- `original_20_flows.csv`：逐包原始特征；
- `reconstructed_20_flows.pcap`：重构结果；
- `reconstructed_flows/flow_001.pcap` 等：与原始单流 PCAP 一一对应的重构流；
- `per_flow_metrics.csv`：每条流的包数、帧长余弦、二维曲线余弦、载荷和协议字段一致性；
- `average_metrics.csv`：20 条流的平均结果；
- `field_diff_summary.csv`：逐字段差异计数，当前实现可能记录 TCP ACK 状态修正；
- `experiment_manifest.json`：数据来源、参数和允许变化字段。

包长度统一使用 PCAP 链路层完整帧长度。重构输出会补齐 Ethernet 60 字节最小帧填充。时间指标以每条流首包为零点，因此不受 PCAP 绝对时间基准影响；抖动只改变相邻包的时间间隔。
