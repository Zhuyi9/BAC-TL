# 时序粒度消融实验

该实验以 CTU-13 场景 12 的 P2P Botnet 流量为正类，IDS-2017 流量为负类。每组只改变流内切片粒度：1 ms、10 ms、100 ms、200 ms、500 ms、1 s、2 s、3 s、4 s、5 s、6 s、8 s、10 s；每条流始终保留 60 个切片。

每组执行相同流程：在严格按时间切分的 CTU-13 训练段上提取窗口质心并训练预测器，单步预测训练段之后的一个窗口；随后在历史训练流中，用归一化欧氏距离检索包数和总字节分布最接近预测质心的一条真实流。该历史流继续按当前粒度聚合为逐时间片的整数包数和链路层总字节数，上一窗口的真实种子流按这组时间片目标重组，因此不再对浮点预测质心取整。生成流随后用于 generated 微调并在固定测试集检测，该消融不运行 SMOTE 对照组。

实验提供两种片内重构方式。`even` 为兼容既有脚本的名称，当前实际采用随机整数划分将片内载荷预算分配到各个包，并在安全边界内随机生成包到达时间；`random` 是该方式的显式名称。`jitter` 以目标历史流在该片内的逐包长度比例和到达位置为基准，默认加入包长权重标准差 0.10 的乘性扰动，以及标准差为 `min(切片长度×0.05, 0.05秒)` 的到达时间扰动。两种方式均严格保持每片包数、协议头约束下的目标总字节数和时间片归属不变。`even/random` 使用系统熵源，不固定随机种子；`jitter` 只有显式提供种子时才保证可复现。

相似度直接比较每条仿构流与被检索到的历史目标流。实验分别计算包长序列余弦，以及使用目标流共同尺度归一化后的“相对到达时刻、链路层帧长度”二维点序列整体余弦，再对所有仿构流的相似度取均值。包长取 PCAP 中捕获到的链路层帧字节数。

由于仿构流本来就以该历史流的时间片统计为目标，两个逐包余弦值反映时间片重构后对原始逐包形态的保留程度。最终表同时记录预测类心到所选历史流的归一化欧氏距离，用于评价不同切片粒度下预测结果与可实现真实行为之间的接近程度；该距离越小越好。

运行示例：

```bash
./comparison_experiments/ablation/temporal_granularity/run_ablation.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

单独运行微小抖动方式：

```bash
./comparison_experiments/ablation/temporal_granularity/run_ablation_jitter.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

依次运行两种方式：

```bash
./comparison_experiments/ablation/temporal_granularity/run_both_intra_slice_ablations.sh \
  --ctu-pcap pcap/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap \
  --ids-csv csv_output/wednesday/flows_100000_to_200000_from_chunks_labeled.csv
```

两种方式顺序运行时最终保留：

- `comparison_results/ablation/temporal_granularity/even/temporal_granularity_comparison.csv`
- `comparison_results/ablation/temporal_granularity/jitter/temporal_granularity_comparison.csv`

其中 `effective_horizon_s = slice_window_s * 60`，用于明确固定切片数下每组实际观察的流内时间范围。
