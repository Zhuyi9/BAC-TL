# 对比实验代码

该目录只存放对比实验和消融实验的代码、配置与说明，不存放运行结果。

目录约定：

```text
comparison_experiments/
  efficiency/      效率与资源开销对比
  run_all_experiments.sh  一次性运行五组完整实验
  dos/              DoS 实验（由公共入口按标签筛选 IDS-2017 流）
  zeus/            Zeus 攻击流增强实验入口
  scan/            Scan 攻击流增强实验入口
  xss/             XSS 攻击流增强实验入口
  attack_types/    三类攻击实验共享实现（内部目录）
  ablation/        后续消融实验
  traffic_reconstruction/            原始特征流量还原实验
  transformed_feature_construction/  变换特征流量仿构实验
```

DoS、Zeus、Scan 和 XSS 分别使用独立配置运行，避免不同攻击类型的参数和结果混在一起。
三个入口内部调用 `attack_types/` 的共享流程，最终结果分别写入
`comparison_results/attack_types/<attack>/`，每个攻击类型只保留一个方法对比 CSV。

使用 `run_all_experiments.sh` 可以按 DoS、CTU-13 场景 12、Scan、XSS、Zeus 的顺序一次性
运行全部实验。

所有运行结果统一写入项目根目录下的 `comparison_results/`。同一对方法的当前结果
直接保存在对应实验类型目录中，后续消融和质量实验使用独立的实验类型目录。

GitHub 发布目录默认从仓库级 `../data/raw/` 读取原始数据，也可以通过
`BAC_TL_DATA_ROOT` 环境变量或命令行参数覆盖。Python 默认使用 `python3`，需要指定
其他虚拟环境时设置 `PYTHON=/path/to/python`。

Zeus、Scan、XSS 入口每次完整运行会各写入两份最终 CSV：`*_method_comparison.csv`
保存检测效果，`*_efficiency_comparison.csv` 只保存各阶段的时间、CPU 占用率和内存使用量。
