#!/usr/bin/env python3
"""验证目标行为特征能否驱动真实协议载荷的网络流量仿构。

实验从一个 PCAP 中选取同一传输协议的 40 条真实流，按编号交替组成
20 个“目标流--种子流”配对。目标流只提供逐时间片的包数和完整 Ethernet
帧长度总和；种子流提供五元组、协议首部模板和真实应用层载荷。重构器按
目标行为配置重新分片并安排到达时间，随后重算必要的协议字段并写出 PCAP。

每个配对都保留目标、种子和仿构 PCAP，并记录行为相似度、逐包结构相似度、
可解析性以及仿构阶段的时间、CPU 和峰值内存。种子载荷按方向顺序一次性
消费，载荷不足时直接截断仿构流。临时特征 CSV 仅在系统临时目录中使用，
实验结束后自动删除。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

import dpkt
import numpy as np
import psutil


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
UNIFIED = SRC_DIR / "UnifiedPcapToCSV.py"


def open_capture(path: Path):
    """按文件头打开 PCAP 或 PCAPNG。"""
    handle = path.open("rb")
    magic = handle.read(24)
    handle.seek(0)
    if magic[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return dpkt.pcap.Reader(handle), handle
    if magic[:4] == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(handle), handle
    handle.close()
    raise ValueError(f"无法识别 PCAP 格式: {path}")


def unpack_transport(raw: bytes):
    """解析 Ethernet/SLL 封装，提取 IP 与 TCP/UDP 层。"""
    for wrapper in (dpkt.ethernet.Ethernet, dpkt.sll.SLL, dpkt.sll2.SLL2):
        try:
            link = wrapper(raw)
            ip_packet = link.data
            while ip_packet is not None and not isinstance(ip_packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
                ip_packet = getattr(ip_packet, "data", None)
            if ip_packet is not None and isinstance(ip_packet.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                return ip_packet, ip_packet.data
        except Exception:
            continue
    return None, None


def protocol_name(transport) -> str:
    if isinstance(transport, dpkt.tcp.TCP):
        return "TCP"
    if isinstance(transport, dpkt.udp.UDP):
        return "UDP"
    return ""


def endpoint_key(ip_packet, transport):
    """构造与项目一致的双向五元组键。"""
    if isinstance(ip_packet, dpkt.ip.IP):
        src = socket.inet_ntoa(ip_packet.src)
        dst = socket.inet_ntoa(ip_packet.dst)
        proto = int(ip_packet.p)
    else:
        src = socket.inet_ntop(socket.AF_INET6, ip_packet.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip_packet.dst)
        proto = int(ip_packet.nxt)
    left = (src, int(transport.sport))
    right = (dst, int(transport.dport))
    return (left, right, proto) if left <= right else (right, left, proto)


def collect_flow_segments(path: Path, timeout: float = 30.0):
    """使用双向五元组和空闲超时将输入 PCAP 拆分为独立流段。"""
    reader, handle = open_capture(path)
    active = {}
    segments = []
    try:
        for timestamp, raw in reader:
            ip_packet, transport = unpack_transport(raw)
            if ip_packet is None:
                continue
            key = endpoint_key(ip_packet, transport)
            state = active.get(key)
            if state is None or float(timestamp) - state["last"] > timeout:
                segment = {
                    "key": key,
                    "protocol": protocol_name(transport),
                    "packets": [],
                    "payload_bytes": 0,
                }
                segments.append(segment)
                active[key] = {"last": float(timestamp), "segment": segment}
            else:
                segment = state["segment"]
                state["last"] = float(timestamp)
            segment["packets"].append((float(timestamp), bytes(raw)))
            segment["payload_bytes"] += len(bytes(transport.data))
    finally:
        handle.close()
    return segments


def choose_pairs(segments, pair_count: int, requested_protocol: str):
    """从同一协议的长流中选择互不重复的目标流和种子流。"""
    # 目标流用于提供行为特征，种子流还必须拥有真实应用层载荷，避免
    # 重构器在空载荷条件下以零字节填充而削弱该论证实验的有效性。
    eligible = [
        segment
        for segment in segments
        if len(segment["packets"]) >= 2 and segment["payload_bytes"] > 0
    ]
    groups = defaultdict(list)
    for segment in eligible:
        groups[segment["protocol"]].append(segment)
    for group in groups.values():
        group.sort(
            key=lambda item: (
                len(item["packets"]),
                item["packets"][-1][0] - item["packets"][0][0],
            ),
            reverse=True,
        )
    protocol = requested_protocol.upper()
    if protocol == "AUTO":
        candidates = [(len(group), name) for name, group in groups.items() if name in {"TCP", "UDP"}]
        if not candidates:
            raise RuntimeError("输入 PCAP 中没有可用的 TCP/UDP 流")
        protocol = max(candidates)[1]
    if protocol not in {"TCP", "UDP"}:
        raise ValueError("--protocol 只能是 auto、TCP 或 UDP")
    selected = groups.get(protocol, [])[: pair_count * 2]
    if len(selected) < pair_count * 2:
        raise RuntimeError(
            f"协议 {protocol} 只有 {len(selected)} 条有效流，少于 {pair_count * 2} 条；"
            "请降低 --pair-count 或指定另一个协议。"
        )
    # 相邻长流配对，使目标与种子的规模尽量接近，同时保证两组流互不重叠。
    return protocol, [(selected[index * 2], selected[index * 2 + 1]) for index in range(pair_count)]


def write_flow_pcap(segment, output: Path):
    """将单条流独立保存为 PCAP，供 Wireshark 对照查看。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for timestamp, raw in sorted(segment["packets"], key=lambda item: item[0]):
            writer.writepkt(raw, ts=timestamp)


def run_conversion(input_pcap: Path, output_csv: Path, python: str):
    """将种子单流转换为重构器所需的统一逐包特征 CSV。"""
    subprocess.run(
        [python, str(UNIFIED), "-i", str(input_pcap), "-o", str(output_csv)],
        cwd=PROJECT_ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if not output_csv.exists() or output_csv.stat().st_size == 0:
        raise RuntimeError(f"种子流特征转换失败: {input_pcap}")


def behavior_profile(segment, slice_window: float):
    """提取目标流逐时间片包数、链路层帧总字节和片内逐包参照。"""
    packets = sorted(segment["packets"], key=lambda item: item[0])
    if not packets:
        raise ValueError("不能从空流提取行为特征")
    start = packets[0][0]
    profile = []
    for timestamp, raw in packets:
        index = int((timestamp - start) // slice_window)
        while len(profile) <= index:
            profile.append(
                {
                    "packet_count": 0,
                    "total_bytes": 0,
                    "packet_lengths": [],
                    "arrival_offsets": [],
                }
            )
        item = profile[index]
        item["packet_count"] += 1
        item["total_bytes"] += len(raw)
        item["packet_lengths"].append(len(raw))
        item["arrival_offsets"].append(float(timestamp - (start + index * slice_window)))
    return profile


def packets_from_pcap(path: Path):
    """读取可解析的 TCP/UDP 包，作为仿构后的独立流。"""
    reader, handle = open_capture(path)
    packets = []
    try:
        for timestamp, raw in reader:
            ip_packet, transport = unpack_transport(raw)
            if ip_packet is not None:
                packets.append((float(timestamp), bytes(raw), ip_packet, transport))
    finally:
        handle.close()
    return sorted(packets, key=lambda item: item[0])


def payload_pools(segment):
    """按通信方向汇集种子流载荷，供结果侧验证仿构载荷的来源。"""
    pools = defaultdict(bytearray)
    for _, raw in segment["packets"]:
        ip_packet, transport = unpack_transport(raw)
        if ip_packet is not None and transport.data:
            pools[directional_key(ip_packet, transport)].extend(bytes(transport.data))
    return {key: bytes(value) for key, value in pools.items()}


def payload_origin_fraction(constructed_packets, seed_segment):
    """验证仿构载荷是否按方向顺序一次性截取自种子载荷。"""
    pools = payload_pools(seed_segment)
    offsets = defaultdict(int)
    total = 0
    matched = 0
    for _, _, ip_packet, transport in constructed_packets:
        payload = bytes(transport.data)
        if not payload:
            continue
        total += len(payload)
        direction = directional_key(ip_packet, transport)
        pool = pools.get(direction, b"")
        offset = offsets[direction]
        expected = pool[offset : offset + len(payload)]
        if payload == expected:
            matched += len(payload)
        offsets[direction] = offset + len(payload)
    return (float(matched / total) if total else 1.0), total


def profile_from_packets(packets, slice_window: float):
    """由生成 PCAP 重新提取行为特征，避免使用内部中间值作为结果。"""
    if not packets:
        return []
    start = packets[0][0]
    profile = []
    for timestamp, raw, _, _ in packets:
        index = int((timestamp - start) // slice_window)
        while len(profile) <= index:
            profile.append({"packet_count": 0, "total_bytes": 0})
        profile[index]["packet_count"] += 1
        profile[index]["total_bytes"] += len(raw)
    return profile


def cosine(left, right):
    left = np.asarray(left, dtype=np.float64).reshape(-1)
    right = np.asarray(right, dtype=np.float64).reshape(-1)
    denominator = np.linalg.norm(left) * np.linalg.norm(right)
    return float(np.dot(left, right) / denominator) if denominator else float("nan")


def padded_series(profile, field: str, length: int):
    return np.asarray(
        [float(profile[index].get(field, 0)) if index < len(profile) else 0.0 for index in range(length)],
        dtype=np.float64,
    )


def behavior_cosines(target_profile, constructed_profile):
    """分别评价包数、字节量及等尺度联合行为序列的余弦相似度。"""
    length = max(len(target_profile), len(constructed_profile))
    target_packets = padded_series(target_profile, "packet_count", length)
    generated_packets = padded_series(constructed_profile, "packet_count", length)
    target_bytes = padded_series(target_profile, "total_bytes", length)
    generated_bytes = padded_series(constructed_profile, "total_bytes", length)
    packet_cosine = cosine(target_packets, generated_packets)
    byte_cosine = cosine(target_bytes, generated_bytes)
    # 分别按两条流的共同尺度归一化，避免字节量的绝对大小掩盖包数行为。
    packet_scale = max(np.max(np.abs(target_packets)), np.max(np.abs(generated_packets)), 1.0)
    byte_scale = max(np.max(np.abs(target_bytes)), np.max(np.abs(generated_bytes)), 1.0)
    joint_target = np.column_stack((target_packets / packet_scale, target_bytes / byte_scale))
    joint_generated = np.column_stack((generated_packets / packet_scale, generated_bytes / byte_scale))
    return packet_cosine, byte_cosine, cosine(joint_target, joint_generated)


def packet_structure_cosines(target_segment, constructed_packets):
    """比较目标流与仿构流的逐包帧长度和时间--长度曲线。"""
    target = sorted(target_segment["packets"], key=lambda item: item[0])
    count = min(len(target), len(constructed_packets))
    if count == 0:
        return float("nan"), float("nan")
    target_times = np.asarray([item[0] for item in target[:count]], dtype=np.float64)
    generated_times = np.asarray([item[0] for item in constructed_packets[:count]], dtype=np.float64)
    target_lengths = np.asarray([len(item[1]) for item in target[:count]], dtype=np.float64)
    generated_lengths = np.asarray([len(item[1]) for item in constructed_packets[:count]], dtype=np.float64)
    length_cosine = cosine(target_lengths, generated_lengths)
    target_curve = np.column_stack((target_times - target_times[0], target_lengths))
    generated_curve = np.column_stack((generated_times - generated_times[0], generated_lengths))
    scales = np.maximum(
        np.maximum(np.max(np.abs(target_curve), axis=0), np.max(np.abs(generated_curve), axis=0)),
        np.asarray([1e-12, 1.0]),
    )
    return length_cosine, cosine(target_curve / scales, generated_curve / scales)


class ResourceMonitor:
    """在单条流的仿构区间内采样当前进程 CPU 占用与 RSS。"""

    def __init__(self, interval: float = 0.02):
        self.interval = interval
        self.process = psutil.Process(os.getpid())
        self.cpu_samples = []
        self.rss_samples = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self):
        self.process.cpu_percent(interval=None)
        while not self.stop_event.wait(self.interval):
            self.cpu_samples.append(self.process.cpu_percent(interval=None))
            self.rss_samples.append(self.process.memory_info().rss / (1024 * 1024))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join(timeout=1.0)
        self.rss_samples.append(self.process.memory_info().rss / (1024 * 1024))

    @property
    def average_cpu(self):
        return float(np.mean(self.cpu_samples)) if self.cpu_samples else 0.0

    @property
    def peak_memory(self):
        return float(max(self.rss_samples)) if self.rss_samples else 0.0


def flow_key(packets):
    if not packets:
        return None
    return endpoint_key(packets[0][2], packets[0][3])


def directional_key(ip_packet, transport):
    """构造与重构器载荷池一致的有向四元组键。"""
    if isinstance(ip_packet, dpkt.ip.IP):
        src = socket.inet_ntoa(ip_packet.src)
        dst = socket.inet_ntoa(ip_packet.dst)
    else:
        src = socket.inet_ntop(socket.AF_INET6, ip_packet.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip_packet.dst)
    return (src, int(transport.sport), dst, int(transport.dport))


def parse_args():
    parser = argparse.ArgumentParser(description="基于变换特征的网络流量仿构实验")
    parser.add_argument("--input-pcap", required=True, help="包含目标流和种子流的输入 PCAP")
    parser.add_argument("--output-dir", default="comparison_results/transformed_feature_construction")
    parser.add_argument("--pair-count", type=int, default=20, help="目标流--种子流配对数量")
    parser.add_argument("--protocol", default="auto", help="auto、TCP 或 UDP；每个配对固定为同一协议")
    parser.add_argument("--slice-window", type=float, default=1.0, help="目标行为特征的时间片大小（秒）")
    parser.add_argument("--python", default=sys.executable, help="用于统一特征转换的 Python 解释器")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.pair_count <= 0 or args.slice_window <= 0:
        raise ValueError("--pair-count 和 --slice-window 必须为正数")
    input_pcap = Path(args.input_pcap).resolve()
    if not input_pcap.is_file():
        raise FileNotFoundError(f"输入 PCAP 不存在: {input_pcap}")
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    protocol, pairs = choose_pairs(collect_flow_segments(input_pcap), args.pair_count, args.protocol)
    sys.path.insert(0, str(SRC_DIR))
    from ReconstitutePackets import reconstruct_csv_to_pcap

    rows = []
    target_features = []
    manifest_pairs = []
    with tempfile.TemporaryDirectory(prefix="transformed_feature_construction_") as temporary:
        temporary_dir = Path(temporary)
        for pair_index, (target, seed) in enumerate(pairs, start=1):
            pair_id = f"pair_{pair_index:03d}"
            target_path = output_dir / "target_flows" / f"{pair_id}_target.pcap"
            seed_path = output_dir / "seed_flows" / f"{pair_id}_seed.pcap"
            constructed_path = output_dir / "constructed_flows" / f"{pair_id}_constructed.pcap"
            write_flow_pcap(target, target_path)
            write_flow_pcap(seed, seed_path)
            constructed_path.parent.mkdir(parents=True, exist_ok=True)

            feature_started = time.perf_counter()
            target_profile = behavior_profile(target, args.slice_window)
            feature_time = time.perf_counter() - feature_started
            for slice_index, item in enumerate(target_profile):
                target_features.append(
                    {
                        "配对编号": pair_id,
                        "时间片编号": slice_index,
                        "目标数据包数": item["packet_count"],
                        "目标总帧长度（字节）": item["total_bytes"],
                    }
                )

            seed_csv = temporary_dir / f"{pair_id}_seed.csv"
            run_conversion(seed_path, seed_csv, args.python)
            started = time.perf_counter()
            with ResourceMonitor() as monitor:
                reconstruct_csv_to_pcap(
                    str(seed_csv),
                    str(constructed_path),
                    absolute_profile=target_profile,
                    slice_window=args.slice_window,
                    intra_slice_mode="random",
                    random_seed=None,
                )
            construction_time = time.perf_counter() - started
            constructed_packets = packets_from_pcap(constructed_path)
            constructed_profile = profile_from_packets(constructed_packets, args.slice_window)
            packet_cosine, byte_cosine, joint_cosine = behavior_cosines(target_profile, constructed_profile)
            length_cosine, curve_cosine = packet_structure_cosines(target, constructed_packets)
            payload_origin, constructed_payload_bytes = payload_origin_fraction(
                constructed_packets, seed
            )
            target_packet_count = len(target["packets"])
            seed_packet_count = len(seed["packets"])
            constructed_packet_count = len(constructed_packets)
            target_total_bytes = sum(len(raw) for _, raw in target["packets"])
            seed_total_bytes = sum(len(raw) for _, raw in seed["packets"])
            constructed_total_bytes = sum(len(raw) for _, raw, _, _ in constructed_packets)
            parse_success = int(constructed_packet_count > 0)
            target_duration = target["packets"][-1][0] - target["packets"][0][0]
            constructed_duration = (
                constructed_packets[-1][0] - constructed_packets[0][0]
                if constructed_packets else float("nan")
            )
            rows.append(
                {
                    "配对编号": pair_id,
                    "传输层协议": protocol,
                    "目标流包数": target_packet_count,
                    "种子流包数": seed_packet_count,
                    "仿构流包数": constructed_packet_count,
                    "目标流总帧长度（字节）": target_total_bytes,
                    "种子流总帧长度（字节）": seed_total_bytes,
                    "仿构流总帧长度（字节）": constructed_total_bytes,
                    "目标流持续时间（秒）": target_duration,
                    "仿构流持续时间（秒）": constructed_duration,
                    "目标时间片数": len(target_profile),
                    "仿构时间片数": len(constructed_profile),
                    "包数序列余弦相似度": packet_cosine,
                    "总帧长度序列余弦相似度": byte_cosine,
                    "联合行为余弦相似度": joint_cosine,
                    "逐包帧长度余弦相似度": length_cosine,
                    "逐包时间长度曲线余弦相似度": curve_cosine,
                    "仿构流载荷总长度（字节）": constructed_payload_bytes,
                    "载荷按种子流顺序截取比例": payload_origin,
                    "仿构特征提取时间（秒）": feature_time,
                    "PCAP仿构时间（秒）": construction_time,
                    "仿构阶段总时间（秒）": feature_time + construction_time,
                    "仿构阶段平均CPU占用率（%）": monitor.average_cpu,
                    "仿构阶段峰值内存（MB）": monitor.peak_memory,
                    "仿构流五元组继承种子流（1=是，0=否）": int(flow_key(constructed_packets) == seed["key"]),
                    "仿构流可重新解析（1=是，0=否）": parse_success,
                    "载荷来源": "种子流真实载荷顺序分片，不重复使用",
                }
            )
            manifest_pairs.append(
                {
                    "pair_id": pair_id,
                    "target_pcap": str(target_path),
                    "seed_pcap": str(seed_path),
                    "constructed_pcap": str(constructed_path),
                    "target_flow_key": [str(value) for value in target["key"]],
                    "seed_flow_key": [str(value) for value in seed["key"]],
                }
            )

    per_flow_path = output_dir / "per_flow_metrics.csv"
    with per_flow_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    target_feature_path = output_dir / "target_behavior_features.csv"
    with target_feature_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(target_features[0]))
        writer.writeheader()
        writer.writerows(target_features)

    excluded = {"配对编号", "传输层协议", "载荷来源"}
    average = {"配对数量": len(rows), "传输层协议": protocol, "时间片大小（秒）": args.slice_window}
    for column in rows[0]:
        if column in excluded:
            continue
        try:
            values = np.asarray([float(row[column]) for row in rows], dtype=np.float64)
        except (TypeError, ValueError):
            continue
        average[f"平均{column}"] = float(np.nanmean(values)) if np.any(~np.isnan(values)) else float("nan")
    average_path = output_dir / "average_metrics.csv"
    with average_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(average))
        writer.writeheader()
        writer.writerow(average)

    manifest = {
        "experiment": "基于变换特征的网络流量仿构实验",
        "input_pcap": str(input_pcap),
        "pair_count": len(rows),
        "protocol": protocol,
        "slice_window_seconds": args.slice_window,
        "feature_definition": "目标流逐时间片数据包数与完整Ethernet帧长度总和",
        "construction_definition": "目标行为特征驱动；种子流提供五元组、协议模板和真实载荷",
        "resource_scope": "目标行为特征提取与PCAP仿构；不含输入PCAP拆流和种子流CSV转换",
        "pairs": manifest_pairs,
    }
    (output_dir / "experiment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"实验完成：{output_dir}")
    print(f"逐流结果：{per_flow_path}")
    print(f"平均结果：{average_path}")


if __name__ == "__main__":
    main()
