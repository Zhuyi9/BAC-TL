#!/usr/bin/env python3
"""验证逐包原始特征能否近无损还原网络流量。

流程：从输入 PCAP 中选择 20 条较长的 TCP/UDP 流，保存原始流子集，
转换为项目逐包特征 CSV，再调用现有重组器生成 PCAP。最终以逐流 CSV
记录包数、帧长、载荷、协议字段和相对时间的一致性，并计算余弦相似度。
重构 PCAP 的包间隔加入很小的随机抖动；因此时间指标直接读取重构 PCAP，
不依赖重组器导出的中间 CSV 时间戳。
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import socket
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import dpkt
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
UNIFIED = SRC_DIR / "UnifiedPcapToCSV.py"


def open_capture(path: Path):
    handle = path.open("rb")
    magic = handle.read(24)
    handle.seek(0)
    if magic[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return dpkt.pcap.Reader(handle), handle
    if magic[:4] == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(handle), handle
    handle.close()
    raise ValueError(f"无法识别 PCAP 格式: {path}")


def unpack(buf: bytes):
    """解析 Ethernet/SLL 包，返回 IP 和传输层对象。"""
    for wrapper in (dpkt.ethernet.Ethernet, dpkt.sll.SLL, dpkt.sll2.SLL2):
        try:
            link = wrapper(buf)
            packet = link.data
            while packet is not None and not isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
                packet = getattr(packet, "data", None)
            if packet is not None:
                transport = packet.data
                if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    return packet, transport
        except Exception:
            continue
    return None, None


def endpoint_key(ip_obj, transport):
    if isinstance(ip_obj, dpkt.ip.IP):
        src = socket.inet_ntoa(ip_obj.src)
        dst = socket.inet_ntoa(ip_obj.dst)
        proto = int(ip_obj.p)
    else:
        src = socket.inet_ntop(socket.AF_INET6, ip_obj.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip_obj.dst)
        proto = int(ip_obj.nxt)
    left = (src, int(transport.sport))
    right = (dst, int(transport.dport))
    return (left, right, proto) if left <= right else (right, left, proto)


def collect_flow_segments(path: Path, timeout: float = 30.0):
    """按项目同样的双向五元组和 30 秒空闲超时划分流段。"""
    reader, handle = open_capture(path)
    segments = []
    active = {}
    try:
        for timestamp, raw in reader:
            ip_obj, transport = unpack(raw)
            if ip_obj is None:
                continue
            key = endpoint_key(ip_obj, transport)
            previous = active.get(key)
            if previous is None or timestamp - previous["last"] > timeout:
                segment = {"key": key, "packets": []}
                segments.append(segment)
                active[key] = {"last": timestamp, "segment": segment}
            else:
                segment = previous["segment"]
                previous["last"] = timestamp
            segment["packets"].append((float(timestamp), bytes(raw)))
    finally:
        handle.close()
    return segments


def select_segments(segments, count: int):
    eligible = [item for item in segments if len(item["packets"]) >= 2]
    eligible.sort(
        key=lambda item: (
            len(item["packets"]),
            item["packets"][-1][0] - item["packets"][0][0],
        ),
        reverse=True,
    )
    return eligible[:count]


def write_subset_pcap(segments, output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = [packet for segment in segments for packet in segment["packets"]]
    packets.sort(key=lambda item: item[0])
    with output.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for timestamp, raw in packets:
            writer.writepkt(raw, ts=timestamp)


def write_flow_pcap(segment, output: Path):
    """将一条已经匹配的流写成独立 PCAP。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        if segment is not None:
            for timestamp, raw in sorted(segment["packets"], key=lambda item: item[0]):
                writer.writepkt(raw, ts=timestamp)


def run_conversion(input_pcap: Path, output_csv: Path, python: str):
    subprocess.run(
        [python, str(UNIFIED), "-i", str(input_pcap), "-o", str(output_csv)],
        cwd=PROJECT_ROOT,
        check=True,
    )
    if not output_csv.exists() or output_csv.stat().st_size == 0:
        raise RuntimeError(f"PCAP 转 CSV 未产生有效文件: {output_csv}")


def read_source_csv(path: Path):
    flows = defaultdict(lambda: {"rows": defaultdict(list), "behavior": None})
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            flow = flows[str(row["flow_id"])]
            if row["layer"] == "behavior":
                flow["behavior"] = row
            else:
                flow["rows"][row["layer"]].append(row)
    for flow in flows.values():
        for layer in flow["rows"]:
            flow["rows"][layer].sort(key=lambda row: int(row["packet_index"]))
    return dict(flows)


def parse_reconstructed_pcap(path: Path, timeout: float = 30.0):
    """读取重构 PCAP，并按五元组/空闲超时重新分段。"""
    reader, handle = open_capture(path)
    segments = []
    active = {}
    try:
        for timestamp, raw in reader:
            ip_obj, transport = unpack(raw)
            if ip_obj is None:
                continue
            key = endpoint_key(ip_obj, transport)
            previous = active.get(key)
            if previous is None or timestamp - previous["last"] > timeout:
                segment = {"key": key, "packets": []}
                segments.append(segment)
                active[key] = {"last": timestamp, "segment": segment}
            else:
                segment = previous["segment"]
                previous["last"] = timestamp
            segment["packets"].append((float(timestamp), bytes(raw)))
    finally:
        handle.close()
    return segments


def pad_ethernet_frames(input_path: Path, output_path: Path, minimum_length: int = 60):
    """补齐 Ethernet 最小帧长度，不改变 IP/传输层内容。"""
    reader, handle = open_capture(input_path)
    try:
        with output_path.open("wb") as out_handle:
            writer = dpkt.pcap.Writer(out_handle)
            for timestamp, raw in reader:
                if len(raw) < minimum_length:
                    raw = raw + b"\x00" * (minimum_length - len(raw))
                writer.writepkt(raw, ts=timestamp)
    finally:
        handle.close()


def packet_details(raw: bytes):
    link = dpkt.ethernet.Ethernet(raw)
    ip_obj = link.data
    transport = ip_obj.data
    if isinstance(ip_obj, dpkt.ip.IP):
        src = socket.inet_ntoa(ip_obj.src)
        dst = socket.inet_ntoa(ip_obj.dst)
        network = {
            "src_ip": src, "dst_ip": dst, "proto": int(ip_obj.p),
            "ttl": int(ip_obj.ttl), "tos": int(ip_obj.tos), "id": int(ip_obj.id),
            "frag_offset": int(ip_obj.off & 0x1FFF),
            "mf": bool(ip_obj.off & 0x2000), "df": bool(ip_obj.off & 0x4000), "version": 4,
        }
    else:
        src = socket.inet_ntop(socket.AF_INET6, ip_obj.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip_obj.dst)
        network = {"src_ip": src, "dst_ip": dst, "proto": int(ip_obj.nxt), "version": 6}
    if isinstance(transport, dpkt.tcp.TCP):
        trans = {
            "sport": int(transport.sport), "dport": int(transport.dport),
            "seq": int(transport.seq), "ack": int(transport.ack),
            "off": int(transport.off), "opts": transport.opts.hex() if transport.opts else "",
            "flags": int(transport.flags), "window": int(transport.win),
            "urg": int(transport.urp), "type": "TCP",
        }
    else:
        trans = {"sport": int(transport.sport), "dport": int(transport.dport), "ulen": int(transport.ulen), "type": "UDP"}
    link_header = {"src_mac": link.src.hex(), "dst_mac": link.dst.hex(), "eth_type": int(link.type)}
    return link_header, network, trans, bytes(transport.data), endpoint_key(ip_obj, transport)


def json_header(row):
    try:
        return json.loads(row["encoding_header"] or "{}")
    except json.JSONDecodeError:
        return {}


def cosine(left, right):
    left = np.asarray(left, dtype=np.float64).reshape(-1)
    right = np.asarray(right, dtype=np.float64).reshape(-1)
    denominator = np.linalg.norm(left) * np.linalg.norm(right)
    return float(np.dot(left, right) / denominator) if denominator else float("nan")


def match_reconstructed(source, candidates):
    link_rows = source["rows"].get("link", [])
    if not link_rows:
        return None
    first_network = json_header(source["rows"]["network"][0])
    first_transport = json_header(source["rows"]["transport"][0])
    src = (first_network.get("src_ip", ""), int(first_transport.get("sport", 0)))
    dst = (first_network.get("dst_ip", ""), int(first_transport.get("dport", 0)))
    proto = int(first_network.get("proto", 0))
    key = (src, dst, proto) if src <= dst else (dst, src, proto)
    possible = [item for item in candidates if item["key"] == key]
    if not possible:
        return None
    expected_payloads = [bytes.fromhex(row["payload"]) if row["payload"] else b"" for row in source["rows"].get("application", [])]
    expected_count = len(link_rows)
    ranked = []
    for candidate in possible:
        packets = candidate["packets"]
        payload_match = 0
        for index, (_, raw) in enumerate(packets[:expected_count]):
            try:
                payload_match += int(packet_details(raw)[3] == expected_payloads[index])
            except (IndexError, ValueError):
                pass
        ranked.append((int(len(packets) == expected_count), payload_match, candidate))
    ranked.sort(key=lambda value: (value[0], value[1]), reverse=True)
    return ranked[0][2]


def compare_flow(flow_id, source, candidate):
    link_rows = source["rows"].get("link", [])
    network_rows = source["rows"].get("network", [])
    transport_rows = source["rows"].get("transport", [])
    app_rows = source["rows"].get("application", [])
    source_count = len(link_rows)
    packets = candidate["packets"] if candidate else []
    reconstructed_count = len(packets)
    source_times = np.asarray([float(row["timestamp"]) for row in link_rows], dtype=np.float64)
    target_times = np.asarray([item[0] for item in packets], dtype=np.float64)
    source_lengths = np.asarray([int(row["size"]) for row in link_rows], dtype=np.float64)
    target_lengths = np.asarray([len(item[1]) for item in packets], dtype=np.float64)
    length_cosine = cosine(source_lengths, target_lengths) if source_count == reconstructed_count else float("nan")
    source_curve = None
    target_curve = None
    if source_count == reconstructed_count and source_count:
        source_curve = np.column_stack((source_times - source_times[0], source_lengths))
        target_curve = np.column_stack((target_times - target_times[0], target_lengths))
        scales = np.maximum(np.max(np.abs(source_curve), axis=0), np.asarray([1e-12, 1.0]))
        curve_cosine = cosine(source_curve / scales, target_curve / scales)
        time_errors_us = np.abs((source_curve[:, 0] - target_curve[:, 0]) * 1e6)
    else:
        curve_cosine = float("nan")
        time_errors_us = np.asarray([], dtype=np.float64)

    payload_equal = []
    field_equal = []
    for index in range(min(source_count, reconstructed_count)):
        try:
            link, network, trans, payload, _ = packet_details(packets[index][1])
        except Exception:
            payload_equal.append(False)
            field_equal.append(False)
            continue
        payload_expected = bytes.fromhex(app_rows[index]["payload"]) if index < len(app_rows) and app_rows[index]["payload"] else b""
        payload_equal.append(payload == payload_expected)
        expected = [json_header(link_rows[index]), json_header(network_rows[index]), json_header(transport_rows[index])]
        actual = [link, network, trans]
        field_equal.append(expected == actual)

    return {
        "flow_id": flow_id,
        "protocol": json_header(transport_rows[0]).get("type", "") if transport_rows else "",
        "original_packet_count": source_count,
        "reconstructed_packet_count": reconstructed_count,
        "packet_count_equal": int(source_count == reconstructed_count),
        "original_total_frame_bytes": int(source_lengths.sum()) if source_count else 0,
        "reconstructed_total_frame_bytes": int(target_lengths.sum()) if reconstructed_count else 0,
        "frame_length_cosine": length_cosine,
        "packet_curve_cosine": curve_cosine,
        "payload_equal_fraction": float(np.mean(payload_equal)) if payload_equal else 0.0,
        "nonmutable_header_equal_fraction": float(np.mean(field_equal)) if field_equal else 0.0,
        "relative_time_mae_us": float(np.mean(time_errors_us)) if time_errors_us.size else float("nan"),
        "relative_time_max_error_us": float(np.max(time_errors_us)) if time_errors_us.size else float("nan"),
        "flow_key_matched": int(candidate is not None),
        "flow_pass": int(
            candidate is not None
            and source_count == reconstructed_count
            and all(payload_equal)
            and all(field_equal)
        ),
    }


def parse_args():
    parser = argparse.ArgumentParser(description="逐包原始特征网络流量还原实验")
    parser.add_argument("--input-pcap", required=True)
    parser.add_argument("--output-dir", default="comparison_results/traffic_reconstruction")
    parser.add_argument("--flow-count", type=int, default=20)
    parser.add_argument("--jitter-min", type=float, default=0.995)
    parser.add_argument("--jitter-max", type=float, default=1.005)
    parser.add_argument("--python", default=sys.executable)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.flow_count <= 0 or not (0 < args.jitter_min <= args.jitter_max):
        raise ValueError("流数量必须为正数，且抖动系数需满足 0 < min <= max")
    input_pcap = Path(args.input_pcap).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    segments = select_segments(collect_flow_segments(input_pcap), args.flow_count)
    if len(segments) < args.flow_count:
        raise RuntimeError(f"输入 PCAP 只有 {len(segments)} 条满足条件的流，少于要求的 {args.flow_count} 条")
    original_pcap = output_dir / f"original_{args.flow_count}_flows.pcap"
    original_csv = output_dir / f"original_{args.flow_count}_flows.csv"
    reconstructed_pcap = output_dir / f"reconstructed_{args.flow_count}_flows.pcap"
    write_subset_pcap(segments, original_pcap)
    run_conversion(original_pcap, original_csv, args.python)

    # 仅启用很小的包间隔抖动；不启用重塑、填充、分片、缩放或漂移配置。
    sys.path.insert(0, str(SRC_DIR))
    from ReconstitutePackets import reconstruct_csv_to_pcap

    raw_reconstructed_pcap = output_dir / f"reconstructed_{args.flow_count}_flows_unpadded.pcap"
    reconstruct_csv_to_pcap(
        str(original_csv), str(raw_reconstructed_pcap),
        jitter_min=args.jitter_min, jitter_max=args.jitter_max,
    )
    pad_ethernet_frames(raw_reconstructed_pcap, reconstructed_pcap)
    raw_reconstructed_pcap.unlink(missing_ok=True)
    source = read_source_csv(original_csv)
    original_segments = parse_reconstructed_pcap(original_pcap)
    reconstructed = parse_reconstructed_pcap(reconstructed_pcap)
    rows = []
    original_flow_paths = []
    reconstructed_flow_paths = []
    for flow_id in sorted(source, key=lambda value: int(value)):
        original_candidate = match_reconstructed(source[flow_id], original_segments)
        candidate = match_reconstructed(source[flow_id], reconstructed)
        flow_number = len(rows) + 1
        original_path = output_dir / "original_flows" / f"flow_{flow_number:03d}.pcap"
        write_flow_pcap(original_candidate, original_path)
        original_flow_paths.append(original_path)
        reconstructed_path = output_dir / "reconstructed_flows" / f"flow_{flow_number:03d}.pcap"
        write_flow_pcap(candidate, reconstructed_path)
        reconstructed_flow_paths.append(reconstructed_path)
        rows.append(compare_flow(flow_id, source[flow_id], candidate))

    per_flow = output_dir / "per_flow_metrics.csv"
    columns = list(rows[0].keys())
    with per_flow.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    # 单独汇总字段差异，便于区分重构器状态修正和真实还原错误。
    diff_counts = Counter()
    for flow_id in sorted(source, key=lambda value: int(value)):
        candidate = match_reconstructed(source[flow_id], reconstructed)
        if candidate is None:
            diff_counts["flow_not_matched"] += 1
            continue
        source_rows = source[flow_id]["rows"]
        for index, (_, raw) in enumerate(candidate["packets"]):
            if index >= len(source_rows.get("transport", [])):
                continue
            actual = packet_details(raw)[2]
            expected = json_header(source_rows["transport"][index])
            for key in sorted(set(expected) | set(actual)):
                if expected.get(key) != actual.get(key):
                    diff_counts[f"transport.{key}"] += 1
            if index < len(source_rows.get("link", [])):
                if int(source_rows["link"][index]["size"]) != len(raw):
                    diff_counts["link.frame_length"] += 1
    diff_path = output_dir / "field_diff_summary.csv"
    with diff_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["field", "mismatch_count"])
        writer.writeheader()
        writer.writerows(
            {"field": key, "mismatch_count": value}
            for key, value in sorted(diff_counts.items())
        )

    numeric = [
        "original_packet_count", "reconstructed_packet_count", "packet_count_equal",
        "original_total_frame_bytes", "reconstructed_total_frame_bytes", "frame_length_cosine",
        "packet_curve_cosine", "payload_equal_fraction", "nonmutable_header_equal_fraction",
        "relative_time_mae_us", "relative_time_max_error_us", "flow_key_matched", "flow_pass",
    ]
    average = {"flow_count": len(rows), "jitter_min": args.jitter_min, "jitter_max": args.jitter_max}
    for column in numeric:
        values = np.asarray([float(row[column]) for row in rows], dtype=np.float64)
        average[f"mean_{column}"] = float(np.nanmean(values)) if np.any(~np.isnan(values)) else float("nan")
    average_csv = output_dir / "average_metrics.csv"
    with average_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(average.keys()))
        writer.writeheader()
        writer.writerow(average)

    manifest = {
        "input_pcap": str(input_pcap),
        "original_pcap": str(original_pcap),
        "original_csv": str(original_csv),
        "reconstructed_pcap": str(reconstructed_pcap),
        "original_flow_pcaps": [str(path) for path in original_flow_paths],
        "reconstructed_flow_pcaps": [str(path) for path in reconstructed_flow_paths],
        "flow_count": len(rows),
        "selection": "按包数量优先、持续时间次优先选择最长的完整 TCP/UDP 流",
        "reconstruction": "逐包原始特征反序列化；未启用流量重塑、填充、分片、缩放或漂移",
        "timestamp_jitter": {"min_factor": args.jitter_min, "max_factor": args.jitter_max, "meaning": "逐包间隔乘性抖动；相对时间指标按每流首包归一化"},
        "packet_length_definition": "PCAP 链路层完整帧长度（字节）",
        "allowed_differences": ["绝对时间起点/PCAP 时间基准", "由重构器重新计算的 IP/TCP/UDP 校验和", "Ethernet 最小帧填充"],
        "metrics": {"frame_length_cosine": "逐包链路层帧长序列余弦", "packet_curve_cosine": "相对到达时间-帧长二维序列余弦"},
    }
    (output_dir / "experiment_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"逐流结果: {per_flow}")
    print(f"平均结果: {average_csv}")


if __name__ == "__main__":
    main()
