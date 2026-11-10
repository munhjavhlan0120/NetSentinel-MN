"""Нэгжийн тест: pytest -q"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentinel.config import load_config  # noqa: E402
from netsentinel.features import WindowAggregator  # noqa: E402
from netsentinel.detectors import RuleDetector, StatisticalDetector  # noqa: E402
from netsentinel.models import PacketInfo, PerfSample  # noqa: E402
from netsentinel.perf_monitor import PerfAnalyzer, jitter_ms  # noqa: E402

CFG = load_config(None)


def run_rules(packets):
    rd, alerts = RuleDetector(CFG["rules"]), []
    agg = WindowAggregator(5, lambda ws: alerts.extend(rd.on_window(ws)),
                           auth_ports=set(CFG["rules"]["brute_force_ports"]))
    for p in packets:
        rd.on_packet(p)
        agg.add(p)
    agg.flush()
    return {a.category for a in alerts}


def syn(ts, src, dst, dport):
    return PacketInfo(ts=ts, length=60, proto="TCP", src=src, dst=dst, sport=40000, dport=dport, tcp_flags="S")


def test_port_scan():
    pk = [syn(100 + i * 0.01, "10.0.0.66", "10.0.0.5", p) for i, p in enumerate(range(1, 200))]
    assert "port_scan" in run_rules(pk)


def test_normal_web_is_quiet():
    pk = []
    for i in range(200):
        pk.append(syn(100 + i * 0.02, f"10.0.0.{10 + i % 20}", "10.0.0.5", 443))
        pk.append(PacketInfo(ts=100 + i * 0.02 + 0.001, length=60, proto="TCP", src="10.0.0.5",
                             dst=f"10.0.0.{10 + i % 20}", sport=443, dport=40000, tcp_flags="SA"))
    assert run_rules(pk) == set()


def test_syn_flood():
    pk = [syn(100 + i * 0.001, f"1.2.{i % 250}.{i % 200 + 1}", "10.0.0.5", 80) for i in range(2000)]
    assert "syn_flood" in run_rules(pk)


def test_arp_spoof():
    a = PacketInfo(ts=1, length=42, proto="ARP", arp_op=2, arp_psrc="10.0.0.1", arp_hwsrc="aa:aa:aa:aa:aa:01")
    b = PacketInfo(ts=2, length=42, proto="ARP", arp_op=2, arp_psrc="10.0.0.1", arp_hwsrc="bb:bb:bb:bb:bb:66")
    assert "arp_spoof" in run_rules([a, b])


def test_brute_force_sliding():
    pk = [syn(100 + i * 0.5, "10.0.0.66", "10.0.0.22", 22) for i in range(40)]
    assert "brute_force" in run_rules(pk)


def test_dns_tunnel():
    pk = [PacketInfo(ts=100 + i * 0.2, length=120, proto="UDP", src="10.0.0.35", dst="10.0.0.1",
                     sport=50000 + i, dport=53, dns_qname="x7k2p9q4mz8w3n5b6v1c0r2t4y6u8i9o0pa7s5d3f.evil.xyz")
          for i in range(10)]
    assert "dns_tunnel" in run_rules(pk)


def test_ewma_flags_spike():
    sd = StatisticalDetector(CFG["statistical"])
    agg = WindowAggregator(5, lambda ws: out.extend(sd.on_window(ws)))
    out = []
    for w in range(60):
        n = 1000 if w == 55 else 50
        for i in range(n):
            agg.add(PacketInfo(ts=w * 5 + i * 5 / n, length=100, proto="UDP", src="a", dst="b",
                               sport=5000, dport=6000))
    agg.flush()
    assert any(a.category == "traffic_anomaly" for a in out)


def test_jitter():
    assert jitter_ms([10, 12, 10, 14]) == (2 + 2 + 4) / 3


def test_perf_unreachable_and_loss():
    an = PerfAnalyzer({"rtt_ms": 100, "jitter_ms": 30, "loss_pct": 2})
    s = PerfSample(ts=0, target="x", method="icmp", rtt_avg=None, rtt_min=None, rtt_max=None,
                   jitter=None, loss_pct=100, sent=5)
    assert an.check(s)[0].category == "host_unreachable"
    s2 = PerfSample(ts=1, target="y", method="icmp", rtt_avg=20, rtt_min=19, rtt_max=21,
                    jitter=1, loss_pct=40, sent=5)
    assert any(a.category == "packet_loss" for a in an.check(s2))
