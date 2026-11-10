"""Пакетуудыг тогтмол хугацааны цонхоор (time window) нэгтгэж шинж чанар гаргах."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import PacketInfo

# ML болон статистик шинжилгээнд ашиглах шинж чанарын дараалал
FEATURE_NAMES = [
    "pkts", "bytes", "tcp", "udp", "icmp", "arp", "syn", "synack", "rst",
    "uniq_srcs", "uniq_dsts", "uniq_dports", "dns_q", "dns_long",
    "mean_size", "dport_entropy", "max_src_dports", "max_dst_syn",
    "syn_ratio", "icmp_req", "max_src_dsts", "max_auth_syn",
]


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def is_syn(flags: str) -> bool:
    return "S" in flags and "A" not in flags


def is_synack(flags: str) -> bool:
    return "S" in flags and "A" in flags


@dataclass
class WindowStats:
    start: float
    end: float
    features: dict[str, float] = field(default_factory=dict)
    # эх үүсвэр тус бүрийн мэдээлэл
    src_dports: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    src_dsts: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    src_auth_syn: Counter = field(default_factory=Counter)
    # очих хаяг тус бүрийн мэдээлэл
    dst_syn: Counter = field(default_factory=Counter)
    dst_synack_out: Counter = field(default_factory=Counter)
    dst_icmp_req: Counter = field(default_factory=Counter)
    dst_top_src: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    dns_queries: list[tuple[str, str]] = field(default_factory=list)  # (src, qname)

    def vector(self) -> list[float]:
        return [float(self.features.get(n, 0.0)) for n in FEATURE_NAMES]


class WindowAggregator:
    """Цонх дүүрэх бүрт on_window(WindowStats) дуудагдана."""

    def __init__(self, window_s: float, on_window: Callable[[WindowStats], None],
                 auth_ports: Optional[set[int]] = None, dns_long_len: int = 52):
        self.window_s = window_s
        self.on_window = on_window
        self.auth_ports = auth_ports or {22, 21, 23, 3389}
        self.dns_long_len = dns_long_len
        self._start: Optional[float] = None
        self._reset_buffers()

    def _reset_buffers(self) -> None:
        self._pkts = 0
        self._bytes = 0
        self._proto = Counter()
        self._flags = Counter()
        self._srcs: set = set()
        self._dsts: set = set()
        self._dports = Counter()
        self._dns_q = 0
        self._dns_long = 0
        self._icmp_req = 0
        self._ws: Optional[WindowStats] = None

    def _ensure(self, ts: float) -> None:
        if self._start is None:
            self._start = math.floor(ts / self.window_s) * self.window_s
        while ts >= self._start + self.window_s:
            self.flush()
            self._start += self.window_s
        if self._ws is None:
            self._ws = WindowStats(start=self._start, end=self._start + self.window_s)

    def add(self, p: PacketInfo) -> None:
        self._ensure(p.ts)
        ws = self._ws
        assert ws is not None
        self._pkts += 1
        self._bytes += p.length
        self._proto[p.proto] += 1
        if p.src:
            self._srcs.add(p.src)
        if p.dst:
            self._dsts.add(p.dst)

        if p.proto == "TCP":
            f = p.tcp_flags
            if is_syn(f):
                self._flags["syn"] += 1
                ws.dst_syn[p.dst] += 1
                ws.dst_top_src[p.dst][p.src] += 1
                ws.src_dports[p.src].add(p.dport)
                ws.src_dsts[p.src].add(p.dst)
                self._dports[p.dport] += 1
                if p.dport in self.auth_ports:
                    ws.src_auth_syn[(p.src, p.dst, p.dport)] += 1
            elif is_synack(f):
                self._flags["synack"] += 1
                ws.dst_synack_out[p.src] += 1   # сервер өөрөө хариулсан
            if "R" in f:
                self._flags["rst"] += 1
        elif p.proto == "UDP":
            # Зөвхөн клиентээс эхэлсэн урсгалыг (эх порт >= 1024) скан шинжилгээнд тооцно.
            # Ингэснээр DNS/NTP серверийн хариу (sport=53/123) хуурамч скан болж харагдахгүй.
            if p.sport is not None and p.sport >= 1024 and p.dport != 53:
                ws.src_dports[p.src].add(p.dport)
                ws.src_dsts[p.src].add(p.dst)
                self._dports[p.dport] += 1
            if p.dns_qname:
                self._dns_q += 1
                ws.dns_queries.append((p.src, p.dns_qname))
                if len(p.dns_qname) >= self.dns_long_len:
                    self._dns_long += 1
        elif p.proto == "ICMP":
            if p.icmp_type == 8:
                self._icmp_req += 1
                ws.dst_icmp_req[p.dst] += 1
                ws.dst_top_src[p.dst][p.src] += 1
                ws.src_dsts[p.src].add(p.dst)

    def flush(self) -> None:
        if self._start is None:
            return
        ws = self._ws or WindowStats(start=self._start, end=self._start + self.window_s)
        ws.features = {
            "pkts": self._pkts,
            "bytes": self._bytes,
            "tcp": self._proto["TCP"],
            "udp": self._proto["UDP"],
            "icmp": self._proto["ICMP"],
            "arp": self._proto["ARP"],
            "syn": self._flags["syn"],
            "synack": self._flags["synack"],
            "rst": self._flags["rst"],
            "uniq_srcs": len(self._srcs),
            "uniq_dsts": len(self._dsts),
            "uniq_dports": len(self._dports),
            "dns_q": self._dns_q,
            "dns_long": self._dns_long,
            "mean_size": self._bytes / self._pkts if self._pkts else 0.0,
            "dport_entropy": shannon_entropy(self._dports),
            "max_src_dports": max((len(v) for v in ws.src_dports.values()), default=0),
            "max_dst_syn": max(ws.dst_syn.values(), default=0),
            "syn_ratio": self._flags["syn"] / (self._flags["synack"] + 1),
            "icmp_req": self._icmp_req,
            "max_src_dsts": max((len(v) for v in ws.src_dsts.values()), default=0),
            "max_auth_syn": max(ws.src_auth_syn.values(), default=0),
        }
        self.on_window(ws)
        self._reset_buffers()
