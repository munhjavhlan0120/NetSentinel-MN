"""Системийн өгөгдлийн бүтэц."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass(slots=True)
class PacketInfo:
    """Scapy пакетаас задалсан хөнгөн бүтэц (санах ой хэмнэнэ)."""
    ts: float
    length: int
    proto: str                     # TCP / UDP / ICMP / ARP / OTHER
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""            # жишээ: "S", "SA", "A", "PA", "R"
    icmp_type: Optional[int] = None
    arp_op: Optional[int] = None   # 1=request, 2=reply
    arp_psrc: Optional[str] = None
    arp_hwsrc: Optional[str] = None
    dns_qname: Optional[str] = None


@dataclass
class Alert:
    ts: float
    severity: str                  # low / medium / high / critical
    category: str                  # port_scan, syn_flood, ...
    detector: str                  # rule / statistical / ml / performance
    description: str
    src: Optional[str] = None
    dst: Optional[str] = None
    score: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Давхардал шүүх түлхүүр."""
        return f"{self.category}|{self.detector}|{self.src}|{self.dst}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PerfSample:
    ts: float
    target: str
    method: str                    # icmp / tcp
    rtt_avg: Optional[float]
    rtt_min: Optional[float]
    rtt_max: Optional[float]
    jitter: Optional[float]
    loss_pct: float
    rx_mbps: Optional[float] = None
    tx_mbps: Optional[float] = None
    sent: Optional[int] = None         # илгээсэн probe-ийн тоо

    @staticmethod
    def now(**kw) -> "PerfSample":
        return PerfSample(ts=time.time(), **kw)
