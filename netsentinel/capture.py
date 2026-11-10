"""Пакет барих (live) болон PCAP унших модуль. Scapy ашиглана."""
from __future__ import annotations

import logging
from typing import Callable, Iterator, Optional

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, AsyncSniffer, PcapReader  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

from .models import PacketInfo

log = logging.getLogger(__name__)


def parse_packet(pkt) -> Optional[PacketInfo]:
    """Scapy пакетаас шаардлагатай талбаруудыг задлана."""
    ts = float(pkt.time)
    length = len(pkt)

    if ARP in pkt:
        a = pkt[ARP]
        return PacketInfo(ts=ts, length=length, proto="ARP", src=a.psrc, dst=a.pdst,
                          arp_op=int(a.op), arp_psrc=a.psrc, arp_hwsrc=a.hwsrc)

    if IP in pkt:
        l3 = pkt[IP]
    elif IPv6 in pkt:
        l3 = pkt[IPv6]
    else:
        return None

    info = PacketInfo(ts=ts, length=length, proto="OTHER", src=l3.src, dst=l3.dst)
    if TCP in pkt:
        t = pkt[TCP]
        info.proto, info.sport, info.dport = "TCP", int(t.sport), int(t.dport)
        info.tcp_flags = str(t.flags)
    elif UDP in pkt:
        u = pkt[UDP]
        info.proto, info.sport, info.dport = "UDP", int(u.sport), int(u.dport)
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            try:
                info.dns_qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:  # pragma: no cover
                pass
    elif ICMP in pkt:
        info.proto, info.icmp_type = "ICMP", int(pkt[ICMP].type)
    return info


def read_pcap(path: str) -> Iterator[PacketInfo]:
    """PCAP файлыг урсгалаар (санах ойд бүгдийг ачаалалгүй) уншина."""
    with PcapReader(path) as reader:
        for pkt in reader:
            info = parse_packet(pkt)
            if info is not None:
                yield info


class LiveCapture:
    """Сүлжээний интерфэйсээс бодит цагт пакет барина (root эрх шаардлагатай)."""

    def __init__(self, callback: Callable[[PacketInfo], None],
                 iface: Optional[str] = None, bpf: str = ""):
        self._cb = callback
        self._sniffer = AsyncSniffer(iface=iface, filter=bpf or None,
                                     prn=self._handle, store=False)

    def _handle(self, pkt) -> None:
        try:
            info = parse_packet(pkt)
            if info is not None:
                self._cb(info)
        except Exception as exc:  # pragma: no cover
            log.debug("parse error: %s", exc)

    def start(self) -> None:
        self._sniffer.start()

    def stop(self) -> None:
        try:
            self._sniffer.stop()
        except Exception:  # pragma: no cover
            pass
