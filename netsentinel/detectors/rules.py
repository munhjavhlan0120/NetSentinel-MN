"""Дүрэмд суурилсан (signature/threshold) илрүүлэгч."""
from __future__ import annotations

import math
from collections import Counter, deque

from ..features import WindowStats
from ..models import Alert, PacketInfo


def label_entropy(name: str) -> float:
    """DNS нэрийн хамгийн урт label-ийн Шенноны энтропи."""
    labels = name.split(".")
    longest = max(labels, key=len) if labels else ""
    if not longest:
        return 0.0
    c = Counter(longest)
    n = len(longest)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class RuleDetector:
    name = "rule"

    def __init__(self, cfg: dict):
        self.c = cfg
        self.arp_table: dict[str, str] = {}      # IP -> MAC
        self._arp_alerts: list[Alert] = []
        # Урт хугацааны (гулсах) цонхны төлөв
        self._auth_hist: deque = deque()          # (window_end, Counter)
        self._port_seen: dict[str, dict[int, float]] = {}   # src -> {port: last_ts}

    # ---- пакет бүр дээр ажиллах төлөвт (stateful) шалгалт ---------------
    def on_packet(self, p: PacketInfo) -> None:
        if p.proto != "ARP" or p.arp_op != 2 or not p.arp_psrc:
            return
        known = self.arp_table.get(p.arp_psrc)
        if known is None:
            self.arp_table[p.arp_psrc] = p.arp_hwsrc
        elif known != p.arp_hwsrc:
            self._arp_alerts.append(Alert(
                ts=p.ts, severity="high", category="arp_spoof", detector=self.name,
                src=p.arp_hwsrc, dst=p.arp_psrc,
                description=f"ARP spoofing: {p.arp_psrc} хаягийг {known} биш "
                            f"{p.arp_hwsrc} MAC зарлаж байна",
                extra={"known_mac": known}))

    # ---- цонх бүр дээр ажиллах босгон шалгалт ----------------------------
    def on_window(self, ws: WindowStats) -> list[Alert]:
        c, ts, out = self.c, ws.end, []

        def target_of(src):
            """Самбарын граф-д зориулж эх үүсвэрийн зорилтыг тодорхойлно."""
            d = ws.src_dsts.get(src) or set()
            return next(iter(d)) if len(d) == 1 else ("олон хост" if d else None)

        def top_source(dst):
            cnt = ws.dst_top_src.get(dst)
            if not cnt:
                return None
            s, n = cnt.most_common(1)[0]
            return s if n >= 0.5 * sum(cnt.values()) else None   # хуурамч олон эх бол None
        out.extend(self._arp_alerts)
        self._arp_alerts = []

        # 1. Порт скан ба хост тойрох (sweep)
        for src, ports in ws.src_dports.items():
            if len(ports) >= c["port_scan_ports"]:
                out.append(Alert(ts, "medium", "port_scan", self.name,
                                 f"{src} нь {len(ports)} ялгаатай порт руу хандсан",
                                 src=src, dst=target_of(src), score=len(ports)))
        for src, dsts in ws.src_dsts.items():
            if len(dsts) >= c["host_sweep_hosts"]:
                out.append(Alert(ts, "medium", "host_sweep", self.name,
                                 f"{src} нь {len(dsts)} хост руу хандсан (sweep)",
                                 src=src, dst="сүлжээ (sweep)", score=len(dsts)))

        # 2. SYN flood
        for dst, syn in ws.dst_syn.items():
            synack = ws.dst_synack_out.get(dst, 0)
            ratio = syn / (synack + 1)
            if syn >= c["syn_flood_syn"] and ratio >= c["syn_flood_ratio"]:
                srcs = len(ws.dst_top_src[dst])
                out.append(Alert(ts, "critical", "syn_flood", self.name,
                                 f"{dst} руу {syn} SYN (SYN/SYN-ACK={ratio:.1f}, "
                                 f"{srcs} эх үүсвэр)", src=top_source(dst), dst=dst, score=syn,
                                 extra={"sources": srcs}))

        # 3. ICMP flood
        for dst, n in ws.dst_icmp_req.items():
            if n >= c["icmp_flood_pkts"]:
                out.append(Alert(ts, "high", "icmp_flood", self.name,
                                 f"{dst} руу {n} ICMP echo request", src=top_source(dst), dst=dst,
                                 score=n))

        # 3б. Удаан скан: гулсах хугацаанд (жиш. 300 с) нэг эх үүсвэрийн хандсан портууд
        fast = {a.src for a in out if a.category == "port_scan"}
        horizon = ts - c["slow_scan_horizon_s"]
        for src, ports in ws.src_dports.items():
            seen = self._port_seen.setdefault(src, {})
            for p in ports:
                seen[p] = ts
        for src in list(self._port_seen):
            seen = {p: t for p, t in self._port_seen[src].items() if t >= horizon}
            if not seen:
                del self._port_seen[src]
                continue
            self._port_seen[src] = seen
            if src in fast:
                # Хурдан скан аль хэдийн мэдэгдсэн тул санах ойг цэвэрлэнэ (давхар alert-аас сэргийлнэ)
                del self._port_seen[src]
                continue
            if len(seen) >= c["slow_scan_ports"] and src in ws.src_dports:
                out.append(Alert(ts, "medium", "slow_scan", self.name,
                                 f"{src} нь сүүлийн {c['slow_scan_horizon_s']} с-д {len(seen)} "
                                 f"ялгаатай порт руу аажмаар хандсан", src=src, dst=target_of(src),
                                 score=len(seen)))

        # 4. Нууц үг таах (brute force): сүүлийн N секундийн шинэ холболтын нийлбэр
        self._auth_hist.append((ts, ws.src_auth_syn))
        while self._auth_hist and self._auth_hist[0][0] <= ts - c["brute_force_horizon_s"]:
            self._auth_hist.popleft()
        auth_total: Counter = Counter()
        for _, cnt in self._auth_hist:
            auth_total.update(cnt)
        for (src, dst, port), n in auth_total.items():
            if n >= c["brute_force_conns"] and ws.src_auth_syn.get((src, dst, port)):
                out.append(Alert(ts, "high", "brute_force", self.name,
                                 f"{src} -> {dst}:{port} руу {c['brute_force_horizon_s']} с-д {n} шинэ холболт",
                                 src=src, dst=dst, score=n, extra={"port": port}))

        # 5. DNS tunneling / DGA шинжтэй асуулга
        susp: Counter = Counter()
        zone: dict[str, Counter] = {}
        for src, q in ws.dns_queries:
            if len(q) >= c["dns_qname_len"] or label_entropy(q) >= c["dns_entropy"]:
                susp[src] += 1
                zone.setdefault(src, Counter())[".".join(q.split(".")[-2:])] += 1
        for src, n in susp.items():
            if n >= c["dns_suspicious_count"]:
                out.append(Alert(ts, "medium", "dns_tunnel", self.name,
                                 f"{src} нь {n} сэжигтэй урт/энтропи өндөр DNS асуулга илгээсэн",
                                 src=src, dst=zone[src].most_common(1)[0][0], score=n))
        return out
