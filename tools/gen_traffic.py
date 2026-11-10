#!/usr/bin/env python3
"""Туршилтын зориулалттай, шошготой (labeled) сүлжээний урсгал үүсгэгч.

Хэвийн урсгал (веб, DNS, ICMP, ARP, SSH) дээр хуваарийн дагуу 8 төрлийн халдлага
ба 1 хууль ёсны ачааллын огцом өсөлт (flash crowd) нэмж PCAP болон шошгын CSV гаргана.

  python3 tools/gen_traffic.py --out data/lab.pcap --labels data/labels.csv
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import string

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw,  # type: ignore
                       PcapWriter)

NET = "192.168.56."
GW, WEB, SSH = NET + "1", NET + "100", NET + "101"
CLIENTS = [NET + str(i) for i in range(10, 40)]
ATTACKER, STEALTH = NET + "66", NET + "77"
MAC = {ip: "08:00:27:%02x:%02x:%02x" % (0x10, int(ip.split(".")[-1]) // 256, int(ip.split(".")[-1]) % 256)
       for ip in CLIENTS + [GW, WEB, SSH, ATTACKER, STEALTH]}
EXTERNAL = ["142.250.%d.%d" % (random.Random(i).randint(0, 255), random.Random(i + 99).randint(1, 254))
            for i in range(25)]
DOMAINS = ["www.google.com", "mail.google.com", "www.must.edu.mn", "sisi.must.edu.mn", "www.facebook.com",
           "static.xx.fbcdn.net", "github.com", "api.github.com", "pypi.org", "files.pythonhosted.org",
           "www.youtube.com", "i.ytimg.com", "ikon.mn", "news.mn", "www.gogo.mn", "teams.microsoft.com",
           "login.microsoftonline.com", "ubuntu.com", "archive.ubuntu.com", "time.cloudflare.com"]

# (эхлэх с, дуусах с, төрөл) — шошгын хуваарь
SCHEDULE = [
    (1000, 1040, "port_scan"),
    (1200, 1260, "brute_force"),
    (1400, 1440, "syn_flood"),
    (1600, 1640, "icmp_flood"),
    (1800, 1860, "arp_spoof"),
    (2000, 2060, "dns_tunnel"),
    (2200, 2230, "host_sweep"),
    (2300, 2330, "benign_burst"),      # хууль ёсны ачаалал — халдлага БИШ
    (2350, 2400, "slow_scan"),
]


class Gen:
    def __init__(self, out: str, t0: float, seed: int):
        self.w = PcapWriter(out, sync=False)
        self.t0 = t0
        self.r = random.Random(seed)
        self.n = 0
        self.port = 40000

    def emit(self, t: float, pkt) -> None:
        pkt.time = self.t0 + t
        self.w.write(pkt)
        self.n += 1

    def eth(self, src_ip: str, dst_ip: str):
        return Ether(src=MAC.get(src_ip, "02:00:00:00:00:01"), dst=MAC.get(dst_ip, MAC[GW]))

    def eport(self) -> int:
        self.port = 40000 + (self.port - 39999) % 20000
        return self.port

    # ---- хэвийн урсгалын элементүүд --------------------------------------
    def tcp_session(self, t: float, c: str, s: str, dport: int, n_data: int = 4, size: int = 900) -> None:
        r, sp = self.r, self.eport()
        rtt = r.uniform(0.002, 0.04) if s.startswith(NET) else r.uniform(0.03, 0.09)
        e1, e2 = self.eth(c, s), self.eth(s, c)
        self.emit(t, e1 / IP(src=c, dst=s) / TCP(sport=sp, dport=dport, flags="S"))
        self.emit(t + rtt, e2 / IP(src=s, dst=c) / TCP(sport=dport, dport=sp, flags="SA"))
        self.emit(t + rtt * 1.05, e1 / IP(src=c, dst=s) / TCP(sport=sp, dport=dport, flags="A"))
        tt = t + rtt * 1.1
        for _ in range(n_data):
            self.emit(tt, e1 / IP(src=c, dst=s) / TCP(sport=sp, dport=dport, flags="PA") / Raw(b"x" * r.randint(60, 400)))
            tt += rtt
            self.emit(tt, e2 / IP(src=s, dst=c) / TCP(sport=dport, dport=sp, flags="PA") / Raw(b"y" * r.randint(min(200, size), size)))
            tt += r.uniform(0.001, 0.05)
        self.emit(tt, e1 / IP(src=c, dst=s) / TCP(sport=sp, dport=dport, flags="FA"))
        self.emit(tt + rtt, e2 / IP(src=s, dst=c) / TCP(sport=dport, dport=sp, flags="FA"))

    def dns(self, t: float, c: str, name: str) -> None:
        sp = self.eport()
        q = IP(src=c, dst=GW) / UDP(sport=sp, dport=53) / DNS(id=self.r.randint(0, 65535), rd=1, qd=DNSQR(qname=name))
        self.emit(t, self.eth(c, GW) / q)
        a = (IP(src=GW, dst=c) / UDP(sport=53, dport=sp) /
             DNS(id=q[DNS].id, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=self.r.choice(EXTERNAL))))
        self.emit(t + self.r.uniform(0.005, 0.03), self.eth(GW, c) / a)

    def ping(self, t: float, c: str, d: str) -> None:
        self.emit(t, self.eth(c, d) / IP(src=c, dst=d) / ICMP(type=8) / Raw(b"p" * 56))
        self.emit(t + self.r.uniform(0.001, 0.02), self.eth(d, c) / IP(src=d, dst=c) / ICMP(type=0) / Raw(b"p" * 56))

    def arp(self, t: float, asker: str, target: str) -> None:
        self.emit(t, Ether(src=MAC[asker], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=asker, pdst=target, hwsrc=MAC[asker]))
        self.emit(t + 0.0005, Ether(src=MAC[target], dst=MAC[asker]) /
                  ARP(op=2, psrc=target, pdst=asker, hwsrc=MAC[target], hwdst=MAC[asker]))

    def normal_second(self, t: float, mult: float = 1.0) -> None:
        r = self.r
        lam = mult * (3.0 * (1 + 0.35 * math.sin(2 * math.pi * t / 900)) + r.gauss(0, 0.3))
        for _ in range(max(0, int(r.expovariate(1 / max(lam, 0.1))))):
            c = r.choice(CLIENTS)
            if r.random() < 0.3:
                self.tcp_session(t + r.random(), c, WEB, r.choice([80, 443]), r.randint(2, 6))
            else:
                self.tcp_session(t + r.random(), c, r.choice(EXTERNAL), 443, r.randint(2, 8), 1400)
        for _ in range(int(r.expovariate(1 / (1.5 * mult)))):
            self.dns(t + r.random(), r.choice(CLIENTS), r.choice(DOMAINS))
        if r.random() < 0.15:
            self.ping(t + r.random(), r.choice(CLIENTS), r.choice([GW, WEB, "8.8.8.8"]))
        if r.random() < 0.08:
            self.arp(t + r.random(), r.choice(CLIENTS), r.choice([GW, WEB, SSH]))
        if r.random() < 0.01:   # админы хууль ёсны SSH нэвтрэлт
            self.tcp_session(t + r.random(), NET + "20", SSH, 22, 12, 300)

    # ---- халдлагууд ---------------------------------------------------------
    def attack(self, kind: str, t: float, t_end: float) -> None:
        r = self.r
        if kind == "port_scan":           # nmap -sS: 1000 порт / 40 с
            ports = r.sample(range(1, 10000), 1000) + [22, 80, 443]
            dt = (t_end - t) / len(ports)
            for i, p in enumerate(ports):
                ts = t + i * dt
                sp = r.randint(30000, 65000)
                self.emit(ts, self.eth(ATTACKER, WEB) / IP(src=ATTACKER, dst=WEB) / TCP(sport=sp, dport=p, flags="S"))
                fl = "SA" if p in (80, 443) else "RA"
                self.emit(ts + 0.001, self.eth(WEB, ATTACKER) / IP(src=WEB, dst=ATTACKER) / TCP(sport=p, dport=sp, flags=fl))
        elif kind == "brute_force":       # hydra ssh: ~2 оролдлого/с
            ts = t
            while ts < t_end:
                self.tcp_session(ts, ATTACKER, SSH, 22, 3, 120)
                ts += r.uniform(0.3, 0.7)
        elif kind == "syn_flood":         # hping3 -S --flood --rand-source: 800 pps
            n = int((t_end - t) * 800)
            for i in range(n):
                ts = t + i / 800
                src = "%d.%d.%d.%d" % (r.randint(1, 223), r.randint(0, 255), r.randint(0, 255), r.randint(1, 254))
                sp = r.randint(1024, 65535)
                self.emit(ts, Ether(src="02:aa:bb:cc:dd:ee", dst=MAC[WEB]) / IP(src=src, dst=WEB) / TCP(sport=sp, dport=80, flags="S"))
                if r.random() < 0.08:     # backlog дүүрсэн тул цөөн SYN-ACK
                    self.emit(ts + 0.001, self.eth(WEB, GW) / IP(src=WEB, dst=src) / TCP(sport=80, dport=sp, flags="SA"))
        elif kind == "icmp_flood":        # hping3 --icmp --flood: 300 pps
            n = int((t_end - t) * 300)
            for i in range(n):
                ts = t + i / 300
                self.emit(ts, self.eth(ATTACKER, WEB) / IP(src=ATTACKER, dst=WEB) / ICMP(type=8) / Raw(b"A" * 512))
                if r.random() < 0.6:
                    self.emit(ts + 0.0005, self.eth(WEB, ATTACKER) / IP(src=WEB, dst=ATTACKER) / ICMP(type=0) / Raw(b"A" * 512))
        elif kind == "arp_spoof":         # arpspoof: гарцын IP-г халдагчийн MAC-аар зарлана
            ts = t
            while ts < t_end:
                for victim in r.sample(CLIENTS, 5):
                    self.emit(ts, Ether(src=MAC[ATTACKER], dst=MAC[victim]) /
                              ARP(op=2, psrc=GW, pdst=victim, hwsrc=MAC[ATTACKER], hwdst=MAC[victim]))
                ts += 2.0
        elif kind == "dns_tunnel":        # iodine / dnscat2 төст: урт base32 label
            ts, victim = t, NET + "35"
            while ts < t_end:
                lab = "".join(r.choice(string.ascii_lowercase + "234567") for _ in range(r.randint(48, 60)))
                self.dns(ts, victim, f"{lab}.{r.randint(0, 999)}.t.evil-tunnel.xyz")
                ts += r.uniform(0.2, 0.45)
        elif kind == "host_sweep":        # nmap -sn 192.168.56.0/24
            hosts = [NET + str(i) for i in range(1, 255)]
            dt = (t_end - t) / len(hosts)
            for i, h in enumerate(hosts):
                ts = t + i * dt
                self.emit(ts, self.eth(ATTACKER, h) / IP(src=ATTACKER, dst=h) / ICMP(type=8))
                if h in MAC:
                    self.emit(ts + 0.001, self.eth(h, ATTACKER) / IP(src=h, dst=ATTACKER) / ICMP(type=0))
        elif kind == "benign_burst":      # хууль ёсны ачаалал (flash crowd) -> урсгал x3
            for s in range(int(t), int(t_end)):
                self.normal_second(float(s), mult=3.0)
        elif kind == "slow_scan":         # nmap -T1 төст: 1 порт / с — босгоос доогуур
            ports = r.sample(range(1, 10000), int(t_end - t))
            for i, p in enumerate(ports):
                sp = r.randint(30000, 65000)
                self.emit(t + i, self.eth(STEALTH, SSH) / IP(src=STEALTH, dst=SSH) / TCP(sport=sp, dport=p, flags="S"))
                self.emit(t + i + 0.001, self.eth(SSH, STEALTH) / IP(src=SSH, dst=STEALTH) / TCP(sport=p, dport=sp, flags="RA"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/lab.pcap")
    ap.add_argument("--labels", default="data/labels.csv")
    ap.add_argument("--duration", type=int, default=2400)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--t0", type=float, default=1767225600.0)   # 2026-01-01 00:00 UTC
    a = ap.parse_args()

    g = Gen(a.out, a.t0, a.seed)
    # Пакетын цагийн дарааллыг хадгалахын тулд секунд бүрийг буферлэж эрэмбэлнэ
    import heapq
    import itertools
    buf: list = []
    seq = itertools.count()
    real_emit = g.emit
    g.emit = lambda t, p: heapq.heappush(buf, (t, next(seq), p))  # type: ignore
    for s in range(a.duration):
        g.normal_second(float(s))
        for st, en, kind in SCHEDULE:
            if st == s:
                g.attack(kind, float(st), float(en))
        # одоогийн секундээс 2 секундийн өмнөх пакетуудыг бичнэ
        while buf and buf[0][0] < s - 2:
            t, _, p = heapq.heappop(buf)
            real_emit(t, p)
    while buf:
        t, _, p = heapq.heappop(buf)
        real_emit(t, p)
    g.w.close()

    with open(a.labels, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["start", "end", "type", "is_attack"])
        for st, en, kind in SCHEDULE:
            w.writerow([a.t0 + st, a.t0 + en, kind, int(kind != "benign_burst")])
    print(f"{g.n} пакет -> {a.out}; шошго -> {a.labels}")


if __name__ == "__main__":
    main()
