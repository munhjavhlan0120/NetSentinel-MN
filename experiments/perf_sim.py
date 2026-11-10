#!/usr/bin/env python3
"""Сүлжээний гүйцэтгэлийн доройтлын симуляци ба PerfAnalyzer-ийн үнэлгээ.

6 цагийн турш 10 секунд тутам 20 ping хийсэн мэт RTT цуваа үүсгэж 4 төрлийн үйл явдал
(түгжрэл, пакет алдагдал, маршрут өөрчлөгдөх, тасалдал) оруулна.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netsentinel.models import PerfSample  # noqa: E402
from netsentinel.perf_monitor import PerfAnalyzer, jitter_ms  # noqa: E402

STEP, HOURS, PINGS = 10, 6, 20
EVENTS = [  # (эхлэх с, дуусах с, нэр)
    (5400, 7200, "congestion"),     # 1:30–2:00 түгжрэл (дараалал)
    (10800, 11400, "loss_burst"),   # 3:00–3:10 пакет алдагдал 15%
    (14400, 21600, "route_change"), # 4:00-с RTT +35 мс (тогтвортой)
    (18000, 18180, "outage"),       # 5:00–5:03 бүрэн тасалдал
]


def simulate(seed: int = 3):
    r = np.random.default_rng(seed)
    out = []
    for i in range(HOURS * 3600 // STEP):
        t = i * STEP
        base, sd, loss_p = 22.0, 1.5, 0.002
        if 14400 <= t:
            base += 35.0
        if 5400 <= t < 7200:
            base += 60 + 40 * np.sin(np.pi * (t - 5400) / 1800)
            sd = 18.0
        if 10800 <= t < 11400:
            loss_p = 0.15
        if 18000 <= t < 18180:
            loss_p = 1.0
        rtts = [float(max(1.0, base + r.normal(0, sd) + r.exponential(1.0)))
                for _ in range(PINGS) if r.random() > loss_p]
        loss = 100.0 * (PINGS - len(rtts)) / PINGS
        out.append(PerfSample(ts=float(t), target="8.8.8.8", method="icmp",
                              rtt_avg=float(np.mean(rtts)) if rtts else None,
                              rtt_min=min(rtts) if rtts else None,
                              rtt_max=max(rtts) if rtts else None,
                              jitter=jitter_ms(rtts), loss_pct=loss, sent=PINGS))
    return out


def main(out_dir: str = "results"):
    samples = simulate()
    an = PerfAnalyzer({"rtt_ms": 100.0, "jitter_ms": 30.0, "loss_pct": 2.0})
    alerts = []
    for s in samples:
        alerts += an.check(s)
    res = {}
    for st, en, name in EVENTS:
        hit = [a for a in alerts if st <= a.ts < (en if name != "route_change" else st + 600)]
        res[name] = {"detected": bool(hit),
                     "delay_s": (min(a.ts for a in hit) - st) if hit else None,
                     "categories": sorted({a.category for a in hit})}

    def in_event(ts):
        return any(st <= ts < en + 60 for st, en, n in EVENTS if n != "route_change") or \
            (14400 <= ts < 14400 + 600)
    false_alarms = [a for a in alerts if not in_event(a.ts)]
    # "Наивный" арга: 1 хэмжилтийн алдагдлаар шууд дүгнэвэл
    naive_loss_fp = sum(1 for s in samples if s.loss_pct > 2.0 and not in_event(s.ts))
    summary = {"samples": len(samples), "alerts": len(alerts), "events": res,
               "false_alarms": len(false_alarms),
               "false_alarm_cats": sorted({a.category for a in false_alarms}),
               "naive_loss_false_alarms": naive_loss_fp}
    os.makedirs(out_dir, exist_ok=True)
    json.dump(summary, open(os.path.join(out_dir, "perf_metrics.json"), "w"), ensure_ascii=False, indent=2)
    np.savez(os.path.join(out_dir, "perf_series.npz"),
             t=np.array([s.ts for s in samples]),
             rtt=np.array([s.rtt_avg if s.rtt_avg is not None else np.nan for s in samples]),
             jit=np.array([s.jitter if s.jitter is not None else np.nan for s in samples]),
             loss=np.array([s.loss_pct for s in samples]),
             a_t=np.array([a.ts for a in alerts]),
             a_c=np.array([a.category for a in alerts]))
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
