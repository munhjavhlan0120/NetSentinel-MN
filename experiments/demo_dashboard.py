#!/usr/bin/env python3
"""Туршилтын PCAP-аар самбарын демо өгөгдлийн сан үүсгэнэ (цагийг одоо руу шилжүүлнэ).

  python3 experiments/demo_dashboard.py data/lab.pcap demo.db
  python3 main.py dashboard   (config.yaml-ийн db_path-ыг demo.db болгоно)
"""
from __future__ import annotations

import os
import pickle
import sqlite3
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netsentinel.capture import read_pcap  # noqa: E402
from netsentinel.config import load_config  # noqa: E402
from netsentinel.detectors import MLDetector  # noqa: E402
from netsentinel.engine import Engine  # noqa: E402
from netsentinel.features import WindowAggregator  # noqa: E402
from netsentinel.storage import Storage  # noqa: E402
from perf_sim import simulate  # noqa: E402


def main(pcap: str = "data/lab.pcap", db_path: str = "demo.db") -> None:
    cache = pcap + ".pkl"
    pk = pickle.load(open(cache, "rb")) if os.path.exists(cache) else list(read_pcap(pcap))
    cfg = load_config("config.yaml")
    cfg["alerting"]["console"] = False
    cfg["general"]["log_path"] = None
    t0 = pk[0].ts
    vecs: list = []
    agg = WindowAggregator(cfg["general"]["window_seconds"], lambda ws: vecs.append(ws.vector()))
    for p in pk:
        if p.ts >= t0 + 900:
            break
        agg.add(p)
    ml = MLDetector(cfg["ml"])
    ml.fit(np.array(vecs[1:]))
    if os.path.exists(db_path):
        os.remove(db_path)
    eng = Engine(cfg, Storage(db_path), ml)
    eng.run_offline(iter(pk))

    # Цагийг одоо руу шилжүүлэх ба гүйцэтгэлийн демо өгөгдөл нэмэх
    db = sqlite3.connect(db_path)
    shift = time.time() - db.execute("SELECT MAX(ts_end) FROM traffic_windows").fetchone()[0]
    db.execute("UPDATE traffic_windows SET ts_start=ts_start+?, ts_end=ts_end+?", (shift, shift))
    db.execute("UPDATE alerts SET ts=ts+?", (shift,))
    s = [x for x in simulate() if 4200 <= x.ts < 6600]
    now = time.time()
    for x in s:
        db.execute("INSERT INTO perf_samples(ts,target,method,rtt_avg,jitter,loss_pct) VALUES (?,?,?,?,?,?)",
                   (x.ts - s[-1].ts + now, "8.8.8.8", "icmp", x.rtt_avg, x.jitter, x.loss_pct))
    db.commit()
    print(f"{db_path}: {len(eng.alerts.emitted)} alert, {eng.alerts.suppressed} дарагдсан")


if __name__ == "__main__":
    main(*sys.argv[1:])
