#!/usr/bin/env python3
"""NetSentinel командын мөрийн интерфэйс.

Жишээ:
  sudo python3 main.py live -c config.yaml           # бодит цагийн хяналт
  python3 main.py train  --pcap normal.pcap          # хэвийн урсгалаар ML загвар сургах
  python3 main.py pcap   --pcap capture.pcap         # PCAP файлыг шинжлэх
  python3 main.py probe                              # нэг удаагийн гүйцэтгэлийн хэмжилт
  python3 main.py dashboard                          # веб самбар (http://127.0.0.1:8050)
"""
from __future__ import annotations

import argparse
import logging

import numpy as np

from netsentinel.capture import read_pcap
from netsentinel.config import load_config
from netsentinel.detectors import MLDetector
from netsentinel.engine import Engine
from netsentinel.features import WindowAggregator
from netsentinel.perf_monitor import PerfAnalyzer, probe_targets
from netsentinel.storage import Storage


def cmd_live(cfg, args):
    ml = MLDetector(cfg["ml"])
    if ml.load():
        logging.info("ML загварыг %s файлаас ачааллаа", cfg["ml"]["model_path"])
    else:
        logging.info("ML загвар олдсонгүй: эхний %d цонхоор онлайн сургана", cfg["ml"]["train_windows"])
    Engine(cfg, Storage(cfg["general"]["db_path"]), ml).run_live()


def cmd_train(cfg, args):
    vecs = []
    agg = WindowAggregator(cfg["general"]["window_seconds"], lambda ws: vecs.append(ws.vector()))
    for p in read_pcap(args.pcap):
        agg.add(p)
    agg.flush()
    ml = MLDetector(cfg["ml"])
    ml.fit(np.array(vecs))
    ml.save()
    print(f"{len(vecs)} цонхоор сургалаа. Босго={ml.threshold:.4f} -> {cfg['ml']['model_path']}")


def cmd_pcap(cfg, args):
    ml = MLDetector(cfg["ml"])
    ml.load()
    eng = Engine(cfg, Storage(cfg["general"]["db_path"]), ml)
    eng.run_offline(read_pcap(args.pcap))
    print(f"\nПакет: {eng.packets}, alert: {len(eng.alerts.emitted)} "
          f"(давхардсан {eng.alerts.suppressed} дарагдсан)")


def cmd_probe(cfg, args):
    an = PerfAnalyzer(cfg["performance"]["sla"])
    for s in probe_targets(cfg["performance"]):
        rtt = f"{s.rtt_avg:.2f}" if s.rtt_avg is not None else "—"
        jit = f"{s.jitter:.2f}" if s.jitter is not None else "—"
        print(f"{s.target:22} {s.method:4} RTT={rtt} мс  jitter={jit} мс  loss={s.loss_pct}%")
        for a in an.check(s):
            print("   ⚠", a.description)


def cmd_dashboard(cfg, args):
    from netsentinel.dashboard import run
    d = cfg["dashboard"]
    run(cfg["general"]["db_path"], d["host"], d["port"])


def main():
    ap = argparse.ArgumentParser(description="NetSentinel сүлжээний хяналтын систем")
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("live")
    sub.add_parser("probe")
    sub.add_parser("dashboard")
    for name in ("train", "pcap"):
        sp = sub.add_parser(name)
        sp.add_argument("--pcap", required=True)
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    {"live": cmd_live, "train": cmd_train, "pcap": cmd_pcap,
     "probe": cmd_probe, "dashboard": cmd_dashboard}[args.cmd](cfg, args)


if __name__ == "__main__":
    main()
