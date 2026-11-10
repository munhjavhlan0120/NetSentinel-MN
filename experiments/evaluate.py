#!/usr/bin/env python3
"""Илрүүлэгчдийн үнэлгээ: шошготой PCAP дээр цонхны түвшний precision/recall/F1,
халдлагын төрөл тус бүрийн илрүүлэлт, саатал, гүйцэтгэл (throughput)-ийг тооцоолно.

  python3 experiments/evaluate.py --pcap data/lab.pcap --labels data/labels.csv --out results
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pickle
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentinel.capture import read_pcap  # noqa: E402
from netsentinel.config import load_config  # noqa: E402
from netsentinel.detectors import MLDetector  # noqa: E402
from netsentinel.engine import Engine  # noqa: E402
from netsentinel.features import WindowAggregator  # noqa: E402

TRAIN_SECONDS = 900   # эхний 15 минут — зөвхөн хэвийн урсгал (сургалт)


def load_packets(pcap: str):
    cache = pcap + ".pkl"
    if os.path.exists(cache):
        with open(cache, "rb") as fh:
            return pickle.load(fh), None
    t = time.perf_counter()
    pk = list(read_pcap(pcap))
    parse_s = time.perf_counter() - t
    with open(cache, "wb") as fh:
        pickle.dump(pk, fh)
    return pk, parse_s


def window_label(ws, we, labels):
    for st, en, kind, atk in labels:
        if ws < en and we > st:        # давхцал байвал
            return kind, atk
    return "normal", 0


def metrics(y, p):
    y, p = np.asarray(y, bool), np.asarray(p, bool)
    tp, fp = int((y & p).sum()), int((~y & p).sum())
    fn, tn = int((y & ~p).sum()), int((~y & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": prec, "recall": rec,
            "f1": f1, "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "accuracy": (tp + tn) / len(y)}


def roc(y, s):
    y, s = np.asarray(y, bool), np.asarray(s, float)
    order = np.argsort(-s)
    ys = y[order]
    tpr = np.concatenate([[0], np.cumsum(ys) / ys.sum()])
    fpr = np.concatenate([[0], np.cumsum(~ys) / (~ys).sum()])
    return fpr, tpr, float(np.trapezoid(tpr, fpr))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default="data/lab.pcap")
    ap.add_argument("--labels", default="data/labels.csv")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    cfg = load_config(a.config)
    cfg["alerting"]["console"] = False
    cfg["general"]["log_path"] = None
    W = cfg["general"]["window_seconds"]
    labels = [(float(r["start"]), float(r["end"]), r["type"], int(r["is_attack"]))
              for r in csv.DictReader(open(a.labels))]

    packets, parse_s = load_packets(a.pcap)
    t0 = packets[0].ts
    t_train = t0 + TRAIN_SECONDS

    # 1) ML загварыг зөвхөн хэвийн (эхний 15 мин) цонхоор сургах
    vecs = []
    agg = WindowAggregator(W, lambda ws: vecs.append(ws.vector()))
    for p in packets:
        if p.ts >= t_train:
            break
        agg.add(p)
    agg.flush()
    vecs = vecs[1:]           # эхний цонх дутуу (partial) тул хасна
    ml = MLDetector(cfg["ml"])
    t = time.perf_counter()
    ml.fit(np.array(vecs))
    fit_s = time.perf_counter() - t

    # 2) Бүх урсгалыг хөдөлгүүрээр дамжуулах
    eng = Engine(cfg, storage=None, ml=ml, keep_results=True)
    t = time.perf_counter()
    eng.run_offline(iter(packets))
    proc_s = time.perf_counter() - t

    # 3) Цонхны түвшний үнэлгээ (сургалтын хэсгийг хасна)
    rows = []
    for r in eng.results:
        if r.start < t_train or r.end > packets[-1].ts:   # сургалтын ба сүүлийн дутуу цонх
            continue
        kind, atk = window_label(r.start, r.end, labels)
        dets = {a_.detector for a_ in r.alerts}
        cats = sorted({a_.category for a_ in r.alerts})
        rows.append({"start": r.start - t0, "kind": kind, "y": atk,
                     "rule": "rule" in dets, "stat": "statistical" in dets, "ml": "ml" in dets,
                     "ml_score": r.ml_score, "max_z": max(r.stat_z.values()) if r.stat_z else 0.0,
                     "pkts": r.features["pkts"], "syn": r.features["syn"],
                     "icmp": r.features["icmp"], "categories": "|".join(cats)})
    y = [r["y"] for r in rows]
    combos = {
        "Дүрэм (rule)": [r["rule"] for r in rows],
        "Статистик (EWMA)": [r["stat"] for r in rows],
        "ML (Isolation Forest)": [r["ml"] for r in rows],
        "Хосолмол: дүрэм ∪ ML": [r["rule"] or r["ml"] for r in rows],
        "Хосолмол: дүрэм ∪ (стат ∩ ML)": [r["rule"] or (r["stat"] and r["ml"]) for r in rows],
    }
    overall = {k: metrics(y, v) for k, v in combos.items()}

    # 4) Халдлагын төрөл тус бүр: илэрсэн эсэх, цонхны recall, саатал
    per_type = {}
    for st, en, kind, atk in labels:
        sub = [r for r in rows if r["kind"] == kind]
        entry = {"windows": len(sub), "is_attack": atk}
        for det in ("rule", "stat", "ml"):
            hit = [r for r in sub if r[det]]
            entry[det + "_windows"] = len(hit)
            entry[det + "_delay"] = (min(r["start"] for r in hit) + W - (st - t0)) if hit else None
        entry["rule_categories"] = sorted({c for r in sub for c in r["categories"].split("|") if c})
        per_type[kind] = entry

    fpr_ml, tpr_ml, auc_ml = roc(y, [r["ml_score"] for r in rows])
    fpr_st, tpr_st, auc_st = roc(y, [r["max_z"] for r in rows])

    # ML босгын мэдрэмж (training score-ын перцентиль)
    Xtr = np.array(vecs)
    tr_scores = ml.scores(Xtr)
    ml_sens = []
    for pct in (90, 95, 97, 98, 99, 99.5, 100):
        thr = float(np.percentile(tr_scores, pct))
        pred = [r["ml_score"] > thr for r in rows]
        m = metrics(y, pred)
        ml_sens.append({"percentile": pct, "threshold": thr, **m})
    stat_sens = []
    for zt in (2.5, 3, 4, 5, 6, 8):
        m = metrics(y, [r["max_z"] >= zt for r in rows])
        stat_sens.append({"z": zt, **m})

    # Шинжийн багцын харьцуулалт (ablation): бүх шинж vs зан төлөвийн шинж
    from netsentinel.features import FEATURE_NAMES
    ablation = {}
    test_X = np.array([[r_.features.get(n, 0.0) for n in FEATURE_NAMES] for r_ in eng.results
                       if r_.start >= t_train and r_.end <= packets[-1].ts])
    for name, fs in (("all", FEATURE_NAMES), ("behavioral", ml.features)):
        mcfg = dict(cfg["ml"], features=list(fs))
        m2 = MLDetector(mcfg)
        m2.fit(np.array(vecs))
        s2 = m2.scores(test_X)
        thr2 = float(np.percentile(m2.scores(np.array(vecs)), cfg["ml"]["threshold_percentile"]))
        ablation[name] = {"n_features": len(fs), "auc": roc(y, s2)[2],
                          **metrics(y, [v > thr2 for v in s2])}

    perf = {"packets": len(packets), "duration_s": packets[-1].ts - t0,
            "windows_eval": len(rows), "train_windows": len(vecs),
            "parse_seconds": parse_s, "parse_pps": len(packets) / parse_s if parse_s else None,
            "engine_seconds": proc_s, "engine_pps": len(packets) / proc_s,
            "ml_fit_seconds": fit_s, "ml_threshold": ml.threshold,
            "alerts_emitted": len(eng.alerts.emitted), "alerts_suppressed": eng.alerts.suppressed,
            "auc_ml": auc_ml, "auc_stat": auc_st}

    json.dump({"overall": overall, "per_type": per_type, "perf": perf,
               "ml_sensitivity": ml_sens, "stat_sensitivity": stat_sens,
               "ml_ablation": ablation},
              open(os.path.join(a.out, "metrics.json"), "w"), ensure_ascii=False, indent=2)
    with open(os.path.join(a.out, "windows.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    np.savez(os.path.join(a.out, "roc.npz"), fpr_ml=fpr_ml, tpr_ml=tpr_ml, fpr_st=fpr_st, tpr_st=tpr_st)
    with open(os.path.join(a.out, "alerts.jsonl"), "w") as fh:
        for al in eng.alerts.emitted:
            d = al.to_dict()
            d["t_rel"] = al.ts - t0
            fh.write(json.dumps(d, ensure_ascii=False, default=str) + "\n")

    print(json.dumps(perf, ensure_ascii=False, indent=1))
    for k, m in overall.items():
        print(f"{k:32} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"FPR={m['fpr']:.4f}  TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}")
    for k, e in per_type.items():
        print(k, e)


if __name__ == "__main__":
    main()
