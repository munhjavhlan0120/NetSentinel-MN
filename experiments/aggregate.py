#!/usr/bin/env python3
"""Олон seed-ийн үр дүнг нэгтгэж дундаж ± стандарт хазайлтыг тооцно."""
import json, sys
import numpy as np
runs = {"7": "results", **{s: f"results/seed_{s}" for s in sys.argv[1:] or ["11", "23", "42"]}}
D = {k: json.load(open(v + "/metrics.json")) for k, v in runs.items()}
out = {}
for k in D["7"]["overall"]:
    out[k] = {m: [float(np.mean([D[r]["overall"][k][m] for r in D])),
                  float(np.std([D[r]["overall"][k][m] for r in D]))]
              for m in ["precision", "recall", "f1", "fpr"]}
out["auc_ml"] = [D[r]["perf"]["auc_ml"] for r in D]
out["auc_stat"] = [D[r]["perf"]["auc_stat"] for r in D]
out["engine_pps"] = [D[r]["perf"]["engine_pps"] for r in D]
out["packets"] = [D[r]["perf"]["packets"] for r in D]
json.dump(out, open("results/multi_seed.json", "w"), ensure_ascii=False, indent=1)
for k, v in out.items():
    print(k, v)
