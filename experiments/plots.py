#!/usr/bin/env python3
"""Дипломын ажлын зургуудыг (PDF) results/ хавтасны өгөгдлөөс зурна."""
from __future__ import annotations

import csv
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

R = sys.argv[1] if len(sys.argv) > 1 else "results"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(R, "fig")
os.makedirs(OUT, exist_ok=True)

C = {"blue": "#2a78d6", "orange": "#eb6834", "aqua": "#1baf7a", "yellow": "#eda100",
     "magenta": "#e87ba4", "violet": "#4a3aa7", "ink": "#0b0b0b", "ink2": "#52514e",
     "muted": "#898781", "grid": "#e1e0d9", "base": "#c3c2b7", "shade": "#ecebe6"}
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": C["base"],
    "axes.labelcolor": C["ink2"], "xtick.color": C["muted"], "ytick.color": C["muted"],
    "axes.grid": True, "grid.color": C["grid"], "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
    "lines.linewidth": 1.4, "savefig.bbox": "tight", "figure.dpi": 150,
})
NAMES = {"port_scan": "Порт скан", "brute_force": "Brute force", "syn_flood": "SYN flood",
         "icmp_flood": "ICMP flood", "arp_spoof": "ARP spoof", "dns_tunnel": "DNS tunnel",
         "host_sweep": "Host sweep", "benign_burst": "Хэвийн ачаалал", "slow_scan": "Удаан скан"}

rows = list(csv.DictReader(open(os.path.join(R, "windows.csv"))))
M = json.load(open(os.path.join(R, "metrics.json")))
t = np.array([float(r["start"]) for r in rows]) / 60
labels = list(csv.DictReader(open("data/labels.csv")))
t0 = None


def shade(ax, text=True):
    global t0
    if t0 is None:
        # windows.csv-ийн start нь pcap-ийн эхнээс хойшхи секунд; labels нь unix цаг
        t0 = float(labels[0]["start"]) - 1000.0
    ymax = ax.get_ylim()[1]
    for lb in labels:
        a, b = (float(lb["start"]) - t0) / 60, (float(lb["end"]) - t0) / 60
        benign = lb["is_attack"] == "0"
        ax.axvspan(a, b, color=C["shade"] if not benign else "#dfeee6", zorder=0, lw=0)
        if text:
            ax.text((a + b) / 2, ymax, NAMES[lb["type"]], rotation=90, va="top", ha="center",
                    fontsize=6.5, color=C["ink2"])


# 1. Урсгалын хугацааны цуваа ба илрүүлэлт
fig, axes = plt.subplots(2, 1, figsize=(7.2, 4.6), sharex=True,
                         gridspec_kw={"height_ratios": [3, 1.2]})
ax = axes[0]
ax.plot(t, [float(r["pkts"]) for r in rows], color=C["blue"], label="Нийт пакет / 5 с")
ax.plot(t, [float(r["syn"]) for r in rows], color=C["orange"], label="TCP SYN / 5 с")
ax.set_yscale("log")
ax.set_ylabel("Пакетын тоо (log)")
ax.set_ylim(1, 1e6)
ax.set_yticks([1, 10, 100, 1000, 10000])
shade(ax)
ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=7.5)
ax = axes[1]
for i, (key, name, col) in enumerate([("rule", "Дүрэм", C["blue"]),
                                     ("stat", "EWMA", C["aqua"]), ("ml", "IForest", C["orange"])]):
    xs = [tt for tt, r in zip(t, rows) if r[key] == "True"]
    ax.scatter(xs, [i] * len(xs), s=10, color=col, marker="|", linewidths=1.6)
ax.set_yticks([0, 1, 2], ["Дүрэм", "EWMA", "IForest"])
ax.set_ylim(-0.6, 2.6)
ax.grid(axis="y", visible=False)
shade(ax, text=False)
ax.set_xlabel("Хугацаа (минут)")
fig.savefig(os.path.join(OUT, "traffic_timeline.pdf"))
plt.close(fig)

# 2. ML аномалийн оноо
fig, ax = plt.subplots(figsize=(7.2, 2.6))
ax.plot(t, [float(r["ml_score"]) for r in rows], color=C["blue"], label="Isolation Forest оноо")
thr = M["perf"]["ml_threshold"]
ax.axhline(thr, color=C["orange"], ls="--", lw=1.2, label=f"Босго ({thr:.3f})")
ax.set_ylabel("Аномалийн оноо")
sc = [float(r["ml_score"]) for r in rows]
ax.set_ylim(min(sc) - 0.02, max(sc) + 0.14)
ax.set_xlabel("Хугацаа (минут)")
shade(ax)
ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=7.5)
fig.savefig(os.path.join(OUT, "ml_scores.pdf"))
plt.close(fig)

# 3. ROC муруй
roc = np.load(os.path.join(R, "roc.npz"))
fig, ax = plt.subplots(figsize=(3.6, 3.4))
ax.plot(roc["fpr_ml"], roc["tpr_ml"], color=C["blue"], label=f"IForest (AUC={M['perf']['auc_ml']:.3f})")
ax.plot(roc["fpr_st"], roc["tpr_st"], color=C["aqua"], label=f"EWMA max-z (AUC={M['perf']['auc_stat']:.3f})")
ax.plot([0, 1], [0, 1], color=C["base"], ls=":", lw=1)
ax.set_xlabel("Хуурамч эерэг хувь (FPR)")
ax.set_ylabel("Илрүүлэлтийн хувь (TPR)")
ax.legend(loc="lower right", fontsize=7)
fig.savefig(os.path.join(OUT, "roc.pdf"))
plt.close(fig)

# 4. P / R / F1 харьцуулалт
ov = M["overall"]
keys = list(ov.keys())
short = ["Дүрэм", "EWMA", "IForest", "Дүрэм∪ML", "Дүрэм∪(EWMA∩ML)"]
x = np.arange(len(keys))
w = 0.26
fig, ax = plt.subplots(figsize=(7.2, 3.0))
for j, (m, name, col) in enumerate([("precision", "Precision", C["blue"]),
                                    ("recall", "Recall", C["orange"]), ("f1", "F1", C["aqua"])]):
    vals = [ov[k][m] for k in keys]
    bars = ax.bar(x + (j - 1) * w, vals, w - 0.03, color=col, label=name)
    if m == "f1":
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}", ha="center",
                    fontsize=7, color=C["ink2"])
ax.set_xticks(x, short, fontsize=8)
ax.set_ylim(0, 1.1)
ax.grid(axis="x", visible=False)
ax.legend(ncol=3, loc="upper left", fontsize=7.5)
fig.savefig(os.path.join(OUT, "detector_f1.pdf"))
plt.close(fig)

# 5. ML босгын мэдрэмж
sens = M["ml_sensitivity"]
fig, ax = plt.subplots(figsize=(3.8, 3.0))
p = [s["percentile"] for s in sens]
xs = np.arange(len(p))
ax.plot(xs, [s["precision"] for s in sens], marker="o", ms=4, color=C["blue"], label="Precision")
ax.plot(xs, [s["recall"] for s in sens], marker="o", ms=4, color=C["orange"], label="Recall")
ax.plot(xs, [s["fpr"] for s in sens], marker="o", ms=4, color=C["muted"], label="FPR")
ax.set_xticks(xs, [str(v) for v in p])
ax.set_xlabel("Босгын перцентиль (сургалтын оноо)")
ax.legend(fontsize=7)
fig.savefig(os.path.join(OUT, "ml_sensitivity.pdf"))
plt.close(fig)

# 6. Гүйцэтгэлийн симуляци
pf = np.load(os.path.join(R, "perf_series.npz"), allow_pickle=True)
th = pf["t"] / 3600
fig, axes = plt.subplots(3, 1, figsize=(7.2, 5.0), sharex=True)
EV = [(1.5, 2.0, "Түгжрэл"), (3.0, 3.167, "Алдагдал"), (4.0, 6.0, "Маршрут"),
      (5.0, 5.05, " Тасалдал")]
series = [("rtt", "RTT (мс)", C["blue"], 100), ("jit", "Jitter (мс)", C["violet"], 30),
          ("loss", "Алдагдал (%)", C["orange"], 2)]
for ax, (k, lab, col, sla) in zip(axes, series):
    for a, b, n in EV:
        ax.axvspan(a, b, color=C["shade"] if n != "Маршрут" else "#f4f1e4", lw=0, zorder=0)
    ax.plot(th, pf[k], color=col, lw=0.9)
    ax.axhline(sla, color=C["ink2"], ls="--", lw=0.9)
    ax.text(th[-1], sla, " SLA", va="center", fontsize=7, color=C["ink2"])
    ax.set_ylabel(lab)
ymax = axes[0].get_ylim()[1]
for i, (a, b, n) in enumerate(EV):
    axes[0].text(a + 0.02, ymax * (0.97 if i < 3 else 0.80), n, fontsize=6.5, va="top", color=C["ink2"])
at = pf["a_t"] / 3600
axes[0].scatter(at, np.full(len(at), -8), s=6, marker="|", color=C["magenta"], clip_on=False)
axes[-1].set_xlabel("Хугацаа (цаг)")
fig.savefig(os.path.join(OUT, "perf_sim.pdf"))
plt.close(fig)
print("figures ->", OUT)

# 7. Төөрөгдлийн матриц (confusion matrix) — илрүүлэгч тус бүр
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
cmap = LinearSegmentedColormap.from_list("b", ["#f4f8fd", "#2a78d6"])
sel = [("Дүрэм (rule)", "Дүрэм"), ("Статистик (EWMA)", "EWMA"),
       ("ML (Isolation Forest)", "Isolation Forest"), ("Хосолмол: дүрэм ∪ ML", "Дүрэм ∪ ML")]
fig, axes = plt.subplots(1, 4, figsize=(7.4, 2.2))
for ax, (k, name) in zip(axes, sel):
    m = M["overall"][k]
    cm = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
    ax.imshow(cm / cm.sum(axis=1, keepdims=True), cmap=cmap, vmin=0, vmax=1)
    for (i, j), v in np.ndenumerate(cm):
        frac = cm[i, j] / cm[i].sum()
        ax.text(j, i, str(v), ha="center", va="center", fontsize=9,
                color="white" if frac > 0.6 else C["ink"])
    ax.set_xticks([0, 1], ["Хэвийн", "Халдлага"], fontsize=7)
    ax.set_yticks([0, 1], ["Хэвийн", "Халдлага"], fontsize=7)
    ax.set_title(name, fontsize=8)
    ax.grid(False)
    for sp in ax.spines.values():
        sp.set_visible(False)
axes[0].set_ylabel("Бодит", fontsize=8)
for ax in axes:
    ax.set_xlabel("Таамаг", fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "confusion.pdf"))
plt.close(fig)
