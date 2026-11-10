"""EWMA (экспоненциал жинлэсэн хөдөлгөөнт дундаж) ба Z-оноонд суурилсан илрүүлэгч."""
from __future__ import annotations

import math
from typing import Iterable

from ..features import WindowStats
from ..models import Alert


class EWMA:
    """mu_t = a*x_t + (1-a)*mu_{t-1};  var_t = (1-a)*(var_{t-1} + a*(x_t-mu_{t-1})^2)"""

    def __init__(self, alpha: float, min_sd: float | None = None):
        self.a = alpha
        self.min_sd = min_sd
        self.mu: float | None = None
        self.var = 0.0
        self.n = 0

    def z(self, x: float) -> float:
        if self.mu is None:
            return 0.0
        sd = math.sqrt(self.var) if self.var > 0 else 0.0
        # Хэт бага хэлбэлзэлтэй үед 0-д хуваахаас сэргийлж доод хязгаар тавина
        if self.min_sd is not None:
            sd = max(sd, self.min_sd)
        else:
            sd = max(sd, 0.1 * abs(self.mu), 1.0)
        return (x - self.mu) / sd

    def update(self, x: float) -> None:
        self.n += 1
        if self.mu is None:
            self.mu = x
            return
        d = x - self.mu
        self.mu += self.a * d
        self.var = (1 - self.a) * (self.var + self.a * d * d)


class StatisticalDetector:
    name = "statistical"

    def __init__(self, cfg: dict):
        self.alpha = cfg["alpha"]
        self.zt = cfg["z_threshold"]
        self.warmup = cfg["warmup_windows"]
        self.features: Iterable[str] = cfg["features"]
        # log(1+x) огторгуйд 0.25 ≈ 28% харьцангуй өөрчлөлт — доод стандарт хазайлт
        self.min_sd = cfg.get("min_sd", 0.25)
        self.models = {f: EWMA(self.alpha, self.min_sd) for f in self.features}
        self.last_scores: dict[str, float] = {}

    def score(self, feats: dict[str, float]) -> dict[str, float]:
        return {f: self.models[f].z(math.log1p(feats.get(f, 0.0))) for f in self.features}

    def on_window(self, ws: WindowStats) -> list[Alert]:
        scores = self.score(ws.features)
        self.last_scores = scores
        warm = all(m.n >= self.warmup for m in self.models.values())
        hits = {f: z for f, z in scores.items() if z >= self.zt}
        # Аномали гэж үзсэн цонхоор загварыг шинэчлэхгүй (baseline бохирдохоос сэргийлнэ)
        if not (warm and hits):
            for f in self.features:
                self.models[f].update(math.log1p(ws.features.get(f, 0.0)))
        if not warm or not hits:
            return []
        top = max(hits, key=hits.get)
        desc = ", ".join(f"{k}: z={v:.1f}" for k, v in sorted(hits.items(), key=lambda i: -i[1]))
        sev = "high" if hits[top] >= 2 * self.zt else "medium"
        return [Alert(ws.end, sev, "traffic_anomaly", self.name,
                      f"Статистик хазайлт ({desc})", score=hits[top],
                      extra={"z": hits})]
