"""Isolation Forest-д суурилсан хяналтгүй (unsupervised) аномали илрүүлэгч."""
from __future__ import annotations

import os
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..features import FEATURE_NAMES, WindowStats
from ..models import Alert

# Эзлэхүүн (volume) биш, зан төлөвийн (behavioral) шинжүүд. Эзлэхүүний хазайлтыг EWMA хариуцна.
DEFAULT_ML_FEATURES = ["syn_ratio", "max_src_dports", "max_src_dsts", "max_dst_syn", "icmp_req",
                       "dport_entropy", "mean_size", "uniq_dports", "rst", "dns_long",
                       "max_auth_syn", "arp"]


def transform(X: np.ndarray) -> np.ndarray:
    """Хүнд сүүлтэй (heavy-tailed) тоолуурын шинжийг log(1+x)-ээр хувиргана."""
    return np.log1p(np.clip(X, 0, None))


class MLDetector:
    name = "ml"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.threshold: float = 0.0
        self._buffer: list[list[float]] = []
        self.last_score: float = 0.0
        self.features = cfg.get("features") or DEFAULT_ML_FEATURES
        self.idx = [FEATURE_NAMES.index(f) for f in self.features]

    def select(self, X) -> np.ndarray:
        """Бүрэн шинжийн вектороос ML-д ашиглах баганыг сонгоно."""
        return np.asarray(X, dtype=float)[:, self.idx]

    # ---- сургалт -----------------------------------------------------------
    def fit(self, X: np.ndarray) -> None:
        Xt = transform(self.select(X))
        self.scaler = StandardScaler().fit(Xt)
        Xs = self.scaler.transform(Xt)
        self.model = IsolationForest(n_estimators=self.cfg["n_estimators"],
                                     contamination="auto", random_state=42).fit(Xs)
        # Аномалийн оноо: их байх тусам хэвийн бус (sklearn-ийн score_samples-ийн эсрэг тэмдэг)
        train_scores = -self.model.score_samples(Xs)
        self.threshold = float(np.percentile(train_scores, self.cfg["threshold_percentile"]))

    def scores(self, X: np.ndarray) -> np.ndarray:
        assert self.model is not None and self.scaler is not None
        Xs = self.scaler.transform(transform(self.select(X)))
        return -self.model.score_samples(Xs)

    def save(self, path: Optional[str] = None) -> None:
        import joblib
        joblib.dump({"model": self.model, "scaler": self.scaler, "thr": self.threshold,
                     "features": self.features},
                    path or self.cfg["model_path"])

    def load(self, path: Optional[str] = None) -> bool:
        import joblib
        p = path or self.cfg["model_path"]
        if not os.path.exists(p):
            return False
        d = joblib.load(p)
        self.model, self.scaler, self.threshold = d["model"], d["scaler"], d["thr"]
        self.features = d.get("features", self.features)
        self.idx = [FEATURE_NAMES.index(f) for f in self.features]
        return True

    # ---- онлайн ажиллагаа ---------------------------------------------------
    def on_window(self, ws: WindowStats) -> list[Alert]:
        v = ws.vector()
        if self.model is None:
            self._buffer.append(v)       # сургалтын өгөгдөл цуглуулах үе
            if len(self._buffer) >= self.cfg["train_windows"]:
                self.fit(np.array(self._buffer))
                self._buffer.clear()
            return []
        s = float(self.scores(np.array([v]))[0])
        self.last_score = s
        if s <= self.threshold:
            return []
        sev = "high" if s > self.threshold * 1.15 else "medium"
        return [Alert(ws.end, sev, "ml_anomaly", self.name,
                      f"Isolation Forest аномали (оноо={s:.3f} > босго={self.threshold:.3f})",
                      score=s)]
