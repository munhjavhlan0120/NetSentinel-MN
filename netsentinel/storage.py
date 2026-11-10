"""SQLite өгөгдлийн сан."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from .features import WindowStats
from .models import Alert, PerfSample

SCHEMA = """
CREATE TABLE IF NOT EXISTS perf_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, target TEXT NOT NULL, method TEXT,
    rtt_avg REAL, rtt_min REAL, rtt_max REAL, jitter REAL, loss_pct REAL,
    rx_mbps REAL, tx_mbps REAL
);
CREATE INDEX IF NOT EXISTS ix_perf_ts ON perf_samples(ts);

CREATE TABLE IF NOT EXISTS traffic_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start REAL NOT NULL, ts_end REAL NOT NULL,
    pkts INTEGER, bytes INTEGER, syn INTEGER, icmp INTEGER,
    features TEXT, ml_score REAL
);
CREATE INDEX IF NOT EXISTS ix_tw_ts ON traffic_windows(ts_end);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, severity TEXT, category TEXT, detector TEXT,
    src TEXT, dst TEXT, score REAL, description TEXT, extra TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
"""


class Storage:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("PRAGMA journal_mode=WAL")

    def add_perf(self, s: PerfSample) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO perf_samples(ts,target,method,rtt_avg,rtt_min,rtt_max,jitter,"
                "loss_pct,rx_mbps,tx_mbps) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (s.ts, s.target, s.method, s.rtt_avg, s.rtt_min, s.rtt_max, s.jitter,
                 s.loss_pct, s.rx_mbps, s.tx_mbps))
            self.conn.commit()

    def add_window(self, ws: WindowStats, ml_score: float | None = None) -> None:
        f = ws.features
        with self._lock:
            self.conn.execute(
                "INSERT INTO traffic_windows(ts_start,ts_end,pkts,bytes,syn,icmp,features,ml_score)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (ws.start, ws.end, f.get("pkts"), f.get("bytes"), f.get("syn"), f.get("icmp"),
                 json.dumps(f), ml_score))
            self.conn.commit()

    def add_alert(self, a: Alert) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO alerts(ts,severity,category,detector,src,dst,score,description,extra)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (a.ts, a.severity, a.category, a.detector, a.src, a.dst, a.score,
                 a.description, json.dumps(a.extra, default=str)))
            self.conn.commit()

    def query(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]
