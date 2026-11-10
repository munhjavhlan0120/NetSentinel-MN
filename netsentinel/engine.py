"""Системийн цөм: пакет -> цонх -> илрүүлэгчид -> сэрэмжлүүлэг."""
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .alerting import AlertManager
from .capture import LiveCapture
from .detectors import MLDetector, RuleDetector, StatisticalDetector
from .features import WindowAggregator, WindowStats
from .models import Alert, PacketInfo
from .perf_monitor import PerfAnalyzer, ThroughputMeter, probe_targets
from .storage import Storage

log = logging.getLogger(__name__)
_TICK = object()


@dataclass
class WindowResult:
    """Нэг цонхны илрүүлэлтийн үр дүн (үнэлгээнд ашиглана)."""
    start: float
    end: float
    features: dict
    alerts: list[Alert] = field(default_factory=list)
    stat_z: dict = field(default_factory=dict)
    ml_score: Optional[float] = None


class Engine:
    def __init__(self, cfg: dict, storage: Optional[Storage] = None,
                 ml: Optional[MLDetector] = None, keep_results: bool = False):
        self.cfg = cfg
        g = cfg["general"]
        self.storage = storage
        self.alerts = AlertManager(cfg["alerting"], storage, g.get("log_path"))
        self.rules = RuleDetector(cfg["rules"])
        self.stat = StatisticalDetector(cfg["statistical"])
        self.ml = ml if ml is not None else (MLDetector(cfg["ml"]) if cfg["ml"]["enabled"] else None)
        self.agg = WindowAggregator(g["window_seconds"], self._on_window,
                                    auth_ports=set(cfg["rules"]["brute_force_ports"]),
                                    dns_long_len=cfg["rules"]["dns_qname_len"])
        self.keep_results = keep_results
        self.results: list[WindowResult] = []
        self.packets = 0
        self._q: "queue.Queue" = queue.Queue(maxsize=100_000)
        self._stop = threading.Event()
        self.dropped = 0

    # ---- нэг пакет боловсруулах -----------------------------------------
    def process(self, p: PacketInfo) -> None:
        self.packets += 1
        # Эхлээд цонхыг шилжүүлнэ: ингэснээр шинэ пакетын ARP alert өмнөх цонхонд буруу хамаарахгүй
        self.agg.add(p)
        self.rules.on_packet(p)

    def _on_window(self, ws: WindowStats) -> None:
        found: list[Alert] = []
        found += self.rules.on_window(ws)
        found += self.stat.on_window(ws)
        ml_score = None
        if self.ml is not None:
            found += self.ml.on_window(ws)
            ml_score = self.ml.last_score if self.ml.model is not None else None
        for a in found:
            self.alerts.emit(a)
        if self.storage is not None:
            self.storage.add_window(ws, ml_score)
        if self.keep_results:
            self.results.append(WindowResult(ws.start, ws.end, dict(ws.features), found,
                                             dict(self.stat.last_scores), ml_score))

    # ---- офлайн (PCAP) горим ------------------------------------------------
    def run_offline(self, packets: Iterable[PacketInfo]) -> None:
        for p in packets:
            self.process(p)
        self.agg.flush()

    # ---- бодит цагийн горим -------------------------------------------------
    def _enqueue(self, p: PacketInfo) -> None:
        try:
            self._q.put_nowait(p)
        except queue.Full:
            self.dropped += 1

    def _consumer(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is _TICK:
                # Урсгал байхгүй үед ч цонхыг цагт нь хаана
                self.agg._ensure(time.time())
            else:
                self.process(item)

    def _ticker(self) -> None:
        while not self._stop.wait(self.cfg["general"]["window_seconds"]):
            self._q.put(_TICK)

    def _perf_loop(self) -> None:
        pc = self.cfg["performance"]
        analyzer = PerfAnalyzer(pc["sla"])
        meter = ThroughputMeter(self.cfg["capture"].get("interface"))
        while not self._stop.is_set():
            rx, tx = meter.sample()
            for s in probe_targets(pc):
                s.rx_mbps, s.tx_mbps = round(rx, 3), round(tx, 3)
                if self.storage is not None:
                    self.storage.add_perf(s)
                for a in analyzer.check(s):
                    self.alerts.emit(a)
            self._stop.wait(pc["interval_seconds"])

    def run_live(self) -> None:
        cap = self.cfg["capture"]
        sniffer = LiveCapture(self._enqueue, cap.get("interface"), cap.get("bpf_filter", ""))
        threads = [threading.Thread(target=self._consumer, daemon=True),
                   threading.Thread(target=self._ticker, daemon=True)]
        if self.cfg["performance"]["enabled"]:
            threads.append(threading.Thread(target=self._perf_loop, daemon=True))
        for t in threads:
            t.start()
        sniffer.start()
        log.info("Хяналт эхэллээ. Зогсоохын тулд Ctrl+C дарна уу.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            sniffer.stop()
            log.info("Зогслоо. Пакет: %d, алдагдсан: %d, alert: %d (дарагдсан %d)",
                     self.packets, self.dropped, len(self.alerts.emitted),
                     self.alerts.suppressed)
