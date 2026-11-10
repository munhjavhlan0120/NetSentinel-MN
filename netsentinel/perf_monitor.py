"""Сүлжээний гүйцэтгэлийн хэмжилт: RTT, jitter, пакет алдагдал, дамжуулах хурд."""
from __future__ import annotations

import platform
import re
import shutil
import socket
import statistics
import subprocess
import time
from collections import deque
from typing import Optional, Sequence

import psutil

from .detectors.statistical import EWMA
from .models import Alert, PerfSample

_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def jitter_ms(rtts: Sequence[float]) -> Optional[float]:
    """Дараалсан RTT-үүдийн зөрүүний абсолют дундаж (IPDV, RFC 3393 / RFC 3550-д тулгуурласан)."""
    if len(rtts) < 2:
        return 0.0 if rtts else None
    return statistics.fmean(abs(b - a) for a, b in zip(rtts, rtts[1:]))


def summarize(target: str, method: str, rtts: list[float], sent: int) -> PerfSample:
    loss = 100.0 * (sent - len(rtts)) / sent if sent else 100.0
    return PerfSample.now(
        target=target, method=method,
        rtt_avg=statistics.fmean(rtts) if rtts else None,
        rtt_min=min(rtts) if rtts else None,
        rtt_max=max(rtts) if rtts else None,
        jitter=jitter_ms(rtts), loss_pct=round(loss, 2), sent=sent)


def icmp_probe(host: str, count: int = 5, timeout_s: int = 2) -> PerfSample:
    """Системийн ping командыг ашиглан ICMP echo хэмжилт хийнэ (root эрх шаардахгүй)."""
    if shutil.which("ping") is None:
        raise RuntimeError("ping команд олдсонгүй")
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", str(timeout_s), host]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=count * (timeout_s + 1) + 5)
    rtts = [float(m.group(1)) for m in _RTT_RE.finditer(proc.stdout)]
    return summarize(host, "icmp", rtts, count)


def tcp_probe(host: str, port: int, count: int = 5, timeout_s: float = 2.0) -> PerfSample:
    """TCP 3-талт гар барилтын (connect) хугацаагаар RTT хэмжинэ (ICMP хаалттай үед)."""
    rtts: list[float] = []
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                rtts.append((time.perf_counter() - t0) * 1000.0)
        except OSError:
            pass
        time.sleep(0.2)
    return summarize(f"{host}:{port}", "tcp", rtts, count)


class ThroughputMeter:
    """psutil-ийн интерфэйсийн тоолуурын зөрүүгээр Мбит/с тооцоолно."""

    def __init__(self, iface: Optional[str] = None):
        self.iface = iface
        self._last = self._read()

    def _read(self):
        c = psutil.net_io_counters(pernic=bool(self.iface))
        if self.iface:
            c = c.get(self.iface)
        return time.time(), c.bytes_recv, c.bytes_sent

    def sample(self) -> tuple[float, float]:
        t, rx, tx = self._read()
        t0, rx0, tx0 = self._last
        self._last = (t, rx, tx)
        dt = max(t - t0, 1e-6)
        return (rx - rx0) * 8 / dt / 1e6, (tx - tx0) * 8 / dt / 1e6


class PerfAnalyzer:
    """SLA босго болон EWMA хазайлтаар гүйцэтгэлийн доройтлыг илрүүлнэ."""

    def __init__(self, sla: dict, alpha: float = 0.1, z_thr: float = 4.0, warmup: int = 10,
                 loss_window: int = 6, rebase_after: int = 30):
        self.sla = sla
        # Хазайлт rebase_after удаа дараалан үргэлжилбэл "шинэ хэвийн түвшин" гэж хүлээн авна
        # (жиш. маршрут өөрчлөгдсөний дараа baseline-ийг шинэчилж, хуурамч alert-ийг зогсооно)
        self.rebase_after = rebase_after
        self.streak: dict[str, int] = {}
        self.alpha, self.z_thr, self.warmup = alpha, z_thr, warmup
        self.rtt_models: dict[str, EWMA] = {}
        # Пакет алдагдлыг сүүлийн N хэмжилтийн нийлбэрээр тооцно: 5 ping-ийн 1 нь алдагдахад
        # 20% гэж буруу дүгнэхээс сэргийлнэ (хэмжилтийн нарийвчлалыг нэмэгдүүлнэ).
        self.loss_window = loss_window
        self.loss_hist: dict[str, deque] = {}

    def window_loss(self, s: PerfSample) -> float:
        sent = s.sent or 0
        recv = round(sent * (1 - s.loss_pct / 100.0))
        h = self.loss_hist.setdefault(s.target, deque(maxlen=self.loss_window))
        h.append((sent, recv))
        tot = sum(a for a, _ in h)
        return 100.0 * (tot - sum(b for _, b in h)) / tot if tot else s.loss_pct

    def check(self, s: PerfSample) -> list[Alert]:
        out: list[Alert] = []
        loss = self.window_loss(s)
        if s.rtt_avg is None:
            return [Alert(s.ts, "critical", "host_unreachable", "performance",
                          f"{s.target} хариу өгөхгүй байна (алдагдал 100%)", dst=s.target)]
        if loss > self.sla["loss_pct"]:
            out.append(Alert(s.ts, "high", "packet_loss", "performance",
                             f"{s.target}: пакет алдагдал {loss:.1f}% (сүүлийн {self.loss_window} "
                             f"хэмжилт, SLA {self.sla['loss_pct']}%)", dst=s.target, score=loss))
        if s.rtt_avg > self.sla["rtt_ms"]:
            out.append(Alert(s.ts, "medium", "high_latency", "performance",
                             f"{s.target}: RTT {s.rtt_avg:.1f} мс (SLA {self.sla['rtt_ms']} мс)",
                             dst=s.target, score=s.rtt_avg))
        if s.jitter is not None and s.jitter > self.sla["jitter_ms"]:
            out.append(Alert(s.ts, "medium", "high_jitter", "performance",
                             f"{s.target}: jitter {s.jitter:.1f} мс (SLA {self.sla['jitter_ms']} мс)",
                             dst=s.target, score=s.jitter))
        m = self.rtt_models.setdefault(s.target, EWMA(self.alpha))
        z = m.z(s.rtt_avg)
        if m.n >= self.warmup and z >= self.z_thr:
            k = self.streak[s.target] = self.streak.get(s.target, 0) + 1
            if k >= self.rebase_after and not out:
                out.append(Alert(s.ts, "low", "baseline_shift", "performance",
                                 f"{s.target}: RTT-ийн шинэ тогтвортой түвшин {s.rtt_avg:.1f} мс "
                                 f"(өмнө {m.mu:.1f} мс) — baseline шинэчлэгдлээ",
                                 dst=s.target, score=z))
                m.mu, self.streak[s.target] = s.rtt_avg, 0
            elif not out:
                out.append(Alert(s.ts, "low", "latency_shift", "performance",
                                 f"{s.target}: RTT хэвийн түвшнээс огцом өссөн (z={z:.1f})",
                                 dst=s.target, score=z))
        else:
            self.streak[s.target] = 0
            m.update(s.rtt_avg)
        return out


def probe_targets(cfg: dict) -> list[PerfSample]:
    samples = []
    for host in cfg.get("targets", []):
        try:
            samples.append(icmp_probe(host, cfg.get("ping_count", 5)))
        except Exception:
            samples.append(tcp_probe(host, 443, cfg.get("ping_count", 5)))
    for hp in cfg.get("tcp_targets", []):
        host, port = hp.rsplit(":", 1)
        samples.append(tcp_probe(host, int(port), cfg.get("ping_count", 5)))
    return samples
