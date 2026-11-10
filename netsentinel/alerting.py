"""Сэрэмжлүүлэг (alert) удирдах: давхардал шүүх, консол, JSON лог, Telegram."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.parse
import urllib.request
from typing import Callable, Optional

from .models import Alert

log = logging.getLogger(__name__)

SEV_ICON = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}
SEV_COLOR = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[35m", "critical": "\033[31m"}


class TelegramSink:
    def __init__(self, token: str, chat_id: str):
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id

    def __call__(self, a: Alert) -> None:
        text = (f"{SEV_ICON.get(a.severity, '')} <b>{a.category.upper()}</b> "
                f"[{a.severity}]\n{a.description}\n"
                f"<i>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a.ts))} · {a.detector}</i>")
        data = urllib.parse.urlencode({"chat_id": self.chat_id, "text": text,
                                       "parse_mode": "HTML"}).encode()
        # Сүлжээний саатал гол урсгалыг зогсоохгүйн тулд тусдаа thread-д илгээнэ
        threading.Thread(target=self._send, args=(data,), daemon=True).start()

    def _send(self, data: bytes) -> None:
        try:
            urllib.request.urlopen(self.url, data=data, timeout=10).read()
        except Exception as exc:
            log.warning("Telegram илгээж чадсангүй: %s", exc)


class AlertManager:
    def __init__(self, cfg: dict, storage=None, log_path: Optional[str] = None):
        self.cooldown = cfg.get("cooldown_seconds", 60)
        self.storage = storage
        self.log_path = log_path
        self._last: dict[str, float] = {}
        self.sinks: list[Callable[[Alert], None]] = []
        self.emitted: list[Alert] = []
        self.suppressed = 0
        if cfg.get("console", True):
            self.sinks.append(self._console)
        tg = cfg.get("telegram", {})
        if tg.get("enabled"):
            token, chat = os.getenv(tg["token_env"]), os.getenv(tg["chat_id_env"])
            if token and chat:
                self.sinks.append(TelegramSink(token, chat))
            else:
                log.warning("Telegram идэвхтэй боловч %s / %s орчны хувьсагч хоосон",
                            tg["token_env"], tg["chat_id_env"])

    @staticmethod
    def _console(a: Alert) -> None:
        t = time.strftime("%H:%M:%S", time.localtime(a.ts))
        print(f"{SEV_COLOR.get(a.severity, '')}[{t}] {a.severity.upper():8} "
              f"{a.category:16} ({a.detector}) {a.description}\033[0m", flush=True)

    def emit(self, a: Alert) -> bool:
        """Cooldown хугацаанд ижил түлхүүртэй alert-ийг дарж (suppress) үлдээнэ."""
        last = self._last.get(a.key)
        if last is not None and a.ts - last < self.cooldown:
            self.suppressed += 1
            return False
        self._last[a.key] = a.ts
        self.emitted.append(a)
        if self.storage is not None:
            self.storage.add_alert(a)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(a.to_dict(), ensure_ascii=False, default=str) + "\n")
        for sink in self.sinks:
            try:
                sink(a)
            except Exception as exc:  # pragma: no cover
                log.warning("sink алдаа: %s", exc)
        return True
