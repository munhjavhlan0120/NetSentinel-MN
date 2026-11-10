"""Тохиргоо ачаалах модуль (config.yaml)."""
from __future__ import annotations

import copy
import os
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

DEFAULTS: dict[str, Any] = {
    "general": {
        "window_seconds": 5,
        "db_path": "netsentinel.db",
        "log_path": "alerts.jsonl",
    },
    "capture": {
        "interface": None,          # None -> scapy-ийн үндсэн интерфэйс
        "bpf_filter": "",           # жишээ: "not port 22"
    },
    "performance": {
        "enabled": True,
        "interval_seconds": 10,
        "ping_count": 5,
        "targets": ["8.8.8.8", "1.1.1.1"],
        "tcp_targets": [],          # ["example.com:443"]
        "sla": {"rtt_ms": 100.0, "jitter_ms": 30.0, "loss_pct": 2.0},
    },
    "rules": {
        "port_scan_ports": 25,       # нэг эх үүсвэрээс цонхонд хандсан ялгаатай портын тоо
        "host_sweep_hosts": 20,      # нэг эх үүсвэрээс хандсан ялгаатай хостын тоо
        "syn_flood_syn": 300,        # нэг очих хаяг руу цонхонд ирсэн SYN
        "syn_flood_ratio": 3.0,      # SYN / (SYN-ACK + 1)
        "icmp_flood_pkts": 250,      # нэг очих хаяг руу ICMP echo request
        "brute_force_conns": 20,     # нэвтрэх үйлчилгээ рүү horizon хугацаанд шинэ холболт
        "brute_force_horizon_s": 30,
        "slow_scan_ports": 40,       # удаан скан: horizon хугацаанд ялгаатай порт
        "slow_scan_horizon_s": 300,
        "brute_force_ports": [21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5900],
        "dns_qname_len": 52,         # хэт урт DNS асуулга
        "dns_entropy": 3.8,
        "dns_suspicious_count": 5,
    },
    "statistical": {
        "alpha": 0.05,               # EWMA жигнэх коэффициент
        "z_threshold": 4.0,
        "warmup_windows": 30,
        "features": ["pkts", "bytes", "syn", "icmp_req", "uniq_dports", "max_src_dports",
                     "max_src_dsts", "dns_long", "syn_ratio"],
    },
    "ml": {
        "enabled": True,
        "model_path": "iforest.joblib",
        "n_estimators": 200,
        "train_windows": 120,        # онлайн горимд эхний N цонхоор сургах
        "threshold_percentile": 98.0,
        "features": None,            # None -> DEFAULT_ML_FEATURES (зан төлөвийн шинжүүд)
    },
    "alerting": {
        "cooldown_seconds": 60,
        "console": True,
        "telegram": {"enabled": False, "token_env": "NS_TG_TOKEN", "chat_id_env": "NS_TG_CHAT"},
    },
    "dashboard": {"host": "127.0.0.1", "port": 8050},
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None = None) -> dict[str, Any]:
    """YAML файлыг үндсэн утгуудтай нэгтгэж буцаана."""
    if path and os.path.exists(path):
        if yaml is None:
            raise RuntimeError("PyYAML суулгаагүй байна: pip install pyyaml")
        with open(path, encoding="utf-8") as fh:
            return _merge(DEFAULTS, yaml.safe_load(fh) or {})
    return copy.deepcopy(DEFAULTS)
