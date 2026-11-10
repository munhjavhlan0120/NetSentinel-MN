"""Веб самбарын API-ийн тест."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentinel.dashboard import create_app  # noqa: E402
from netsentinel.models import Alert  # noqa: E402
from netsentinel.storage import Storage  # noqa: E402


def test_api(tmp_path):
    db = str(tmp_path / "t.db")
    st = Storage(db)
    now = time.time()
    st.add_alert(Alert(now, "critical", "syn_flood", "rule", "SYN flood", src=None, dst="10.0.0.5"))
    st.add_alert(Alert(now, "medium", "port_scan", "rule", "scan", src="10.0.0.66", dst="10.0.0.5"))
    c = create_app(db).test_client()
    for ep in ["/", "/api/summary", "/api/timeline", "/api/top_sources", "/api/graph",
               "/api/protocols", "/api/traffic", "/api/perf", "/api/alerts", "/api/alert/1"]:
        assert c.get(ep).status_code == 200, ep
    s = c.get("/api/summary").get_json()
    assert s["total"] == 2 and s["attackers"] == 1
    g = c.get("/api/graph").get_json()
    assert len(g["edges"]) == 2
    assert len(c.get("/api/alerts?severity=critical").get_json()) == 1
    assert c.get("/api/alert/999").status_code == 404
