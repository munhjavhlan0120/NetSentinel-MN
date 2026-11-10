#!/usr/bin/env python3
"""Веб самбарын хариу өгөх хугацааг хэмжиж, дэлгэцийн зураг авна.

  python3 experiments/dashboard_bench.py demo.db results [chart.umd.js]
3-р аргумент: интернэтгүй орчинд Chart.js-ийн локал хуулбар.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netsentinel.dashboard import create_app  # noqa: E402

ENDPOINTS = ["/api/summary", "/api/timeline?bucket=60", "/api/top_sources", "/api/graph",
             "/api/traffic", "/api/protocols", "/api/alerts", "/api/perf"]


def main(db: str, out: str, chartjs: str | None = None) -> None:
    os.makedirs(os.path.join(out, "fig"), exist_ok=True)
    app = create_app(db)
    c = app.test_client()
    lat = {}
    for ep in ENDPOINTS:
        sep = "&" if "?" in ep else "?"
        ts = []
        for _ in range(30):
            t = time.perf_counter()
            r = c.get(ep + sep + "minutes=120")
            ts.append((time.perf_counter() - t) * 1000)
            assert r.status_code == 200
        lat[ep.split("?")[0]] = {"median_ms": statistics.median(ts), "p95_ms": sorted(ts)[int(0.95 * len(ts)) - 1],
                                 "bytes": len(r.data)}
    res = {"api": lat}

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps(res, indent=1))
        return
    threading.Thread(target=lambda: app.run(port=8057, threaded=True), daemon=True).start()
    time.sleep(1.0)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1400, "height": 900})
        if chartjs:
            pg.route("**/chart.umd.min.js", lambda r: r.fulfill(path=chartjs, content_type="application/javascript"))
        loads = []
        for _ in range(5):
            t = time.perf_counter()
            pg.goto("http://127.0.0.1:8057/")
            pg.wait_for_function("document.getElementById('updated').textContent.startsWith('шинэчлэгдсэн')")
            loads.append((time.perf_counter() - t) * 1000)
        res["page_load_ms"] = {"median": statistics.median(loads), "max": max(loads)}
        # Нэг шинэчлэлтийн (7 API + зурах) хугацаа хөтөч дотор
        res["refresh_ms"] = pg.evaluate("""async () => { const t = performance.now(); await refresh();
                                           return performance.now() - t; }""")
        time.sleep(0.5)
        f = os.path.join(out, "fig")
        pg.screenshot(path=os.path.join(f, "dash_full.png"), full_page=True)
        pg.screenshot(path=os.path.join(f, "dash_top.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 900})
        pg.add_style_tag(content="header{position:static !important}")
        g = pg.query_selector("#graph").evaluate_handle("e => e.closest('section')")
        g.as_element().screenshot(path=os.path.join(f, "dash_graph.png"))
        # Шүүлт: халдагч IP дээр дарах
        pg.click("#topsrc tr[data-ip='192.168.56.66']")
        time.sleep(0.8)
        el = pg.query_selector("#alerts").evaluate_handle("e => e.closest('section')")
        el.as_element().screenshot(path=os.path.join(f, "dash_filtered.png"))
        # Дэлгэрэнгүй цонх
        pg.click("#alerts tr[data-id]")
        time.sleep(0.8)
        pg.screenshot(path=os.path.join(f, "dash_detail.png"))
        b.close()
    json.dump(res, open(os.path.join(out, "dashboard_bench.json"), "w"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
