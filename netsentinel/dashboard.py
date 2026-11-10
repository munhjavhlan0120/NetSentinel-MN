"""Flask веб хяналтын самбар (визуал хэсэг) ба REST API."""
from __future__ import annotations

import json
import os
import time

from flask import Flask, abort, jsonify, render_template, request

from .storage import Storage

# Сэрэмжлүүлгийн ангиллыг дүрслэлд зориулж 7 бүлэгт нэгтгэнэ (өнгө тогтмол дарааллаар)
FAMILY = {
    "port_scan": "Скан", "slow_scan": "Скан", "host_sweep": "Скан",
    "syn_flood": "DoS", "icmp_flood": "DoS",
    "brute_force": "Нууц үг таах",
    "arp_spoof": "Spoofing",
    "dns_tunnel": "DNS tunnel",
    "traffic_anomaly": "Аномали", "ml_anomaly": "Аномали",
}
FAMILY_ORDER = ["Скан", "DoS", "Нууц үг таах", "Spoofing", "DNS tunnel", "Аномали", "Гүйцэтгэл"]
SEV_RANK = "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END"
RANK_SEV = {4: "critical", 3: "high", 2: "medium", 1: "low"}


def family(category: str) -> str:
    return FAMILY.get(category, "Гүйцэтгэл")


def create_app(db_path: str) -> Flask:
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    db = Storage(db_path)

    def since() -> float:
        return time.time() - 60 * float(request.args.get("minutes", 60))

    def alert_filter() -> tuple[str, list]:
        """URL параметрээр (severity, category, detector, q) шүүх WHERE нөхцөл."""
        where, args = ["ts>=?"], [since()]
        for col in ("severity", "category", "detector"):
            v = request.args.get(col)
            if v:
                where.append(f"{col}=?")
                args.append(v)
        q = request.args.get("q")
        if q:
            where.append("(src LIKE ? OR dst LIKE ? OR description LIKE ?)")
            args += [f"%{q}%"] * 3
        return " AND ".join(where), args

    @app.get("/")
    def index():
        return render_template("index.html", families=FAMILY_ORDER)

    # ---- тойм ----------------------------------------------------------------
    @app.get("/api/summary")
    def summary():
        t = since()
        sev = db.query("SELECT severity, COUNT(*) n FROM alerts WHERE ts>=? GROUP BY severity", (t,))
        cat = db.query("SELECT category, COUNT(*) n FROM alerts WHERE ts>=? "
                       "GROUP BY category ORDER BY n DESC", (t,))
        det = db.query("SELECT detector, COUNT(*) n FROM alerts WHERE ts>=? GROUP BY detector", (t,))
        src = db.query("SELECT COUNT(DISTINCT src) n FROM alerts WHERE ts>=? AND src IS NOT NULL", (t,))
        # Сүүлийн 6 цонхны (30 с) дундаж хурд — нэг дутуу цонхоос хамаарахгүй
        last = db.query("SELECT pkts, bytes, ts_start, ts_end, ml_score FROM traffic_windows "
                        "ORDER BY id DESC LIMIT 6")
        lw = dict(last[0]) if last else None
        if lw:
            dur = sum(r["ts_end"] - r["ts_start"] for r in last)
            lw["pps"] = sum(r["pkts"] or 0 for r in last) / max(dur, 1e-6)
        return jsonify({"severity": sev, "category": cat, "detector": det,
                        "attackers": src[0]["n"], "total": sum(r["n"] for r in sev),
                        "last_window": lw, "server_time": time.time()})

    # ---- халдлагын хугацааны шугам ------------------------------------------
    @app.get("/api/timeline")
    def timeline():
        b = max(int(request.args.get("bucket", 60)), 5)
        rows = db.query(f"SELECT CAST(ts/{b} AS INTEGER)*{b} t, category, COUNT(*) n FROM alerts "
                        "WHERE ts>=? GROUP BY t, category ORDER BY t", (since(),))
        out: dict[float, dict[str, int]] = {}
        for r in rows:
            fam = family(r["category"])
            out.setdefault(r["t"], {}).setdefault(fam, 0)
            out[r["t"]][fam] += r["n"]
        return jsonify({"bucket": b, "families": FAMILY_ORDER,
                        "rows": [{"t": t, **v} for t, v in sorted(out.items())]})

    # ---- хамгийн идэвхтэй халдагчид -----------------------------------------
    @app.get("/api/top_sources")
    def top_sources():
        rows = db.query(f"SELECT src, COUNT(*) n, MAX({SEV_RANK}) sev, "
                        "GROUP_CONCAT(DISTINCT category) cats, MIN(ts) first, MAX(ts) last "
                        "FROM alerts WHERE ts>=? AND src IS NOT NULL GROUP BY src "
                        "ORDER BY sev DESC, n DESC LIMIT ?",
                        (since(), int(request.args.get("limit", 10))))
        for r in rows:
            r["severity"] = RANK_SEV[r.pop("sev")]
            r["categories"] = (r.pop("cats") or "").split(",")
        return jsonify(rows)

    # ---- протоколын тархалт --------------------------------------------------
    @app.get("/api/protocols")
    def protocols():
        rows = db.query("SELECT features FROM traffic_windows WHERE ts_end>=?", (since(),))
        tot = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0}
        for r in rows:
            f = json.loads(r["features"] or "{}")
            for k in tot:
                tot[k] += int(f.get(k.lower(), 0))
        return jsonify(tot)

    # ---- эх -> очих холболтын граф -------------------------------------------
    @app.get("/api/graph")
    def graph():
        rows = db.query(f"SELECT COALESCE(src, 'хуурамч/олон эх') s, COALESCE(dst, 'олон хост') d, "
                        f"COUNT(*) n, MAX({SEV_RANK}) sev, GROUP_CONCAT(DISTINCT category) cats "
                        "FROM alerts WHERE ts>=? AND detector='rule' GROUP BY s, d", (since(),))
        nodes: dict[str, dict] = {}
        for r in rows:
            nodes.setdefault(r["s"], {"id": r["s"], "role": "source", "n": 0})["n"] += r["n"]
            nd = nodes.setdefault(r["d"], {"id": r["d"], "role": "target", "n": 0})
            nd["n"] += r["n"]
            if nodes[r["s"]]["role"] == "target":
                nodes[r["s"]]["role"] = "both"
        edges = [{"source": r["s"], "target": r["d"], "n": r["n"], "severity": RANK_SEV[r["sev"]],
                  "categories": (r["cats"] or "").split(",")} for r in rows]
        return jsonify({"nodes": list(nodes.values()), "edges": edges})

    # ---- урсгал, гүйцэтгэл ---------------------------------------------------
    @app.get("/api/traffic")
    def traffic():
        return jsonify(db.query(
            "SELECT ts_end ts,pkts,bytes,syn,icmp,ml_score FROM traffic_windows "
            "WHERE ts_end>=? ORDER BY ts_end", (since(),)))

    @app.get("/api/perf")
    def perf():
        return jsonify(db.query(
            "SELECT ts,target,rtt_avg,jitter,loss_pct,rx_mbps,tx_mbps FROM perf_samples "
            "WHERE ts>=? ORDER BY ts", (since(),)))

    # ---- сэрэмжлүүлгийн жагсаалт ба дэлгэрэнгүй ------------------------------
    @app.get("/api/alerts")
    def alerts():
        where, args = alert_filter()
        return jsonify(db.query(
            f"SELECT id,ts,severity,category,detector,src,dst,score,description FROM alerts "
            f"WHERE {where} ORDER BY ts DESC LIMIT ?", (*args, int(request.args.get("limit", 300)))))

    @app.get("/api/alert/<int:aid>")
    def alert_detail(aid: int):
        rows = db.query("SELECT * FROM alerts WHERE id=?", (aid,))
        if not rows:
            abort(404)
        a = rows[0]
        a["extra"] = json.loads(a["extra"] or "{}")
        a["family"] = family(a["category"])
        keys = [k for k in (a["src"], a["dst"]) if k]
        related = []
        if keys:
            marks = ",".join("?" * len(keys))
            related = db.query(
                f"SELECT id,ts,severity,category,detector,src,dst FROM alerts WHERE id<>? AND "
                f"(src IN ({marks}) OR dst IN ({marks})) ORDER BY ABS(ts-?) LIMIT 15",
                (aid, *keys, *keys, a["ts"]))
        win = db.query("SELECT ts_start, ts_end, features, ml_score FROM traffic_windows "
                       "WHERE ts_end>=? ORDER BY ts_end LIMIT 1", (a["ts"],))
        if win:
            win[0]["features"] = json.loads(win[0]["features"] or "{}")
        return jsonify({"alert": a, "related": related, "window": win[0] if win else None})

    return app


def run(db_path: str, host: str = "127.0.0.1", port: int = 8050) -> None:
    create_app(db_path).run(host=host, port=port, debug=False, threaded=True)
