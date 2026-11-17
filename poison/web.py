"""Local web page: check an address before sending, and a live dashboard of what the detector sees.

    python -m poison.web               # http://127.0.0.1:8787  (check)  and  /dashboard

Reads the live DB read-only, next to a running `python -m poison.live`. Binds to localhost only.
The dashboard shows imitated addresses and lookalikes, never a list of victims.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .detect import MIN_PREFIX, MIN_SUFFIX, match_lengths
from .live import LIVE_DB, key_int

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"
ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")


def ro(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30, check_same_thread=False)
    return con


def check(con, to: str, sender: str | None = None) -> dict:
    """Verdict for sending to `to` (optionally from `sender`): danger > warning > known > unknown."""
    out = {"to": to, "from": sender, "known_lookalike": None, "planted_in_your_history": None,
           "imitates_your_counterparty": None, "paid_before": False, "losses_to_it": 0}
    n, victims, mimics, first = con.execute("""SELECT COUNT(*), COUNT(DISTINCT victim), MIN(mimics), MIN(first_block)
                                               FROM pairs WHERE lookalike = ?""", (to,)).fetchone()
    if n:
        top = [r[0] for r in con.execute("""SELECT mimics FROM pairs WHERE lookalike = ? GROUP BY mimics
                                            ORDER BY COUNT(*) DESC LIMIT 3""", (to,))]
        out["known_lookalike"] = {"victims": victims, "mimics": top, "first_block": first}
    out["losses_to_it"] = con.execute("SELECT COUNT(*) FROM loss_alerts WHERE lookalike = ?", (to,)).fetchone()[0]
    if sender:
        r = con.execute("SELECT mimics, first_block FROM pairs WHERE victim = ? AND lookalike = ?",
                        (sender, to)).fetchone()
        if r:
            out["planted_in_your_history"] = {"mimics": r[0], "block": r[1]}
        sid = con.execute("SELECT id FROM addr WHERE a = ?", (sender,)).fetchone()
        tid = con.execute("SELECT id FROM addr WHERE a = ?", (to,)).fetchone()
        if sid:
            if tid:
                out["paid_before"] = bool(con.execute("SELECT 1 FROM rel WHERE owner = ? AND other = ?",
                                                      (sid[0], tid[0])).fetchone())
            best = None
            for real, in con.execute("""SELECT a.a FROM rel r JOIN addr a ON a.id = r.other
                                        WHERE r.owner = ? AND r.k = ?""", (sid[0], key_int(to))):
                p, s = match_lengths(real, to)
                if real != to and p >= MIN_PREFIX and s >= MIN_SUFFIX and (best is None or p + s > best[1] + best[2]):
                    best = (real, p, s)
            if best:
                out["imitates_your_counterparty"] = {"real": best[0], "prefix": best[1], "suffix": best[2]}
    if out["known_lookalike"] or out["planted_in_your_history"] or out["losses_to_it"]:
        out["verdict"] = "danger"
    elif out["imitates_your_counterparty"]:
        out["verdict"] = "warning"
    elif out["paid_before"]:
        out["verdict"] = "known"
    else:
        out["verdict"] = "unknown"
    return out


def stats(con, now: float | None = None) -> dict:
    now = now or time.time()
    meta = dict(con.execute("SELECT k, v FROM meta"))
    since = now - 24 * 3600
    live = con.execute("""SELECT COUNT(*), COALESCE(SUM(events), 0), COUNT(DISTINCT victim), COUNT(DISTINCT lookalike),
                                 MIN(detected_at)
                          FROM pairs WHERE detected_at IS NOT NULL""").fetchone()
    losses = con.execute("SELECT COUNT(*), COALESCE(SUM(amount_units), 0) FROM loss_alerts").fetchone()
    buckets = dict(con.execute("""SELECT detected_at / 600 * 600, COUNT(*) FROM pairs
                                  WHERE detected_at >= ? GROUP BY 1""", (int(since),)))
    start = int(since) // 600 * 600 + 600       # always a full 24 h axis
    series = [{"t": t, "pairs": buckets.get(t, 0)} for t in range(start, int(now) // 600 * 600 + 1, 600)]
    top_mimicked = [{"address": a, "lookalikes": lk, "victims": v} for a, lk, v in con.execute("""
        SELECT mimics, COUNT(DISTINCT lookalike), COUNT(DISTINCT victim) FROM pairs WHERE detected_at >= ?
        GROUP BY mimics ORDER BY 3 DESC LIMIT 8""", (int(since),))]
    top_lookalikes = [{"address": a, "mimics": m, "victims": v} for a, m, v in con.execute("""
        SELECT lookalike, MIN(mimics), COUNT(DISTINCT victim) FROM pairs WHERE detected_at >= ?
        GROUP BY lookalike ORDER BY 3 DESC LIMIT 8""", (int(since),))]
    recent_losses = [{"lookalike": l, "mimics": m, "usdc": u / 1e6, "tx": tx, "at": at} for l, m, u, tx, at in
                     con.execute("""SELECT lookalike, mimics, amount_units, tx, detected_at FROM loss_alerts
                                    ORDER BY detected_at DESC LIMIT 10""")]
    ev = ROOT / "reports" / "evaluation.json"
    return {
        "now": int(now),
        "detector": {"next_block": int(meta.get("next_block", 0)), "updated_at": int(meta.get("updated_at", 0))},
        "live": {"since": live[4], "pairs": live[0], "events": live[1], "victims": live[2], "lookalikes": live[3],
                 "losses": losses[0], "lost_usdc": losses[1] / 1e6},
        "known_pairs_total": con.execute("SELECT COUNT(*) FROM pairs").fetchone()[0],
        "series": series, "top_mimicked": top_mimicked, "top_lookalikes": top_lookalikes,
        "recent_losses": recent_losses,
        "evaluation": json.loads(ev.read_text()) if ev.exists() else None,
    }


def make_handler(db: Path):
    con, lock = ro(db), threading.Lock()      # one read-only connection, one query at a time

    class Handler(BaseHTTPRequestHandler):
        def send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def json(self, obj, code: int = 200) -> None:
            self.send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0].strip().lower() for k, v in parse_qs(u.query).items()}
            if u.path in ("/", "/check"):
                return self.send(200, (STATIC / "check.html").read_bytes(), "text/html; charset=utf-8")
            if u.path == "/dashboard":
                return self.send(200, (STATIC / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
            if u.path == "/api/check":
                to, sender = q.get("to", ""), q.get("from") or None
                if not ADDRESS.match(to) or (sender and not ADDRESS.match(sender)):
                    return self.json({"error": "Enter full 42-character 0x addresses."}, 400)
                with lock:
                    result = check(con, to, sender)
                return self.json(result)
            if u.path == "/api/stats":
                with lock:
                    result = stats(con)
                return self.json(result)
            self.send(404, b"not found", "text/plain")

        def log_message(self, *args):        # keep addresses people check out of the console
            pass

    return Handler


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=LIVE_DB)
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    print(f"http://127.0.0.1:{a.port}  (check)   http://127.0.0.1:{a.port}/dashboard", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(a.db)).serve_forever()
