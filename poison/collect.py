"""Collect every USDC Transfer on Base for a time window into SQLite. Resumable.

    python -m poison.collect --hours 24            # last 24 h (ending ~5 min ago)
    python -m poison.collect                       # resume an interrupted run

The database lives outside OneDrive by default (it gets large: ~3M rows per day).
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

from .rpc import USDC_BASE, Rpc, RpcError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = Path(os.environ.get("POISON_DB", Path.home() / "poisoning_data" / "base_usdc.db"))
DUST_UNITS = 10_000            # 0.01 USDC: below this a transfer is a poisoning candidate and keeps its tx hash
SAFE_LAG = 1_500               # ~5 minutes behind head at 0.2 s blocks


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript((ROOT / "sql" / "schema.sql").read_text())
    return con


def meta(con, k, default=None):
    r = con.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
    return r[0] if r else default


def set_meta(con, k, v):
    con.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))


class Interner:
    def __init__(self, con):
        self.con = con
        self.ids = {a: i for i, a in con.execute("SELECT id, a FROM addr")}

    def __call__(self, a: str) -> int:
        i = self.ids.get(a)
        if i is None:
            i = self.con.execute("INSERT INTO addr(a) VALUES (?)", (a,)).lastrowid
            self.ids[a] = i
        return i


def rows_from_logs(logs, intern):
    out = []
    for lg in logs:
        if len(lg["topics"]) != 3:          # not a standard Transfer(from, to, value)
            continue
        v = int(lg["data"], 16) if lg["data"] not in ("0x", "") else 0
        out.append((int(lg["blockNumber"], 16), int(lg["logIndex"], 16),
                    intern("0x" + lg["topics"][1][-40:].lower()), intern("0x" + lg["topics"][2][-40:].lower()),
                    v, lg["transactionHash"] if v < DUST_UNITS else None))
    return out


def run(db: Path, hours: float | None, rpc: Rpc) -> None:
    con = connect(db)
    if hours is not None and meta(con, "end_block") is None:
        end = rpc.head() - SAFE_LAG
        span = int(hours * 3600 / ((rpc.block_time(end) - rpc.block_time(end - 10_000)) / 10_000))
        set_meta(con, "start_block", end - span)
        set_meta(con, "next_block", end - span)
        set_meta(con, "end_block", end)
        con.commit()
    if meta(con, "end_block") is None:
        sys.exit("nothing to resume: pass --hours")
    nxt, end = int(meta(con, "next_block")), int(meta(con, "end_block"))
    start = int(meta(con, "start_block"))
    intern, step, t0 = Interner(con), 1200, time.time()
    print(f"collecting blocks {start}..{end} ({end - start:,} blocks), resuming at {nxt}", flush=True)
    while nxt <= end:
        hi = min(nxt + step - 1, end)
        try:
            logs = rpc.transfer_logs(USDC_BASE, nxt, hi)
        except RpcError as e:
            if "max results" in str(e) or "range" in str(e):
                step = max(50, step // 2)
                continue
            raise
        rows = rows_from_logs(logs, intern)
        con.executemany("INSERT OR IGNORE INTO xfer VALUES (?,?,?,?,?,?)", rows)
        con.execute("INSERT OR IGNORE INTO block_time VALUES (?, ?)", (nxt, rpc.block_time(nxt)))
        nxt = hi + 1
        set_meta(con, "next_block", nxt)
        con.commit()
        if len(logs) < 9_000:
            step = min(2_400, int(step * 1.2))
        done = (nxt - start) / (end - start)
        el = time.time() - t0
        print(f"  {done:6.1%}  block {hi}  +{len(rows):5d} transfers  step {step}  "
              f"elapsed {el / 60:5.1f} min", flush=True)
    con.execute("INSERT OR IGNORE INTO block_time VALUES (?, ?)", (end, rpc.block_time(end)))
    con.commit()
    n = con.execute("SELECT COUNT(*) FROM xfer").fetchone()[0]
    print(f"done: {n:,} transfers in {db}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float)
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    a = ap.parse_args()
    run(a.db, a.hours, Rpc())
