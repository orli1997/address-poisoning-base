"""Live address-poisoning detector for USDC on Base: reads every new block and raises alerts within seconds.

    python -m poison.live                      # follow the chain head (Ctrl+C to stop, rerun to resume)
    python -m poison.live --seed               # first, load known relationships from the 72 h research DB
    python -m poison.live --replay             # check: rerun the research window through the live logic

The rules are the ones in detect.py, applied one transfer at a time and in chain order:

  relationship   every transfer of >= 1 USDC records (owner, counterparty, first block, last block), both ways
  poison alert   a transfer under 0.1 USDC between V and L, where L is a stranger to V (no relationship before
                 this block) and shares >= 4 hex chars at the start and end with someone V has a relationship with
  loss alert     V later sends >= 1 USDC to an L it was poisoned with

Only the first poison event for a (victim, lookalike) pair raises an alert; later ones increase its count.
Alerts go to stdout as JSON lines and to the `pairs` / `loss_alerts` tables, which the alert bot (step 2) reads.

The detector only knows relationships it has seen, so a fresh start misses poisoning that imitates older
counterparties. --seed shortens that warm-up; relationships unused for --keep-days are pruned.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import time
from pathlib import Path

from .detect import CANDIDATE_UNITS, GENUINE_UNITS, MIN_PREFIX, MIN_SUFFIX, lookalike_key, match_lengths
from .rpc import TRANSFER_TOPIC, USDC_BASE, Rpc, RpcError

LIVE_DB = Path(os.environ.get("POISON_LIVE_DB", Path.home() / "poisoning_data" / "live.db"))
RESEARCH_DB = Path(os.environ.get("POISON_DB", Path.home() / "poisoning_data" / "base_usdc.db"))
CONFIRMATIONS = 10            # stay this many blocks behind head (~2 s) to avoid reorged blocks
MAX_RANGE = 2_000             # blocks per eth_getLogs call when catching up
BLOCKS_PER_DAY = 432_000      # Base at 0.2 s blocks

SCHEMA = """
CREATE TABLE IF NOT EXISTS addr (id INTEGER PRIMARY KEY, a TEXT NOT NULL UNIQUE);
-- one row per direction: owner sent to / received from other at least 1 USDC
CREATE TABLE IF NOT EXISTS rel (
    owner INTEGER NOT NULL, other INTEGER NOT NULL,
    k INTEGER NOT NULL,                      -- lookalike key of `other` (first 4 + last 4 hex chars)
    first INTEGER NOT NULL, last INTEGER NOT NULL,
    PRIMARY KEY (owner, other)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rel_k ON rel(owner, k);
CREATE INDEX IF NOT EXISTS rel_last ON rel(last);
-- one row per (victim, lookalike): the alert the bot sends
CREATE TABLE IF NOT EXISTS pairs (
    victim TEXT NOT NULL, lookalike TEXT NOT NULL, mimics TEXT NOT NULL,
    prefix_match INTEGER, suffix_match INTEGER, pattern TEXT,
    first_block INTEGER, first_tx TEXT, last_block INTEGER, events INTEGER NOT NULL,
    detected_at INTEGER,                     -- unix time the detector saw it
    PRIMARY KEY (victim, lookalike)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairs_look ON pairs(lookalike);
CREATE TABLE IF NOT EXISTS loss_alerts (
    victim TEXT, lookalike TEXT, mimics TEXT, block INTEGER, li INTEGER, tx TEXT, amount_units INTEGER,
    detected_at INTEGER, PRIMARY KEY (block, li)
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def connect_live(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript(SCHEMA)
    return con


def get_meta(con, k, default=None):
    r = con.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
    return r[0] if r else default


def set_meta(con, k, v):
    con.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))


def key_int(a: str) -> int:
    return int(lookalike_key(a), 16)


def pattern_of(v: int, outgoing: bool) -> str:
    if v == 0:
        return "zero_value_spoof" if outgoing else "zero_value_incoming"
    return "dust_to_lookalike" if outgoing else "dust_from_lookalike"


def parse_logs(logs: list[dict]) -> list[tuple]:
    """Transfer logs -> (block, li, from, to, value, tx), in chain order."""
    out = []
    for lg in logs:
        if len(lg["topics"]) != 3 or lg.get("removed"):
            continue
        v = int(lg["data"], 16) if lg["data"] not in ("0x", "") else 0
        out.append((int(lg["blockNumber"], 16), int(lg["logIndex"], 16), "0x" + lg["topics"][1][-40:].lower(),
                    "0x" + lg["topics"][2][-40:].lower(), v, lg["transactionHash"]))
    return sorted(out)


class LiveDetector:
    def __init__(self, con: sqlite3.Connection, emit=None, now=time.time):
        self.con, self.emit, self.now = con, emit or (lambda alert: None), now
        self.stats = {"transfers": 0, "relationships": 0, "poison_events": 0, "new_pairs": 0, "losses": 0}

    # address interning -----------------------------------------------------------------------------------------
    def id_of(self, a: str) -> int | None:
        r = self.con.execute("SELECT id FROM addr WHERE a = ?", (a,)).fetchone()
        return r[0] if r else None

    def intern(self, a: str) -> int:
        i = self.id_of(a)
        return i if i is not None else self.con.execute("INSERT INTO addr(a) VALUES (?)", (a,)).lastrowid

    # rules -----------------------------------------------------------------------------------------------------
    def remember(self, f: str, t: str, block: int) -> None:
        fi, ti = self.intern(f), self.intern(t)
        self.con.executemany("""INSERT INTO rel VALUES (?, ?, ?, ?, ?)
                                ON CONFLICT(owner, other) DO UPDATE SET last = MAX(last, excluded.last)""",
                             [(fi, ti, key_int(t), block, block), (ti, fi, key_int(f), block, block)])
        self.stats["relationships"] += 1

    def mimicked(self, victim: str, other: str, block: int):
        """Best counterparty of `victim` that `other` imitates, or None (stranger rule applied)."""
        vi = self.id_of(victim)
        if vi is None:
            return None
        oi = self.id_of(other)
        if oi is not None and self.con.execute("SELECT 1 FROM rel WHERE owner = ? AND other = ? AND first < ?",
                                               (vi, oi, block)).fetchone():
            return None                                  # a real counterparty, not a stranger
        best = None
        for real, first in self.con.execute("""SELECT a.a, r.first FROM rel r JOIN addr a ON a.id = r.other
                                               WHERE r.owner = ? AND r.k = ? AND r.first < ?""",
                                            (vi, key_int(other), block)):
            if real == other:
                continue
            p, s = match_lengths(real, other)
            if p >= MIN_PREFIX and s >= MIN_SUFFIX and (best is None or p + s > best[1] + best[2]):
                best = (real, p, s)
        return best

    def check_loss(self, f: str, t: str, block: int, li: int, v: int, tx: str) -> None:
        r = self.con.execute("SELECT mimics FROM pairs WHERE victim = ? AND lookalike = ? AND first_block < ?",
                             (f, t, block)).fetchone()
        if not r:
            return
        now = int(self.now())
        if self.con.execute("INSERT OR IGNORE INTO loss_alerts VALUES (?,?,?,?,?,?,?,?)",
                            (f, t, r[0], block, li, tx, v, now)).rowcount:
            self.stats["losses"] += 1
            self.emit({"kind": "loss", "victim": f, "lookalike": t, "mimics": r[0], "usdc": v / 1e6,
                       "block": block, "tx": tx, "detected_at": now})

    def poison(self, block: int, li: int, f: str, t: str, v: int, tx: str) -> None:
        for victim, other, outgoing in ((f, t, True), (t, f, False)):
            if victim == other:
                continue
            hit = self.mimicked(victim, other, block)
            if hit is None:
                continue
            real, p, s = hit
            self.stats["poison_events"] += 1
            now = int(self.now())
            self.con.execute("""INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,1,?)
                                      ON CONFLICT(victim, lookalike) DO UPDATE
                                      SET events = events + 1, last_block = excluded.last_block""",
                                   (victim, other, real, p, s, pattern_of(v, outgoing), block, tx, block, now))
            if self.con.execute("SELECT events FROM pairs WHERE victim = ? AND lookalike = ?",
                                (victim, other)).fetchone()[0] == 1:
                self.stats["new_pairs"] += 1
                self.emit({"kind": "poison", "victim": victim, "lookalike": other, "mimics": real,
                           "prefix_match": p, "suffix_match": s, "pattern": pattern_of(v, outgoing),
                           "usdc": v / 1e6, "block": block, "tx": tx, "detected_at": now})

    def process(self, rows) -> None:
        """Apply the rules to transfers (block, li, from, to, value, tx) given in chain order."""
        for block, li, f, t, v, tx in rows:
            self.stats["transfers"] += 1
            if v >= GENUINE_UNITS:
                self.check_loss(f, t, block, li, v, tx)
                self.remember(f, t, block)
            elif v < CANDIDATE_UNITS:
                self.poison(block, li, f, t, v, tx)

    def prune(self, before_block: int) -> int:
        return self.con.execute("DELETE FROM rel WHERE last < ?", (before_block,)).rowcount


# chain access ----------------------------------------------------------------------------------------------------
def fetch(rpc: Rpc, lo: int, hi: int) -> list[dict]:
    try:
        return rpc.transfer_logs(USDC_BASE, lo, hi)
    except RpcError:
        if lo == hi:
            raise
        mid = (lo + hi) // 2
        return fetch(rpc, lo, mid) + fetch(rpc, mid + 1, hi)


def print_alert(alert: dict) -> None:
    print(json.dumps(alert), flush=True)


def follow(db: Path, rpc: Rpc, poll: float, keep_days: float, until: int | None = None) -> None:
    con = connect_live(db)
    det = LiveDetector(con, emit=print_alert)
    nxt = int(get_meta(con, "next_block") or rpc.head() - CONFIRMATIONS)
    print(f"# following USDC on Base from block {nxt:,}; Ctrl+C to stop", flush=True)
    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    last_status = last_prune = 0.0
    while not stop and (until is None or nxt <= until):
        head = rpc.head() - CONFIRMATIONS
        hi = min(head, nxt + MAX_RANGE - 1, until if until is not None else head)
        if hi < nxt:
            time.sleep(poll)
            continue
        det.process(parse_logs(fetch(rpc, nxt, hi)))
        nxt = hi + 1
        set_meta(con, "next_block", nxt)
        con.commit()
        if time.time() - last_prune > 3600:
            last_prune = time.time()
            n = det.prune(nxt - int(keep_days * BLOCKS_PER_DAY))
            con.commit()
            if n:
                print(f"# pruned {n:,} stale relationships", flush=True)
        if time.time() - last_status > 60:
            last_status = time.time()
            lag = time.time() - rpc.block_time(hi)
            print(f"# block {hi:,}  lag {lag:.0f}s  {json.dumps(det.stats)}", flush=True)
        if hi == head:
            time.sleep(poll)
    print(f"# stopped at block {nxt:,}  {json.dumps(det.stats)}", flush=True)


# warm start and validation ---------------------------------------------------------------------------------------
def research_rows(src: sqlite3.Connection):
    return src.execute("""SELECT x.block, x.li, fa.a, ta.a, x.v, x.tx FROM xfer x
                          JOIN addr fa ON fa.id = x.f JOIN addr ta ON ta.id = x.t ORDER BY x.block, x.li""")


def seed(db: Path, research: Path) -> None:
    """Load the research window's >= 1 USDC relationships, so the detector starts with history."""
    con, src = connect_live(db), sqlite3.connect(f"file:{research}?mode=ro", uri=True)
    det = LiveDetector(con)
    n = 0
    for f, t, first, last in src.execute("""SELECT fa.a, ta.a, MIN(x.block), MAX(x.block) FROM xfer x
                                            JOIN addr fa ON fa.id = x.f JOIN addr ta ON ta.id = x.t
                                            WHERE x.v >= ? GROUP BY x.f, x.t""", (GENUINE_UNITS,)):
        fi, ti = det.intern(f), det.intern(t)
        for o, other, k in ((fi, ti, key_int(t)), (ti, fi, key_int(f))):
            con.execute("""INSERT INTO rel VALUES (?, ?, ?, ?, ?) ON CONFLICT(owner, other) DO UPDATE
                           SET first = MIN(first, excluded.first), last = MAX(last, excluded.last)""",
                        (o, other, k, first, last))
        n += 1
        if n % 200_000 == 0:
            con.commit()
            print(f"  {n:,} relationships", flush=True)
    con.commit()
    print(f"seeded {n:,} sender->receiver relationships from {research}")


def replay(research: Path, out: Path) -> dict:
    """Run the research window through the live logic and compare with the batch detector's tables."""
    if out.exists():
        out.unlink()
    con, src = connect_live(out), sqlite3.connect(f"file:{research}?mode=ro", uri=True)
    det = LiveDetector(con)
    t0, batch = time.time(), []
    for row in research_rows(src):
        batch.append(row)
        if len(batch) == 50_000:
            det.process(batch)
            con.commit()
            batch = []
            if det.stats["transfers"] % 1_000_000 == 0:
                print(f"  {det.stats['transfers']:,} transfers, {time.time() - t0:.0f}s, {det.stats}", flush=True)
    det.process(batch)
    con.commit()
    want_events = src.execute("SELECT COUNT(*) FROM poison_events").fetchone()[0]
    want_pairs = src.execute("SELECT COUNT(*) FROM (SELECT DISTINCT victim, lookalike FROM poison_events)").fetchone()[0]
    want_losses = src.execute("SELECT COUNT(*) FROM losses").fetchone()[0]
    result = {"live_poison_events": det.stats["poison_events"], "batch_poison_events": want_events,
              "live_pairs": det.stats["new_pairs"], "batch_pairs": want_pairs,
              "live_losses": det.stats["losses"], "batch_losses": want_losses,
              "transfers": det.stats["transfers"], "seconds": round(time.time() - t0)}
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=LIVE_DB)
    ap.add_argument("--seed", action="store_true", help="load relationships from the research DB, then exit")
    ap.add_argument("--replay", action="store_true", help="rerun the research window and compare with batch")
    ap.add_argument("--research-db", type=Path, default=RESEARCH_DB)
    ap.add_argument("--poll", type=float, default=2.0, help="seconds between head checks")
    ap.add_argument("--keep-days", type=float, default=30, help="forget relationships unused for this long")
    ap.add_argument("--until", type=int, help="stop after this block (for tests)")
    a = ap.parse_args()
    if a.seed:
        seed(a.db, a.research_db)
    elif a.replay:
        replay(a.research_db, a.db.with_name("replay.db"))
    else:
        follow(a.db, Rpc(), a.poll, a.keep_days, a.until)
