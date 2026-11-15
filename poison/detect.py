"""Find address-poisoning events and the payments that fell for them.

Definitions (all on USDC Transfer logs in the window):

  genuine interaction   a transfer of >= 0.01 USDC between V and R. R is a real counterparty of V.
  poisoning candidate   a transfer of < 0.01 USDC (including 0) between V and L.
  lookalike             L != R, and L shares at least 4 hex characters at the start AND 4 at the end
                        with R (after "0x"). Chance of that for one random pair: 16^-8 = 1 in 4.3 billion.
  poison event          a candidate where L is a lookalike of a counterparty V interacted with BEFORE it.
  loss                  V later sends >= 0.01 USDC to L, after the first poison event between them.

Patterns:
  zero_value_spoof      0 USDC "from V to L": a transferFrom with amount 0 needs no allowance, so the attacker
                        can put a fake outgoing payment into V's history without V's key.
  zero_value_incoming   0 USDC from L to V.
  dust_from_lookalike   a tiny real amount from L to V.
  dust_to_lookalike     a tiny amount from V to L.

Window effect: a counterparty is only known if V interacted with it inside the window, so the counts are a
lower bound; poisoning that targets older relationships is missed.
"""
from __future__ import annotations

import argparse
import bisect
import sqlite3
import time
from collections import defaultdict
from pathlib import Path

from .collect import DEFAULT_DB, DUST_UNITS, connect
from .rpc import USDC_BASE, TRANSFER_TOPIC, Rpc

MIN_PREFIX = MIN_SUFFIX = 4


def common_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def match_lengths(a: str, b: str) -> tuple[int, int]:
    """Matching hex chars at the start and end of two 0x addresses (lower-case)."""
    ha, hb = a[2:], b[2:]
    return common_prefix(ha, hb), common_prefix(ha[::-1], hb[::-1])


def lookalike_key(a: str) -> str:
    return a[2:2 + MIN_PREFIX] + a[-MIN_SUFFIX:]


def build_indexes(con) -> None:
    con.execute("CREATE INDEX IF NOT EXISTS xfer_f ON xfer(f, block)")
    con.execute("CREATE INDEX IF NOT EXISTS xfer_t ON xfer(t, block)")
    con.execute("CREATE INDEX IF NOT EXISTS xfer_small ON xfer(v) WHERE v < %d" % DUST_UNITS)
    con.commit()


class Counterparties:
    """Genuine counterparties of one address, with every block they interacted in, keyed for lookalike lookups."""

    def __init__(self, con, vid: int, addr: dict[int, str]):
        blocks: dict[tuple[int, str], list[int]] = defaultdict(list)
        for other, b in con.execute("SELECT t, block FROM xfer WHERE f = ? AND v >= ?", (vid, DUST_UNITS)):
            blocks[(other, "sent")].append(b)
        for other, b in con.execute("SELECT f, block FROM xfer WHERE t = ? AND v >= ?", (vid, DUST_UNITS)):
            blocks[(other, "received")].append(b)
        self.by_key: dict[str, list[tuple[str, str, list[int]]]] = defaultdict(list)
        self.addresses = set()
        for (other, rel), bl in blocks.items():
            a = addr[other]
            self.addresses.add(a)
            self.by_key[lookalike_key(a)].append((a, rel, sorted(bl)))

    def before(self, lookalike: str, block: int):
        """Counterparties L imitates that V had interacted with before `block` (best match first)."""
        hits = []
        for real, rel, bl in self.by_key.get(lookalike_key(lookalike), []):
            if real == lookalike or bl[0] >= block:
                continue
            p, s = match_lengths(real, lookalike)
            last = bl[bisect.bisect_left(bl, block) - 1]
            hits.append((p + s, p, s, real, rel, bl[0], last))
        return sorted(hits, reverse=True)


def detect(con, rpc: Rpc | None = None, log=print) -> dict:
    build_indexes(con)
    # analysis tables are derived data: rebuild them from the schema on every run
    con.executescript("DROP TABLE IF EXISTS poison_events; DROP TABLE IF EXISTS losses;")
    con.executescript((Path(__file__).resolve().parents[1] / "sql" / "schema.sql").read_text())
    addr = dict(con.execute("SELECT id, a FROM addr"))
    cands = con.execute("SELECT block, li, f, t, v, tx FROM xfer WHERE v < ? ORDER BY block, li",
                        (DUST_UNITS,)).fetchall()
    log(f"{len(cands):,} transfers under 0.01 USDC to check")
    cache: dict[int, Counterparties] = {}
    checks_weighted = 0.0       # expected chance matches: sum over checks of n_counterparties / 16^8
    t0 = time.time()
    events = []
    for i, (block, li, f, t, v, tx) in enumerate(cands):
        for victim, other, outgoing in ((f, t, True), (t, f, False)):
            if victim == other:
                continue
            cp = cache.get(victim)
            if cp is None:
                cp = cache[victim] = Counterparties(con, victim, addr)
            checks_weighted += len(cp.addresses) / 16 ** 8
            hits = cp.before(addr[other], block)
            if not hits:
                continue
            _, p, s, real, rel, first, last = hits[0]
            if v == 0:
                pattern = "zero_value_spoof" if outgoing else "zero_value_incoming"
            else:
                pattern = "dust_to_lookalike" if outgoing else "dust_from_lookalike"
            events.append((block, li, tx, pattern, addr[victim], addr[other], real, p, s, rel, first, v, last))
        if i and i % 20000 == 0:
            log(f"  {i:,}/{len(cands):,} checked, {len(events):,} poison events, {time.time() - t0:.0f}s")
    con.executemany("INSERT OR IGNORE INTO poison_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    events)

    # losses: the victim later pays the lookalike a real amount
    ids = {a: i for i, a in addr.items()}
    first_poison = {}
    for block, _, _, _, victim, look, real, *_ in events:
        k = (victim, look)
        if k not in first_poison or block < first_poison[k][0]:
            first_poison[k] = (block, real)
    losses = []
    for (victim, look), (b0, real) in first_poison.items():
        for block, li, v in con.execute("SELECT block, li, v FROM xfer WHERE f = ? AND t = ? AND v >= ? AND block > ?",
                                        (ids[victim], ids[look], DUST_UNITS, b0)):
            losses.append([victim, look, real, b0, block, li, None, v])
    if rpc is not None:
        for row in losses:      # tx hashes of real-value transfers are not stored; fetch the few we need
            logs = rpc.call("eth_getLogs", [{"address": USDC_BASE, "fromBlock": hex(row[4]), "toBlock": hex(row[4]),
                                             "topics": [TRANSFER_TOPIC, "0x" + "0" * 24 + row[0][2:],
                                                        "0x" + "0" * 24 + row[1][2:]]}])
            row[6] = next((lg["transactionHash"] for lg in logs if int(lg["logIndex"], 16) == row[5]), None)
    con.executemany("INSERT OR IGNORE INTO losses VALUES (?,?,?,?,?,?,?,?)", losses)
    con.commit()
    summary = {"candidates": len(cands), "poison_events": len(events), "victims": len({e[4] for e in events}),
               "losses": len(losses), "lost_usdc": sum(r[7] for r in losses) / 1e6,
               "expected_chance_matches": checks_weighted, "seconds": round(time.time() - t0, 1)}
    log(summary)
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--offline", action="store_true", help="don't fetch tx hashes for losses")
    a = ap.parse_args()
    detect(connect(a.db), None if a.offline else Rpc())
