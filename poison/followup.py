"""Follow-up: did poisoned victims pay the lookalike AFTER the 72-hour window?

    python -m poison.followup            # scan from the window's end (or where it stopped) to the chain head
    python -m poison.followup --report   # only recompute and print the follow-up losses

Losses usually come days after the poison, so the window alone gives a lower bound. This asks the node for
every USDC transfer *into* any of the window's lookalike addresses (2,000 addresses per query, 50,000 blocks
per query: the public node's limits), stores them in `followup_xfer`, and is resumable, so it can be rerun
later to extend the follow-up period.

A follow-up loss = a transfer of >= 1 USDC from victim V to lookalike L, where (V, L) is a poison event from
the window. Transfers into lookalikes from anyone else are kept and counted separately (an attacker funding
its own address, or a victim we did not see being poisoned).
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from .collect import DEFAULT_DB, connect, meta, set_meta
from .detect import GENUINE_UNITS
from .rpc import TRANSFER_TOPIC, USDC_BASE, Rpc, RpcError

ADDRS_PER_QUERY = 2000
BLOCKS_PER_QUERY = 50_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS followup_xfer (
  block INTEGER NOT NULL, li INTEGER NOT NULL, f TEXT NOT NULL, t TEXT NOT NULL, v INTEGER NOT NULL, tx TEXT NOT NULL,
  PRIMARY KEY (block, li)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS followup_xfer_t ON followup_xfer(t);
"""


def pad(a: str) -> str:
    return "0x" + "0" * 24 + a[2:].lower()


def fetch(rpc: Rpc, lo: int, hi: int, topics_to: list[str], depth: int = 0) -> list[dict]:
    """eth_getLogs for transfers into `topics_to`; on a node error, split the block range and retry."""
    try:
        return rpc.call("eth_getLogs", [{"address": USDC_BASE, "fromBlock": hex(lo), "toBlock": hex(hi),
                                         "topics": [TRANSFER_TOPIC, None, topics_to]}])
    except RpcError:
        if hi == lo or depth > 12:
            raise
        time.sleep(2)
        mid = (lo + hi) // 2
        return fetch(rpc, lo, mid, topics_to, depth + 1) + fetch(rpc, mid + 1, hi, topics_to, depth + 1)


def scan(con, rpc: Rpc, log=print) -> None:
    con.executescript(SCHEMA)
    looks = [r[0] for r in con.execute("SELECT DISTINCT lookalike FROM poison_events ORDER BY lookalike")]
    groups = [looks[i:i + ADDRS_PER_QUERY] for i in range(0, len(looks), ADDRS_PER_QUERY)]
    start = int(meta(con, "followup_next_block", int(meta(con, "end_block")) + 1))
    if meta(con, "followup_start_block") is None:
        set_meta(con, "followup_start_block", start)
    head = rpc.head() - 30                       # stay a few seconds behind the tip
    log(f"{len(looks):,} lookalikes in {len(groups)} groups; blocks {start:,} -> {head:,}")
    t0 = time.time()
    for lo in range(start, head + 1, BLOCKS_PER_QUERY):
        hi = min(lo + BLOCKS_PER_QUERY - 1, head)
        rows = []
        for g in groups:
            logs = fetch(rpc, lo, hi, [pad(a) for a in g])
            rows += [(int(x["blockNumber"], 16), int(x["logIndex"], 16), "0x" + x["topics"][1][-40:],
                      "0x" + x["topics"][2][-40:], int(x["data"], 16), x["transactionHash"]) for x in logs]
        con.executemany("INSERT OR IGNORE INTO followup_xfer VALUES (?,?,?,?,?,?)", rows)
        set_meta(con, "followup_next_block", hi + 1)
        set_meta(con, "followup_end_block", hi)
        con.commit()
        log(f"  {hi:,}  +{len(rows)} transfers  {time.time() - t0:.0f}s")
    set_meta(con, "followup_end_ts", rpc.block_time(int(meta(con, "followup_end_block"))))
    con.commit()


def losses(con) -> dict:
    """Recompute follow-up losses from followup_xfer + poison_events. Pure SQL, no network."""
    con.executescript(SCHEMA + """
    DROP TABLE IF EXISTS followup_losses;
    CREATE TABLE followup_losses AS
    SELECT x.f AS victim, x.t AS lookalike, x.block, x.tx, x.v AS amount_units,
           (SELECT MIN(e.block) FROM poison_events e WHERE e.victim = x.f AND e.lookalike = x.t) AS first_poison_block,
           (SELECT e.mimics FROM poison_events e WHERE e.victim = x.f AND e.lookalike = x.t LIMIT 1) AS mimics
    FROM followup_xfer x
    WHERE x.v >= %d AND EXISTS (SELECT 1 FROM poison_events e WHERE e.victim = x.f AND e.lookalike = x.t);
    """ % GENUINE_UNITS)
    q = lambda s: con.execute(s).fetchone()
    n, victims, usdc = q("SELECT COUNT(*), COUNT(DISTINCT victim), COALESCE(SUM(amount_units), 0) / 1e6 FROM followup_losses")
    other_n, other_usdc = q(f"""SELECT COUNT(*), COALESCE(SUM(v), 0) / 1e6 FROM followup_xfer x WHERE v >= {GENUINE_UNITS}
        AND NOT EXISTS (SELECT 1 FROM poison_events e WHERE e.victim = x.f AND e.lookalike = x.t)""")
    con.commit()
    return {"start_block": meta(con, "followup_start_block"), "end_block": meta(con, "followup_end_block"),
            "transfers_into_lookalikes": q("SELECT COUNT(*) FROM followup_xfer")[0],
            "loss_payments": n, "victims_who_paid": victims, "usdc_lost": round(usdc, 2),
            "other_payments_into_lookalikes_ge_1usdc": other_n, "other_usdc": round(other_usdc, 2)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--report", action="store_true", help="skip the scan, only recompute")
    a = ap.parse_args()
    con = connect(a.db)
    if not a.report:
        scan(con, Rpc())
    print(losses(con))
