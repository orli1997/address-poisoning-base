"""Attribute poison events to operators: who sent each poisoning transaction, through which contract.

    python -m poison.campaigns

A transfer log shows the token's from/to, not who paid for the transaction. Attackers send many
poisonings in one transaction through a batch contract, so the transaction's sender (an EOA paying gas)
and its `to` (the batch contract) group events into operations. Also traces who funded the lookalike
addresses that send real dust (they need USDC to do it).
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

from .collect import DEFAULT_DB, connect
from .rpc import BASE_RPC


def batch(method: str, params_list: list[list], url: str = BASE_RPC, size: int = 100) -> list:
    out = []
    for i in range(0, len(params_list), size):
        chunk = params_list[i:i + size]
        body = json.dumps([{"jsonrpc": "2.0", "id": j, "method": method, "params": p}
                           for j, p in enumerate(chunk)]).encode()
        for attempt in range(6):
            try:
                req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                                      "User-Agent": "research-script"})
                with urllib.request.urlopen(req, timeout=90) as r:
                    res = sorted(json.load(r), key=lambda x: x["id"])
                break
            except Exception:   # noqa: BLE001  rate limit / transient
                time.sleep(min(2 ** attempt, 30))
        else:
            raise RuntimeError(f"batch {method} failed at {i}")
        out.extend(x.get("result") for x in res)
    return out


def attribute(con, log=print) -> None:
    con.executescript("DROP TABLE IF EXISTS tx_meta;")
    con.executescript((Path(__file__).resolve().parents[1] / "sql" / "schema.sql").read_text())
    txs = con.execute("SELECT tx, COUNT(*) FROM poison_events WHERE tx IS NOT NULL GROUP BY tx").fetchall()
    log(f"{len(txs):,} poisoning transactions to look up")
    t0, rows = time.time(), []
    for i in range(0, len(txs), 1000):
        chunk = txs[i:i + 1000]
        res = batch("eth_getTransactionByHash", [[t] for t, _ in chunk])
        for (tx, n), r in zip(chunk, res):
            if r:
                rows.append((tx, r["from"].lower(), (r["to"] or "").lower(), r["input"][:10], n))
        log(f"  {min(i + 1000, len(txs)):,}/{len(txs):,}  {time.time() - t0:.0f}s")
    con.executemany("INSERT OR REPLACE INTO tx_meta VALUES (?,?,?,?,?)", rows)

    # funders of lookalike addresses that send real dust: who gave them USDC (>= 0.1) in the window
    con.executescript("""
    DROP TABLE IF EXISTS lookalike_funding;
    CREATE TABLE lookalike_funding AS
    SELECT la.a AS lookalike, fa.a AS funder, COUNT(*) AS n, SUM(x.v) / 1e6 AS usdc
    FROM (SELECT DISTINCT lookalike FROM poison_events WHERE pattern = 'dust_from_lookalike') d
    JOIN addr la ON la.a = d.lookalike
    JOIN xfer x ON x.t = la.id AND x.v >= 100000
    JOIN addr fa ON fa.id = x.f
    GROUP BY 1, 2;
    """)
    con.commit()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    attribute(connect(ap.parse_args().db))
