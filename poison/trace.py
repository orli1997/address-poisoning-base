"""Trace where the attackers' native ETH comes from (needs an Alchemy key in .env: ALCHEMY_KEY=...).

    python -m poison.trace

Native ETH transfers are not event logs, so the public node cannot list them. Alchemy's
`alchemy_getAssetTransfers` returns external and internal ETH transfers per address. For each target
(the top operator's gas wallet, the dust-lookalike funder) this writes:

    reports/trace_sources.csv   who sent the target ETH, with a profile of each source
    reports/trace_fanout.csv    what the funder sent out, grouped by amount

A source's profile (contract or EOA, nonce, USDC activity in the 72 h window) hints at what it is: an EOA
with a huge nonce that sends millions of USDC behaves like an exchange hot wallet. That is a hypothesis;
nothing here is an official label.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import urllib.request
from pathlib import Path

from .collect import DEFAULT_DB, connect

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "top_operator_gas_wallet": "0x3959e49639d3b1bd9d1746a7971155e94fecf1f6",
    "dust_lookalike_funder": "0x0370fc9593b1a556585d7592dd91f6bdd4b4729f",
}


def alchemy_url() -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("ALCHEMY_KEY="):
            return f"https://base-mainnet.g.alchemy.com/v2/{line.split('=', 1)[1].strip()}"
    raise SystemExit("ALCHEMY_KEY missing from .env")


class Alchemy:
    def __init__(self, url: str):
        self.url = url

    def call(self, method: str, params: list):
        req = urllib.request.Request(self.url, data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=90) as r:
            out = json.load(r)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["result"]

    def eth_transfers(self, limit: int = 20_000, **direction) -> list[dict]:
        out, page = [], None
        while True:
            p = {"category": ["external", "internal"], "order": "asc", "withMetadata": True,
                 "maxCount": "0x3e8", **direction}
            if page:
                p["pageKey"] = page
            r = self.call("alchemy_getAssetTransfers", [p])
            out += r["transfers"]
            page = r.get("pageKey")
            if not page or len(out) >= limit:
                return out

    def profile(self, a: str) -> tuple[str, int]:
        code = self.call("eth_getCode", [a, "latest"])
        return ("contract" if len(code) > 2 else "EOA"), int(self.call("eth_getTransactionCount", [a, "latest"]), 16)


def usdc_activity(con, a: str) -> tuple[int, int, float]:
    return con.execute("""
        SELECT (SELECT COUNT(*) FROM xfer x JOIN addr z ON z.id = x.f WHERE z.a = ?),
               (SELECT COUNT(*) FROM xfer x JOIN addr z ON z.id = x.t WHERE z.a = ?),
               (SELECT ROUND(COALESCE(SUM(x.v), 0) / 1e6) FROM xfer x JOIN addr z ON z.id = x.f WHERE z.a = ?)""",
                       (a, a, a)).fetchone()


def run(db: Path) -> None:
    al, con = Alchemy(alchemy_url()), connect(db)
    out = ROOT / "reports"
    with open(out / "trace_sources.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "source", "category", "transfers", "eth", "first", "last", "kind", "nonce",
                    "window_usdc_tx_out", "window_usdc_tx_in", "window_usdc_out", "example_tx"])
        for name, target in TARGETS.items():
            agg = collections.defaultdict(lambda: {"n": 0, "eth": 0.0, "first": None, "last": None, "tx": None})
            for t in al.eth_transfers(toAddress=target):
                g = agg[(t["from"], t["category"])]
                g["n"] += 1
                g["eth"] += t["value"] or 0
                g["first"] = g["first"] or t["metadata"]["blockTimestamp"]
                g["last"] = t["metadata"]["blockTimestamp"]
                g["tx"] = g["tx"] or t["hash"]
            total = sum(g["eth"] for g in agg.values())
            print(f"{name}: {sum(g['n'] for g in agg.values())} incoming ETH transfers, {total:.4f} ETH, "
                  f"{len(agg)} sources")
            for (src, cat), g in sorted(agg.items(), key=lambda kv: -kv[1]["eth"])[:15]:
                kind, nonce = al.profile(src)
                w.writerow([name, src, cat, g["n"], round(g["eth"], 6), g["first"], g["last"], kind, nonce,
                            *usdc_activity(con, src), g["tx"]])

    funder = TARGETS["dust_lookalike_funder"]
    by_amount = collections.Counter(round(t["value"] or 0, 9) for t in al.eth_transfers(fromAddress=funder))
    looks = {r[0] for r in con.execute("SELECT DISTINCT lookalike FROM poison_events")}
    eth_to = {t["to"] for t in al.eth_transfers(fromAddress=funder) if round(t["value"] or 0, 9) == 0.00014}
    usdc_to = {r[0] for r in con.execute("""SELECT DISTINCT ta.a FROM xfer x JOIN addr fa ON fa.id = x.f
                                             JOIN addr ta ON ta.id = x.t WHERE fa.a = ?""", (funder,))}
    with open(out / "trace_fanout.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["eth_amount", "transfers"])
        w.writerows(by_amount.most_common())
    print(f"funder fan-out: ETH amounts {by_amount.most_common(3)}; ETH recipients {len(eth_to)}, "
          f"USDC recipients {len(usdc_to)}, both {len(eth_to & usdc_to)}, of which lookalikes "
          f"{len(eth_to & usdc_to & looks)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    run(ap.parse_args().db)
