"""How often is the detector wrong? Three checks on the 72 h research window.

    python -m poison.evaluate          # writes reports/evaluation.json and reports/evaluation_review.csv

There is no labelled list of poisoners, so precision is bounded from three sides:

  1. chance       how many lookalike matches pure chance would produce (1 in 16^8 per counterparty checked)
  2. behaviour    a poisoner's lookalike exists to be copied: it should not do real business. A flagged lookalike
                  with >= 1 USDC of activity (other than receiving a victim's loss) is a possible false positive
     control: the same test on 1,000 imitated (real) addresses must find activity in nearly all of them
  3. vanity       low-entropy addresses (0x0000…0000) can match each other without any attack; counted separately

The review file lists every flagged lookalike with real activity, busiest first, for a manual check.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .collect import DEFAULT_DB, connect
from .detect import CANDIDATE_UNITS, GENUINE_UNITS

ROOT = Path(__file__).resolve().parents[1]


def low_entropy(a: str) -> bool:
    """First 4 or last 4 hex chars are one repeated character (vanity / precompile-style addresses)."""
    h = a[2:]
    return len(set(h[:4])) == 1 or len(set(h[-4:])) == 1


def chance_matches(con) -> float:
    """Expected matches by chance: every candidate checks each side's counterparties (upper bound: whole window)."""
    con.execute("""CREATE TEMP TABLE IF NOT EXISTS ncp AS
                   SELECT a, COUNT(DISTINCT o) n FROM (
                       SELECT f a, t o FROM xfer WHERE v >= ? UNION ALL SELECT t, f FROM xfer WHERE v >= ?)
                   GROUP BY a""", (GENUINE_UNITS, GENUINE_UNITS))
    con.execute("CREATE INDEX IF NOT EXISTS temp.ncp_a ON ncp(a)")
    checks = con.execute("""SELECT COALESCE(SUM(COALESCE(nf.n, 0) + COALESCE(nt.n, 0)), 0) FROM xfer x
                            LEFT JOIN ncp nf ON nf.a = x.f LEFT JOIN ncp nt ON nt.a = x.t
                            WHERE x.v < ?""", (CANDIDATE_UNITS,)).fetchone()[0]
    return checks / 16 ** 8


def evaluate(con) -> dict:
    ids = {a: i for i, a in con.execute("SELECT id, a FROM addr")}
    pairs = con.execute("""SELECT lookalike, COUNT(DISTINCT victim), MIN(mimics) FROM poison_events
                           GROUP BY lookalike""").fetchall()
    loss_tx = {(ids[v], ids[l]) for v, l in con.execute("SELECT victim, lookalike FROM losses")}
    review, by_victims = [], Counter()
    for look, n_victims, mimics in pairs:
        li = ids[look]
        rows = con.execute("""SELECT f, t, v FROM xfer WHERE f = ? AND v >= ?
                              UNION ALL SELECT f, t, v FROM xfer WHERE t = ? AND v >= ?""",
                           (li, GENUINE_UNITS, li, GENUINE_UNITS)).fetchall()
        rows = [r for r in rows if (r[0], r[1]) not in loss_tx]
        by_victims["1 victim" if n_victims == 1 else "2-9 victims" if n_victims < 10 else "10+ victims"] += 1
        if rows:
            review.append({"lookalike": look, "mimics": mimics, "victims": n_victims,
                           "genuine_transfers": len(rows),
                           "counterparties": len({r[0] for r in rows} | {r[1] for r in rows}) - 1,
                           "usdc": round(sum(r[2] for r in rows) / 1e6, 2),
                           "low_entropy": low_entropy(look)})
    events = con.execute("SELECT COUNT(*) FROM poison_events").fetchone()[0]
    vanity_events = sum(1 for (lk, mm) in con.execute("SELECT lookalike, mimics FROM poison_events")
                        if low_entropy(lk) and low_entropy(mm))
    flagged_active_events = 0
    active = {r["lookalike"] for r in review}
    for (lk,) in con.execute("SELECT lookalike FROM poison_events"):
        flagged_active_events += lk in active
    # control: the same activity test on the real addresses being imitated must find activity, or it is broken
    sample = [r[0] for r in con.execute("SELECT DISTINCT mimics FROM poison_events ORDER BY mimics LIMIT 1000")]
    control_active = sum(1 for m in sample if con.execute(
        "SELECT 1 FROM xfer WHERE f = ? AND v >= ? UNION ALL SELECT 1 FROM xfer WHERE t = ? AND v >= ? LIMIT 1",
        (ids[m], GENUINE_UNITS, ids[m], GENUINE_UNITS)).fetchone())
    n = len(pairs)
    result = {
        "control_imitated_sampled": len(sample), "control_imitated_with_real_activity": control_active,
        "lookalikes": n, "poison_events": events,
        "chance_matches_expected": round(chance_matches(con), 3),
        "lookalikes_by_victims": dict(by_victims),
        "lookalikes_with_real_activity": len(review),
        "events_from_active_lookalikes": flagged_active_events,
        "events_between_vanity_addresses": vanity_events,
        "precision_lower_bound_events": round(1 - (flagged_active_events + vanity_events) / events, 4),
        "precision_lower_bound_lookalikes": round(1 - len(review) / n, 4),
    }
    review.sort(key=lambda r: -r["genuine_transfers"])
    with open(ROOT / "reports" / "evaluation_review.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(review[0]) if review else ["lookalike"])
        w.writeheader()
        w.writerows(review)
    (ROOT / "reports" / "evaluation.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    evaluate(connect(ap.parse_args().db))
