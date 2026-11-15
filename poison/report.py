"""Run sql/analysis.sql, save each result to reports/<name>.csv, draw the charts.

    python -m poison.report
"""
from __future__ import annotations

import argparse
import re
import sqlite3
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from .collect import DEFAULT_DB  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports"


def queries() -> dict[str, str]:
    text = (ROOT / "sql" / "analysis.sql").read_text()
    parts = re.split(r"^-- name: (\w+)\s*$", text, flags=re.M)
    return {parts[i]: parts[i + 1].strip() for i in range(1, len(parts), 2)}


def block_to_time(con) -> callable:
    bt = pd.read_sql("SELECT block, ts FROM block_time ORDER BY block", con)
    return lambda blocks: pd.to_datetime(
        pd.Series(blocks).pipe(lambda s: pd.Series(
            __import__("numpy").interp(s, bt["block"], bt["ts"]))), unit="s", utc=True)


def charts(con) -> None:
    to_time = block_to_time(con)
    ev = pd.read_sql("SELECT block, pattern FROM poison_events", con)
    allx = pd.read_sql("SELECT block FROM xfer WHERE v >= 10000 AND block % 50 = 0", con)   # 1-in-50 sample
    if ev.empty:
        return
    ev["hour"] = to_time(ev["block"]).dt.floor("h").values
    allx["hour"] = to_time(allx["block"]).dt.floor("h").values
    per_hour = ev.groupby("hour").size()
    fig, ax = plt.subplots(figsize=(10, 3.6))
    ax.plot(per_hour.index, per_hour.values, color="#b4443c", lw=1.6, label="poison events")
    ax2 = ax.twinx()
    vol = allx.groupby("hour").size() * 50
    ax2.plot(vol.index, vol.values, color="#8a8a8a", lw=1, ls="--", label="genuine USDC transfers (est.)")
    ax.set_ylabel("poison events / hour")
    ax2.set_ylabel("genuine transfers / hour")
    ax.set_title("Address poisoning on Base USDC, per hour (UTC)", loc="left")
    fig.legend(loc="upper right", frameon=False, fontsize=8)
    for a in (ax, ax2):
        a.spines["top"].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "events_per_hour.png", dpi=150)
    plt.close(fig)

    rt = pd.read_csv(OUT / "reaction_time.csv")
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    ax.barh(rt["delay"][::-1], rt["events"][::-1], color="#b4443c")
    ax.set_title("Delay between a genuine payment and the poison that imitates it", loc="left", fontsize=10)
    ax.set_xlabel("poison events")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "reaction_time.png", dpi=150)
    plt.close(fig)


def run(db: Path) -> dict[str, pd.DataFrame]:
    OUT.mkdir(exist_ok=True)
    con = sqlite3.connect(str(db))
    results = {}
    for name, sql in queries().items():
        df = pd.read_sql(sql, con)
        df.to_csv(OUT / f"{name}.csv", index=False)
        results[name] = df
        print(f"\n== {name}\n{df.head(10).to_string(index=False)}")
    charts(con)
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    run(ap.parse_args().db)
