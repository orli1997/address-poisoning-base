import sqlite3

from poison.live import SCHEMA, LiveDetector
from poison.web import check, stats

V = "0x" + "11" * 20
W = "0x" + "22" * 20
R = "0xabcd" + "00" * 16 + "1234"
L = "0xabcd" + "ff" * 16 + "1234"
L2 = "0xabcd" + "ee" * 16 + "1234"          # imitates R but never used in an attack
STRANGER = "0x" + "33" * 20
USDC = 1_000_000


def db():
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    LiveDetector(con, now=lambda: 1000).process([
        (1, 0, V, R, 50 * USDC, "0xa"), (1, 1, W, R, 5 * USDC, "0xb"), (2, 0, V, L, 0, "0xc")])
    return con


def test_known_lookalike_is_danger_for_anyone():
    r = check(db(), L)
    assert r["verdict"] == "danger" and r["known_lookalike"]["victims"] == 1 and r["known_lookalike"]["mimics"] == [R]


def test_planted_in_own_history():
    r = check(db(), L, V)
    assert r["verdict"] == "danger" and r["planted_in_your_history"]["mimics"] == R


def test_new_lookalike_of_my_counterparty_is_warning():
    r = check(db(), L2, W)
    assert r["verdict"] == "warning" and r["imitates_your_counterparty"]["real"] == R


def test_real_counterparty_is_known_and_stranger_unknown():
    assert check(db(), R, V)["verdict"] == "known"
    assert check(db(), STRANGER, V)["verdict"] == "unknown"
    assert check(db(), STRANGER)["verdict"] == "unknown"


def test_stats_counts_live_pairs_only():
    con = db()
    con.execute("INSERT INTO pairs VALUES (?,?,?,4,4,'zero_value_spoof',0,'0x',0,1,NULL)", (W, L2, R))
    s = stats(con, now=1500)
    assert s["live"]["pairs"] == 1 and s["known_pairs_total"] == 2
    assert s["top_lookalikes"][0]["address"] == L and sum(b["pairs"] for b in s["series"]) == 1
