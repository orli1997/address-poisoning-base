"""Detection logic on a tiny hand-built chain, where the right answer is known."""
from pathlib import Path

from poison.collect import connect
from poison.detect import detect, match_lengths

V = "0x" + "11" * 20                                       # victim
R = "0xabcd" + "0" * 32 + "9876"                           # the real counterparty
L = "0xabcd" + "f" * 32 + "9876"                           # lookalike: same first 4 and last 4
NEAR = "0xabc0" + "f" * 32 + "9876"                        # only 3 at the start: not a lookalike
OTHER = "0x" + "22" * 20


def chain(tmp_path: Path, transfers):
    con = connect(tmp_path / "t.db")
    ids = {}
    for a in {a for t in transfers for a in t[2:4]}:
        ids[a] = con.execute("INSERT INTO addr(a) VALUES (?)", (a,)).lastrowid
    con.executemany("INSERT INTO xfer VALUES (?,?,?,?,?,?)",
                    [(b, li, ids[f], ids[t], v, f"0xtx{b}") for b, li, f, t, v in transfers])
    con.commit()
    return con


def test_match_lengths():
    assert match_lengths(R, L) == (4, 4)
    assert match_lengths(R, NEAR) == (3, 4)
    assert match_lengths(R, R) == (40, 40)


def test_spoof_then_loss(tmp_path):
    con = chain(tmp_path, [
        (10, 0, V, R, 5_000_000),        # genuine: V pays R 5 USDC
        (20, 0, V, L, 0),                # attacker: 0-value transferFrom V -> L
        (25, 0, V, NEAR, 0),             # 3+4 match only: ignored
        (30, 0, V, L, 100_000_000),      # V copies L from history and pays 100 USDC
    ])
    s = detect(con, log=lambda *_: None)
    assert s["poison_events"] == 1 and s["losses"] == 1 and s["lost_usdc"] == 100
    pattern, victim, look, mimics = con.execute("SELECT pattern, victim, lookalike, mimics FROM poison_events").fetchone()
    assert (pattern, victim, look, mimics) == ("zero_value_spoof", V, L, R)


def test_dust_from_lookalike_after_receiving(tmp_path):
    con = chain(tmp_path, [(10, 0, R, V, 2_000_000), (11, 0, L, V, 1)])
    detect(con, log=lambda *_: None)
    assert con.execute("SELECT pattern, mimic_relation FROM poison_events").fetchone() == ("dust_from_lookalike", "received")


def test_lookalike_before_any_genuine_interaction_is_not_poison(tmp_path):
    con = chain(tmp_path, [(5, 0, V, L, 0), (10, 0, V, R, 5_000_000)])
    assert detect(con, log=lambda *_: None)["poison_events"] == 0


def test_paying_a_lookalike_without_poison_is_not_counted_as_loss(tmp_path):
    con = chain(tmp_path, [(10, 0, V, R, 5_000_000), (30, 0, V, L, 100_000_000), (31, 0, OTHER, V, 0)])
    s = detect(con, log=lambda *_: None)
    assert s["poison_events"] == 0 and s["losses"] == 0


def test_tiny_genuine_payments_are_not_counterparties(tmp_path):
    con = chain(tmp_path, [(10, 0, V, R, 9_999), (20, 0, V, L, 0)])     # under 0.01 USDC is not "genuine"
    assert detect(con, log=lambda *_: None)["poison_events"] == 0


def test_attacker_sending_exactly_one_cent_does_not_swap_roles(tmp_path):
    # V has a real, two-way business relationship with BIG; an attacker's lookalike sends V 0.01 USDC;
    # BIG later refunds V a few cents. The attacker must be the lookalike, BIG must never be.
    BIG = L
    ATT = R
    con = chain(tmp_path, [
        (10, 0, V, BIG, 30_000_000_000), (11, 0, BIG, V, 30_000_000_000),
        (20, 0, ATT, V, 10_000),                     # attacker: exactly 0.01 USDC
        (30, 0, BIG, V, 18_788),                     # genuine small refund from the real counterparty
        (40, 0, V, BIG, 30_000_000_000),
    ])
    s = detect(con, log=lambda *_: None)
    rows = con.execute("SELECT lookalike, mimics FROM poison_events").fetchall()
    assert rows == [(ATT, BIG)] and s["losses"] == 0


def test_lookalike_with_prior_genuine_history_is_not_poison(tmp_path):
    con = chain(tmp_path, [(10, 0, V, R, 5_000_000), (12, 0, V, L, 5_000_000), (20, 0, L, V, 1)])
    s = detect(con, log=lambda *_: None)
    assert s["poison_events"] == 0 and s["skipped_known_counterparty"] == 1
