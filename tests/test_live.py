import sqlite3

from poison.live import SCHEMA, LiveDetector, parse_logs

V = "0x" + "11" * 20
R = "0xabcd" + "00" * 16 + "1234"          # V's real counterparty
L = "0xabcd" + "ff" * 16 + "1234"          # lookalike: same first 4 and last 4 hex chars
USDC = 1_000_000


def detector():
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    alerts = []
    return LiveDetector(con, emit=alerts.append, now=lambda: 0), alerts


def test_poison_then_loss():
    det, alerts = detector()
    det.process([(1, 0, V, R, 50 * USDC, "0xa"),
                 (2, 0, V, L, 0, "0xb"),             # zero-value spoof
                 (3, 0, V, L, 0, "0xc"),             # repeat: counted, no second alert
                 (4, 0, V, L, 298 * USDC, "0xd")])   # victim copies the fake address
    assert [a["kind"] for a in alerts] == ["poison", "loss"]
    assert alerts[0]["pattern"] == "zero_value_spoof" and alerts[0]["mimics"] == R
    assert alerts[1]["usdc"] == 298
    assert det.con.execute("SELECT events FROM pairs").fetchone()[0] == 2


def test_same_block_relationship_does_not_count():
    det, alerts = detector()
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (1, 1, L, V, 1000, "0xb")])
    assert alerts == []


def test_known_counterparty_is_not_a_stranger():
    det, alerts = detector()
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 5 * USDC, "0xb"), (3, 0, L, V, 0, "0xc")])
    assert alerts == []


def test_incoming_dust_and_non_lookalike():
    det, alerts = detector()
    other = "0xabcd" + "ff" * 16 + "9999"          # prefix matches, suffix does not
    det.process([(1, 0, R, V, 50 * USDC, "0xa"), (2, 0, other, V, 1000, "0xb"), (3, 0, L, V, 1000, "0xc")])
    assert len(alerts) == 1 and alerts[0]["pattern"] == "dust_from_lookalike"


def test_parse_logs_orders_and_skips():
    lg = lambda b, i, v: {"blockNumber": hex(b), "logIndex": hex(i), "transactionHash": "0x1", "data": hex(v),
                          "topics": ["0xddf", "0x" + "0" * 24 + V[2:], "0x" + "0" * 24 + R[2:]]}
    bad = dict(lg(1, 0, 1), topics=["0xddf"])
    rows = parse_logs([lg(2, 0, 5), lg(1, 3, 7), bad, dict(lg(3, 0, 1), removed=True)])
    assert [(r[0], r[1], r[4]) for r in rows] == [(1, 3, 7), (2, 0, 5)]
    assert rows[0][2] == V and rows[0][3] == R
