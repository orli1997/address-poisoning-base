import sqlite3

from poison.bot import Bot, TelegramError
from poison.live import SCHEMA, LiveDetector

V = "0x" + "11" * 20
R = "0xabcd" + "00" * 16 + "1234"
L = "0xabcd" + "ff" * 16 + "1234"
USDC = 1_000_000


def setup():
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    sent = []

    def api(method, params, timeout=30):
        if params.get("chat_id") == 403:
            raise TelegramError(403, "blocked")
        sent.append((params["chat_id"], params["text"]))
    return con, LiveDetector(con, now=lambda: 0), Bot(con, api, now=lambda: 0), sent


def test_watch_then_alert_once():
    con, det, bot, sent = setup()
    bot.handle(7, f"/watch {V.upper().replace('0X', '0x')}")       # mixed case is accepted
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 0, "0xb"), (3, 0, V, L, 0, "0xc")])
    assert bot.notify() == 1 and bot.notify() == 0
    assert L in sent[-1][1] and R in sent[-1][1] and "Address poisoning" in sent[-1][1]
    det.process([(4, 0, V, L, 298 * USDC, "0xd")])
    assert bot.notify() == 1 and "298.00 USDC" in sent[-1][1]


def test_watch_reports_history_without_realerting():
    con, det, bot, sent = setup()
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 0, "0xb")])
    bot.handle(7, f"/watch {V}")
    assert "Already seen: <b>1</b>" in sent[-1][1] and L in sent[-1][1]
    assert bot.notify() == 0


def test_only_the_watching_chat_gets_it():
    con, det, bot, sent = setup()
    bot.handle(7, f"/watch {R}")
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 0, "0xb")])
    assert bot.notify() == 0


def test_check_and_bad_input():
    con, det, bot, sent = setup()
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 0, "0xb")])
    bot.handle(7, f"/check {L}")
    assert "Known lookalike" in sent[-1][1]
    bot.handle(7, f"/check {R}")
    assert "Not seen" in sent[-1][1]
    bot.handle(7, "/watch 0x123")
    assert "42-character" in sent[-1][1]


def test_blocked_user_is_forgotten():
    con, det, bot, sent = setup()
    con.execute("INSERT INTO subs VALUES (403, ?, 0)", (V,))
    det.process([(1, 0, V, R, 50 * USDC, "0xa"), (2, 0, V, L, 0, "0xb")])
    bot.notify()
    assert con.execute("SELECT COUNT(*) FROM subs").fetchone()[0] == 0
