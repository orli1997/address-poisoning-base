"""Telegram alert bot: tells a user, within seconds, when their wallet is poisoned or pays a lookalike.

    python -m poison.live        # the detector (one terminal)
    python -m poison.bot         # the bot (another terminal); needs TELEGRAM_BOT_TOKEN=... in .env

Commands a user can send the bot:
    /watch 0x...     get alerts for an address, plus what the detector already knows about it
    /unwatch 0x...   stop
    /list            watched addresses
    /check 0x...     before sending: is this address a known lookalike?

Privacy: the bot stores only (Telegram chat id, watched address) in the local live DB, and sends an alert
only to the chat that watches that address. No public list of victims.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path

from .live import LIVE_DB, connect_live

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
MAX_WATCH = 10
SCAN = "https://basescan.org"

SCHEMA = """
CREATE TABLE IF NOT EXISTS subs (chat_id INTEGER, address TEXT, since INTEGER, PRIMARY KEY (chat_id, address));
CREATE INDEX IF NOT EXISTS subs_address ON subs(address);
CREATE TABLE IF NOT EXISTS notified (chat_id INTEGER, kind TEXT, ref TEXT, PRIMARY KEY (chat_id, kind, ref));
CREATE INDEX IF NOT EXISTS loss_victim ON loss_alerts(victim);
"""

HELP = """<b>Address-poisoning alerts for USDC on Base</b>

Scammers send tiny or zero-value transfers from addresses that look like ones you have paid before, hoping you copy the fake one from your history.

/watch <code>0x…</code> alert me when this address is poisoned
/unwatch <code>0x…</code> stop alerts
/list my watched addresses
/check <code>0x…</code> is this address a known lookalike? (use before sending)

Always compare the <b>whole</b> address before you send, not just the start and end."""


def token() -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("TELEGRAM_BOT_TOKEN="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("TELEGRAM_BOT_TOKEN missing from .env")


class TelegramError(RuntimeError):
    def __init__(self, code: int, text: str):
        super().__init__(f"{code}: {text}")
        self.code = code


def telegram_api(tok: str):
    def call(method: str, params: dict, timeout: float = 30):
        req = urllib.request.Request(f"https://api.telegram.org/bot{tok}/{method}",
                                     data=json.dumps(params).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)["result"]
        except urllib.error.HTTPError as e:      # never echo the URL: it contains the token
            raise TelegramError(e.code, json.load(e).get("description", "")) from None
    return call


def link(kind: str, value: str, text: str | None = None) -> str:
    return f'<a href="{SCAN}/{kind}/{value}">{text or value[:10] + "…"}</a>'


def poison_text(victim, lookalike, mimics, pattern, tx) -> str:
    how = {"zero_value_spoof": "a fake 0 USDC payment <b>from you</b> to it",
           "zero_value_incoming": "a 0 USDC transfer to you",
           "dust_from_lookalike": "a tiny USDC amount sent to you",
           "dust_to_lookalike": "a tiny USDC amount from you"}.get(pattern, "a tiny transfer")
    return (f"⚠️ <b>Address poisoning on your wallet</b>\n<code>{victim}</code>\n\n"
            f"A lookalike address was planted in your history with {how} ({link('tx', tx, 'transaction')}).\n\n"
            f"Real address you used:\n<code>{mimics}</code>\n"
            f"Fake lookalike — <b>never send to it</b>:\n<code>{lookalike}</code>\n\n"
            "Don't copy addresses from your transaction history. Compare the whole address.")


def loss_text(victim, lookalike, mimics, usdc, tx) -> str:
    return (f"🚨 <b>{usdc:,.2f} USDC was sent to a lookalike</b>\nfrom <code>{victim}</code>\n\n"
            f"Sent to the fake:\n<code>{lookalike}</code>\nwhich imitates:\n<code>{mimics}</code>\n"
            f"{link('tx', tx, 'transaction')}\n\n"
            "If this was you: stop further payments to that address. Contact your wallet or exchange and "
            "report the transaction; keep the transaction hash.")


class Bot:
    def __init__(self, con: sqlite3.Connection, api, now=time.time):
        self.con, self.api, self.now = con, api, now
        con.executescript(SCHEMA)

    def send(self, chat_id: int, text: str) -> bool:
        try:
            self.api("sendMessage", {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                                     "disable_web_page_preview": True})
            return True
        except TelegramError as e:
            if e.code == 403:                    # the user blocked the bot: forget them
                self.con.execute("DELETE FROM subs WHERE chat_id = ?", (chat_id,))
                self.con.commit()
                return False
            raise

    # commands --------------------------------------------------------------------------------------------------
    def handle(self, chat_id: int, text: str) -> None:
        parts = text.strip().split()
        cmd = parts[0].split("@")[0].lower() if parts else ""
        arg = parts[1] if len(parts) > 1 else ""
        if cmd in ("/watch", "/unwatch", "/check") and not ADDRESS.match(arg):
            self.send(chat_id, f"Send it like this: <code>{cmd} 0x…</code> (a full 42-character address)")
            return
        arg = arg.lower()
        if cmd == "/watch":
            self.watch(chat_id, arg)
        elif cmd == "/unwatch":
            n = self.con.execute("DELETE FROM subs WHERE chat_id = ? AND address = ?", (chat_id, arg)).rowcount
            self.con.commit()
            self.send(chat_id, "Stopped." if n else "That address wasn't on your list.")
        elif cmd == "/list":
            rows = [r[0] for r in self.con.execute("SELECT address FROM subs WHERE chat_id = ? ORDER BY since",
                                                   (chat_id,))]
            self.send(chat_id, "\n".join(f"<code>{a}</code>" for a in rows) or "You aren't watching any address.")
        elif cmd == "/check":
            self.check(chat_id, arg)
        else:
            self.send(chat_id, HELP)

    def watch(self, chat_id: int, a: str) -> None:
        n = self.con.execute("SELECT COUNT(*) FROM subs WHERE chat_id = ?", (chat_id,)).fetchone()[0]
        if n >= MAX_WATCH:
            self.send(chat_id, f"You can watch up to {MAX_WATCH} addresses.")
            return
        self.con.execute("INSERT OR IGNORE INTO subs VALUES (?, ?, ?)", (chat_id, a, int(self.now())))
        # everything already known counts as sent, so the alert loop only reports what happens from now on
        self.con.execute("""INSERT OR IGNORE INTO notified SELECT ?, 'poison', lookalike FROM pairs
                            WHERE victim = ?""", (chat_id, a))
        self.con.execute("""INSERT OR IGNORE INTO notified SELECT ?, 'loss', block || ':' || li FROM loss_alerts
                            WHERE victim = ?""", (chat_id, a))
        self.con.commit()
        past = self.con.execute("""SELECT lookalike, mimics FROM pairs WHERE victim = ?
                                   ORDER BY first_block DESC LIMIT 5""", (a,)).fetchall()
        total = self.con.execute("SELECT COUNT(*) FROM pairs WHERE victim = ?", (a,)).fetchone()[0]
        msg = f"✅ Watching <code>{a}</code>. You'll get an alert within seconds of any poisoning."
        if past:
            msg += (f"\n\n⚠️ Already seen: <b>{total}</b> lookalike address(es) planted in this wallet's history. "
                    "Never send to these:\n" + "\n".join(f"<code>{lk}</code>\n  imitates <code>{real}</code>"
                                                         for lk, real in past))
        self.send(chat_id, msg)

    def check(self, chat_id: int, a: str) -> None:
        r = self.con.execute("""SELECT COUNT(*), COUNT(DISTINCT mimics), MIN(mimics) FROM pairs
                                WHERE lookalike = ?""", (a,)).fetchone()
        if r[0]:
            self.send(chat_id, f"🚨 <b>Known lookalike.</b> <code>{a}</code> was used to poison <b>{r[0]}</b> "
                               f"wallet(s), imitating {r[1]} real address(es), e.g.\n<code>{r[2]}</code>\n\n"
                               "Do not send to it.")
        else:
            self.send(chat_id, f"Not seen as a lookalike since the detector started.\n<code>{a}</code>\n\n"
                               "That is not proof it is safe: compare the whole address with the one "
                               "you got from the recipient directly.")

    # alerts ----------------------------------------------------------------------------------------------------
    def pending(self):
        for chat, victim, look, mimics, pattern, tx in self.con.execute("""
                SELECT s.chat_id, p.victim, p.lookalike, p.mimics, p.pattern, p.first_tx
                FROM subs s JOIN pairs p ON p.victim = s.address
                WHERE p.detected_at >= s.since AND NOT EXISTS (SELECT 1 FROM notified n WHERE n.chat_id = s.chat_id AND n.kind = 'poison'
                                  AND n.ref = p.lookalike)""").fetchall():
            yield chat, "poison", look, poison_text(victim, look, mimics, pattern, tx)
        for chat, victim, look, mimics, block, li, tx, units in self.con.execute("""
                SELECT s.chat_id, l.victim, l.lookalike, l.mimics, l.block, l.li, l.tx, l.amount_units
                FROM subs s JOIN loss_alerts l ON l.victim = s.address
                WHERE l.detected_at >= s.since AND NOT EXISTS (SELECT 1 FROM notified n WHERE n.chat_id = s.chat_id AND n.kind = 'loss'
                                  AND n.ref = l.block || ':' || l.li)""").fetchall():
            yield chat, "loss", f"{block}:{li}", loss_text(victim, look, mimics, units / 1e6, tx)

    def notify(self) -> int:
        sent = 0
        for chat, kind, ref, text in list(self.pending()):
            if self.send(chat, text):
                sent += 1
            self.con.execute("INSERT OR IGNORE INTO notified VALUES (?, ?, ?)", (chat, kind, ref))
            self.con.commit()
        return sent

    def run(self, poll: float = 1.0) -> None:
        offset = None
        me = self.api("getMe", {})["username"]
        print(f"# @{me} running; Ctrl+C to stop", flush=True)
        while True:
            try:
                params = {"timeout": int(poll), "allowed_updates": ["message"]}
                if offset is not None:
                    params["offset"] = offset
                for u in self.api("getUpdates", params, timeout=poll + 30):
                    offset = u["update_id"] + 1
                    m = u.get("message") or {}
                    if m.get("text") and m.get("chat", {}).get("type") == "private":
                        self.handle(m["chat"]["id"], m["text"])
                n = self.notify()
                if n:
                    print(f"# sent {n} alert(s)", flush=True)
            except (TelegramError, urllib.error.URLError, TimeoutError, ConnectionError) as e:
                print(f"# telegram error, retrying: {e}", flush=True)
                time.sleep(5)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=LIVE_DB)
    a = ap.parse_args()
    try:
        Bot(connect_live(a.db), telegram_api(token())).run()
    except KeyboardInterrupt:
        pass
