"""Minimal JSON-RPC client for a public Base node. No API key, no account."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

BASE_RPC = "https://base-rpc.publicnode.com"
USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class RpcError(RuntimeError):
    pass


class Rpc:
    def __init__(self, url: str = BASE_RPC, timeout: float = 60):
        self.url, self.timeout = url, timeout

    def call(self, method: str, params: list, retries: int = 6):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        for attempt in range(retries):
            req = urllib.request.Request(self.url, data=body, headers={
                "Content-Type": "application/json", "User-Agent": "research-script"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    out = json.load(r)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ConnectionError) as e:
                code = getattr(e, "code", None)
                if code is not None and code not in (408, 429, 500, 502, 503, 504):
                    raise
                time.sleep(min(2 ** attempt, 30))
                continue
            if "error" in out:
                raise RpcError(str(out["error"]))
            return out["result"]
        raise RpcError(f"{method}: gave up after {retries} attempts")

    def head(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def block_time(self, n: int) -> int:
        return int(self.call("eth_getBlockByNumber", [hex(n), False])["timestamp"], 16)

    def transfer_logs(self, contract: str, lo: int, hi: int) -> list[dict]:
        return self.call("eth_getLogs", [{"address": contract, "topics": [TRANSFER_TOPIC],
                                          "fromBlock": hex(lo), "toBlock": hex(hi)}])
