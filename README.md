# Address poisoning on Base USDC: a 72-hour on-chain investigation

**English** | [עברית](README.he.md)

**Window:** Base mainnet blocks 56,511,333 to 57,807,333, 2026-11-12 14:10 to 2026-11-15 14:10 UTC.
**Data:** every USDC `Transfer` log in the window, 11,670,478 transfers, pulled from a public RPC. No third-party labels were used.

## Summary

| | |
|---|---|
| Poison events detected | **327,930** |
| Victims targeted | **178,360** addresses |
| Lookalike addresses used | **80,646** |
| Poisoning transactions | 35,153 |
| Share from one operator | **84.4%** of events, through one batch contract |
| Confirmed USDC lost inside the window | **1 payment, 298 USDC** (verified on-chain) |
| New losses in the ~20 h after the window | **0** |

Address poisoning is industrial on Base. One operator sent most of it.

The attack is cheap and runs almost all the time: about 4,500 poison events per hour. Very few victims fell for it during these three days. Losses usually come later than poisoning, so this window gives a lower bound on losses, not an estimate of them.

## How the attack works

1. A victim pays a real counterparty `R`.
2. The attacker generates an address `L` whose first 4 and last 4 hex characters match `R`. The odds of that happening by chance are 1 in 16⁸ per pair.
3. The attacker makes `L` show up in the victim's history, in one of two ways:
   - **zero-value spoof**: a `transferFrom(victim → L, 0)`. An amount of 0 needs no allowance, so anyone can emit it, and the victim appears to have *sent* to `L`.
   - **dust from lookalike**: `L` sends the victim a tiny real amount.
4. Next time, the victim copies the "recent" address from a wallet or explorer and pays `L`.

## Findings

### 1. One operator runs most of the poisoning

| Gas-paying sender | Contract called | Txs | Events | Share | Victims |
|---|---|---|---|---|---|
| `0x3959e496…f1f6` | `0xc3236716…5032` (selector `0x12514bba`) | 8,054 | 276,623 | **84.4%** | 176,040 |
| `0xdf97d92d…b89d` | `0xf39fdf81…2797` | 2,355 | 14,594 | 4.5% | 6,218 |
| `0x6f92c759…3187` | `0x75161fd5…eb96` | 1,210 | 7,681 | 2.3% | 3,038 |
| `0x13203ab0…8931` | `0x6c05874f…0f61` | 1,249 | 4,940 | 1.5% | 3,004 |

- **One EOA, one batch contract.** The top operator calls a single batch contract from a single EOA. That contract emits about 34 zero-value spoofs per transaction.
- **Scale of the top operator.** It used 72,179 distinct lookalike addresses.
- **The second tier.** The next four operators each use their own batch contract.
- **Direct dust senders.** Another 522 wallets call USDC directly. These are lookalikes sending dust themselves.
- **Full list.** See [reports/operators.csv](reports/operators.csv) and [reports/contracts.csv](reports/contracts.csv).

### 2. Zero-value spoofs dominate

| Pattern | Events | Victims |
|---|---|---|
| zero_value_spoof | 279,484 (85.2%) | 176,094 |
| dust_from_lookalike | 48,445 (14.8%) | 21,332 |

Zero-value spoofs cost the attacker only gas, and Base gas is cheap.

### 3. Poison arrives within minutes of the real payment

![reaction time](reports/reaction_time.png)

| Delay after the genuine transfer | Events |
|---|---|
| 0–30 s | 3,402 |
| 30–60 s | 16,252 |
| 1–2 min | 128,226 |
| 2–10 min | 127,445 |
| 10–60 min | 33,209 |
| > 1 h | 19,396 |

- **Most poison comes within 10 minutes.** 78% of events arrive 1–10 minutes after the victim's genuine transfer.
- **The attack is automated.** Operators watch the mempool or new blocks and react within the same session the victim is active in.

### 4. Popular addresses are imitated at scale

- **One lookalike, 55,547 victims.** `0x786aedd0…2fa8` imitates `0x786abf52…2fa8` and was used against 55,547 different victims in 72 hours.
- **The target is a hub.** The real address is clearly a high-traffic hub, and the attacker poisons everyone who pays it.
- **Funding pattern.** One funder, `0x0370fc95…729f`, sent USDC to 194 of the dust-sending lookalikes. That is a funding pattern worth tracing further.

### 5. Match quality

| Prefix + suffix match | Events |
|---|---|
| 4 + 4 | 289,544 (88.3%) |
| 4 + 5 / 5 + 4 | 33,074 |
| 6 or more on either side | about 4,000 |

- **Attackers do the minimum.** Nearly everything is a 4 + 4 match, which is exactly what most wallet UIs show (`0xabcd…9876`).
- **Chance matches are negligible.** About 1.0 coincidental match is expected among all candidates in the window, against 327,930 detected events.

### 6. The confirmed loss

- **Who:** victim `0x34a08f7c…8bd5`.
- **The payment:** 298 USDC to lookalike `0x0742fdb7…d158` in tx [`0x732fdc7b…7434`](https://basescan.org/tx/0x732fdc7b313a0bacc29b63ec8a68bd2105d5bfdc1d45b2fbd7fa9d4ff2c77434). The receipt has status 1, and the victim signed the transfer directly.

Timeline (Base blocks):

| Block | Event |
|---|---|
| 57,515,112 | Victim receives 307 USDC from `0x4c2c0f0b…` (a recurring payer) |
| 57,522,021 | Victim pays the real address `0x07423f37…d158` **977 USDC** |
| 57,522,539 | **Poison:** zero-value spoof victim → `0x0742fdb7…d158`, sent by the top operator (about 1.7 min later) |
| 57,530,349 | Second spoof, same lookalike, same operator |
| 57,568,193 | Victim receives 298 USDC from the same recurring payer |
| 57,583,093 | **Victim pays 298 USDC to the lookalike** (about 3.4 h after the first poison) |

- **Clean pattern.** It is a textbook case: the victim forwards incoming funds to the same destination each time, and the one time they copied from history, they copied the fake.
- **The poison passes on.** Within the window, the real recipient `0x07423f37…` forwards the money and is then poisoned in turn by `0x6fa54e03…`, a lookalike of its own counterparty.

## Following the money (after the window)

### 7. Follow-up: about 20 more hours, no new losses

[`followup.py`](poison/followup.py) asked the node for every USDC transfer **into** any of the 80,646 lookalikes from the end of the window (block 57,807,334) to block 58,167,968 (16 Nov 2026, 10:12 UTC), about 20 hours. It queries 2,000 addresses per call and is resumable, so the follow-up can be extended later.

| Transfers into lookalikes | Count |
|---|---|
| Total | 28,939 |
| Zero-value spoofs (lookalikes reused) | 28,416 |
| Dust (above 0, under 1 USDC) | 523 |
| **Payments of 1 USDC or more (new losses)** | **0** |

- **Checked against the known loss.** Run over the block of the 298 USDC loss, the same scanner finds it, so the zero reflects the data and not a broken query.
- **Still a lower bound.** Twenty hours is short. The script can be rerun to extend the follow-up period.

### 8. The main operator went quiet

- **Last transaction.** The top operator's gas wallet `0x3959e496…f1f6` sent 1,883 more transactions after the window. Its last one was [`0xbc235803…9d81`](https://basescan.org/tx/0xbc235803690def39f18488fd60cb59ce49e5b926f593d915158b338e78529d81) in block 58,022,783 (16 Nov 2026, 02:08 UTC): one batch of 300 spoofs for a fee of 0.0000189 ETH. Its nonce has not moved since (366,591).
- **Not just one wallet.** In 1,000-block samples, zero-value USDC transfers across all of Base fell from 100 (block 57.9M) to 7–26 (blocks 58.0M–58.16M), and only 0–7 of those went into known lookalikes. The campaign as a whole paused.
- **Probably not out of gas.** The wallet still holds 0.0000429 ETH, enough for about two more batches at the last fee. Why it stopped is unknown (hypothesis: a pause or a move to new infrastructure).
- **Cost.** About 63 nano-ETH (0.000000063 ETH) per spoof at that fee. Poisoning tens of thousands of wallets an hour costs very little on Base.

### 9. The stolen 298 USDC has not moved

- **Still in place.** As of 16 Nov 2026 the lookalike `0x0742fdb7…d158` still holds the 298 USDC.
- **Never active.** It has never sent a transaction (nonce 0) and has no code.
- **What it suggests.** Attackers leave the stolen funds in place for now (hypothesis: they collect from many lookalikes later).

### 10. How dust-sending lookalikes are funded

1. **ETH in.** `0x0370fc95…729f` swapped **0.0364 ETH for 69.886 USDC** through a DEX router (`0x0729e2a4…97f7`, via the WETH/USDC pool) in [`0x34d867bf…270e`](https://basescan.org/tx/0x34d867bf87583fc1c3425bb3ce4f8d0e2fbd53a83224f8ef5af10e64a326270e).
2. **Fan-out.** It then sent **exactly 0.122 USDC to 567 addresses**, between blocks 57,085,898 and 57,100,363. No other address in the window sent that amount more than 20 times, so the amount works as a fingerprint.
3. **Use.** 194 of those addresses appear as lookalikes in this data. They sent 19,931 dust transfers to 9,687 victims, each lookalike paying its own gas.

The wallet's nonce (1,135) is consistent with one swap, 567 USDC fan-out transfers and 567 more transactions (hypothesis: ETH for each lookalike's gas, which logs cannot show).

> **First reading corrected.** The router sends tens of millions of USDC to thousands of addresses, and at first it looked like the funder had *withdrawn* from a service. The transaction itself showed the funder sent the ETH and swapped it. A router is not a custodian, so there is no account behind it to identify.

**Still open: where the ETH comes from.** Both the operator and the funder are financed in native ETH. Native ETH transfers do not appear in event logs. Tracing them needs an indexer: an explorer API, or an API such as Alchemy's `getAssetTransfers`.

## Method

Code is in [poison/](poison/), queries in [sql/analysis.sql](sql/analysis.sql), and tests in [tests/](tests/).

1. **Collect.** [`collect.py`](poison/collect.py) runs `eth_getLogs` over the USDC contract and stores the logs in SQLite. It interns addresses, uses an adaptive block step (to stay under the RPC's 20,000-result cap), and can resume.
2. **Detect.** In [`detect.py`](poison/detect.py), a *candidate* is a transfer under 0.1 USDC. A candidate becomes a poison event when:
   - one side is the victim, and the other side `L` matches ≥ 4 leading and ≥ 4 trailing hex characters of a **genuine counterparty** `R` of the victim;
   - "genuine" means a transfer of at least 1 USDC, in either direction, **before** the candidate;
   - `L` itself is **not** a genuine counterparty of the victim before the event (the stranger rule).
3. **Losses.** A loss is a victim → `L` transfer of at least 1 USDC **after** that victim's first poison event from `L`.
4. **Attribution.** [`campaigns.py`](poison/campaigns.py) fetches each poisoning transaction with `eth_getTransactionByHash` to get the gas payer and the contract called, which a `Transfer` log does not show. It also lists who funded dust-sending lookalikes.
5. **Report.** [`report.py`](poison/report.py) runs the named queries into [reports/](reports/) and draws the charts.

### A false positive caught during the analysis

- **The bad number.** The first run reported a single "loss" of **$15.88M**.
- **What actually happened.** Manual review showed a role reversal:
  - an attacker's lookalike had sent the victim *exactly* 0.01 USDC;
  - the old threshold counted 0.01 USDC as "genuine", so the attacker became the "real counterparty";
  - the victim's real, long-running business partner was labelled the "lookalike";
  - the partner's normal payments were then counted as losses.
- **The fixes:**
  - raised the genuine threshold to 1 USDC;
  - lowered the candidate threshold to under 0.1 USDC;
  - added the stranger rule;
  - added a "lookalike paid the victim back" column, so every loss gets a manual check.
- **Tests.** Regression tests for both cases are in [tests/test_detect.py](tests/test_detect.py).
- **What the correction did.** The headline loss number fell from $15.88M to $298. The detection counts barely moved (328,153 events before, 327,930 after).

## Limitations

- **The loss figure is a lower bound.** Victims often pay a lookalike days or weeks after being poisoned. A 72-hour window catches only losses that happen inside it, and poison sent near the end has had almost no time to work.
- **USDC on Base only.** A victim poisoned here may lose ETH or other tokens, and those losses are not counted.
- **Some detection gaps:**
  - Transaction hashes are stored only for transfers under 0.01 USDC, so attribution misses dust between 0.01 and 0.1 USDC (71 events have no hash).
  - Approximate (similar-looking, non-exact) lookalikes are not detected.
- **Genuine history starts at the window.** A counterparty from before the window is invisible. The stranger rule therefore misses lookalikes that were paid before the window, and some poisoning of older relationships is missed.
- **The edges of the window are partial.** The first and last hours in the hourly chart are incomplete.
- **Snapshot of a public RPC.** Results reflect the logs the RPC returned at collection time.

![events per hour](reports/events_per_hour.png)

## Reproduce

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
python -m poison.collect --hours 72      # writes ~/poisoning_data/base_usdc.db (about 1 GB, not in git)
python -m poison.detect
python -m poison.campaigns
python -m poison.report
python -m poison.followup     # payments into lookalikes after the window; rerun to extend
python -m pytest
```
