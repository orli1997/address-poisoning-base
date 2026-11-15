-- Named queries; report.py runs each one and saves it to reports/<name>.csv.
-- Seconds are approximated from block distance (Base: one block every ~0.2 s; checked against block_time).

-- name: overview
SELECT
  (SELECT COUNT(*) FROM xfer)                                   AS usdc_transfers,
  (SELECT COUNT(*) FROM xfer WHERE v < 10000)                   AS transfers_under_1_cent,
  (SELECT COUNT(*) FROM poison_events)                          AS poison_events,
  (SELECT COUNT(DISTINCT victim) FROM poison_events)            AS victims,
  (SELECT COUNT(DISTINCT lookalike) FROM poison_events)         AS lookalike_addresses,
  (SELECT COUNT(DISTINCT tx) FROM poison_events)                AS poisoning_txs,
  (SELECT COUNT(DISTINCT sender) FROM tx_meta)                  AS operator_wallets,
  (SELECT COUNT(*) FROM losses)                                 AS loss_payments,
  (SELECT COUNT(DISTINCT victim) FROM losses)                   AS victims_who_paid,
  (SELECT ROUND(COALESCE(SUM(amount_units), 0) / 1e6, 2) FROM losses) AS usdc_lost;

-- name: by_pattern
SELECT pattern, COUNT(*) AS events, COUNT(DISTINCT victim) AS victims, COUNT(DISTINCT lookalike) AS lookalikes
FROM poison_events GROUP BY pattern ORDER BY events DESC;

-- name: operators
-- One row per (gas-paying sender, contract called). Share of all looked-up poisoning txs.
SELECT m.sender, m.to_contract, m.selector,
       COUNT(*) AS txs, SUM(m.n_logs_poison) AS events,
       ROUND(100.0 * SUM(m.n_logs_poison) / (SELECT SUM(n_logs_poison) FROM tx_meta), 1) AS pct_of_events,
       (SELECT COUNT(DISTINCT e.victim) FROM poison_events e JOIN tx_meta m2 ON m2.tx = e.tx
         WHERE m2.sender = m.sender AND m2.to_contract = m.to_contract) AS victims
FROM tx_meta m GROUP BY m.sender, m.to_contract, m.selector ORDER BY events DESC LIMIT 25;

-- name: contracts
-- Operators that share a batch contract are probably one operation using several gas wallets.
SELECT to_contract, COUNT(DISTINCT sender) AS sender_wallets, COUNT(*) AS txs, SUM(n_logs_poison) AS events
FROM tx_meta GROUP BY to_contract ORDER BY events DESC LIMIT 15;

-- name: match_lengths
SELECT prefix_match, suffix_match, COUNT(*) AS events
FROM poison_events GROUP BY 1, 2 ORDER BY events DESC LIMIT 15;

-- name: reaction_time
-- How long after the victim's genuine transfer with R does the lookalike of R show up?
SELECT CASE
         WHEN block - mimic_last_block <= 150  THEN '0-30 s'
         WHEN block - mimic_last_block <= 300  THEN '30-60 s'
         WHEN block - mimic_last_block <= 600  THEN '1-2 min'
         WHEN block - mimic_last_block <= 3000 THEN '2-10 min'
         WHEN block - mimic_last_block <= 18000 THEN '10-60 min'
         ELSE '> 1 h' END AS delay,
       COUNT(*) AS events,
       MIN(block - mimic_last_block) AS min_blocks
FROM poison_events GROUP BY 1 ORDER BY min_blocks;

-- name: lookalike_reuse
-- One lookalike, many victims: the attacker imitates a popular address and poisons everyone who pays it.
SELECT lookalike, mimics, COUNT(DISTINCT victim) AS victims, COUNT(*) AS events,
       MIN(prefix_match) AS prefix, MIN(suffix_match) AS suffix
FROM poison_events GROUP BY lookalike, mimics ORDER BY victims DESC LIMIT 20;

-- name: most_imitated
SELECT mimics, COUNT(DISTINCT lookalike) AS lookalikes_made, COUNT(DISTINCT victim) AS victims_targeted
FROM poison_events GROUP BY mimics ORDER BY victims_targeted DESC LIMIT 20;

-- name: repeat_victims
SELECT victim, COUNT(*) AS events, COUNT(DISTINCT lookalike) AS lookalikes, COUNT(DISTINCT mimics) AS counterparties_imitated
FROM poison_events GROUP BY victim ORDER BY events DESC LIMIT 20;

-- name: losses
SELECT l.victim, l.lookalike, l.mimics, ROUND(l.amount_units / 1e6, 2) AS usdc,
       l.loss_block - l.first_poison_block AS blocks_after_poison, l.loss_tx,
       (SELECT COUNT(*) FROM xfer x JOIN addr v ON v.id = x.f JOIN addr r ON r.id = x.t
         WHERE v.a = l.victim AND r.a = l.mimics AND x.v >= 10000) AS genuine_payments_to_real_address
FROM losses l ORDER BY l.amount_units DESC;

-- name: lookalike_funding
SELECT funder, COUNT(DISTINCT lookalike) AS lookalikes_funded, ROUND(SUM(usdc), 2) AS usdc
FROM lookalike_funding GROUP BY funder ORDER BY lookalikes_funded DESC LIMIT 15;
