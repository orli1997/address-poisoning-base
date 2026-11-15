-- Raw layer: every USDC Transfer log on Base in the collection window.
-- Addresses are interned (addr.id) to keep millions of rows small.
CREATE TABLE IF NOT EXISTS addr (
    id INTEGER PRIMARY KEY,
    a  TEXT NOT NULL UNIQUE                -- lower-case 0x address
);
CREATE TABLE IF NOT EXISTS xfer (
    block INTEGER NOT NULL,
    li    INTEGER NOT NULL,                -- log index in the block
    f     INTEGER NOT NULL REFERENCES addr(id),
    t     INTEGER NOT NULL REFERENCES addr(id),
    v     INTEGER NOT NULL,                -- raw units, 6 decimals (1 USDC = 1000000)
    tx    TEXT,                            -- kept only for transfers under 0.01 USDC (candidates)
    PRIMARY KEY (block, li)
) WITHOUT ROWID;
-- one timestamp per collected chunk; times in between are interpolated
CREATE TABLE IF NOT EXISTS block_time (block INTEGER PRIMARY KEY, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

-- Analysis layer, written by detect.py / campaigns.py
CREATE TABLE IF NOT EXISTS poison_events (
    block INTEGER, li INTEGER, tx TEXT,
    pattern TEXT,                          -- zero_value_spoof | zero_value_incoming | dust_from_lookalike | dust_to_lookalike
    victim TEXT, lookalike TEXT, mimics TEXT,
    prefix_match INTEGER, suffix_match INTEGER,
    mimic_relation TEXT,                   -- victim had SENT to / RECEIVED from the mimicked address
    mimic_first_block INTEGER, value_units INTEGER,
    mimic_last_block INTEGER,              -- last genuine interaction with the mimicked address before the event
    PRIMARY KEY (block, li, victim)
);
CREATE TABLE IF NOT EXISTS losses (
    victim TEXT, lookalike TEXT, mimics TEXT,
    first_poison_block INTEGER, loss_block INTEGER, loss_li INTEGER, loss_tx TEXT,
    amount_units INTEGER,
    PRIMARY KEY (loss_block, loss_li)
);
CREATE TABLE IF NOT EXISTS tx_meta (
    tx TEXT PRIMARY KEY, sender TEXT, to_contract TEXT, selector TEXT, n_logs_poison INTEGER
);
