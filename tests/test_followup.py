"""Follow-up losses: only a poisoned victim paying ITS lookalike >= 1 USDC counts."""
from poison.collect import connect
from poison.followup import SCHEMA, losses

V, L, R, OTHER, L2 = ("0x" + c * 40 for c in "12345")


def test_followup_loss_rules(tmp_path):
    con = connect(tmp_path / "t.db")
    con.executescript(SCHEMA)
    con.execute("INSERT INTO poison_events(block, li, tx, pattern, victim, lookalike, mimics, prefix_match, suffix_match,"
                " mimic_relation, mimic_first_block, value_units, mimic_last_block)"
                " VALUES (10, 0, '0xa', 'zero_value_spoof', ?, ?, ?, 4, 4, 'sent', 5, 0, 5)", (V, L, R))
    con.executemany("INSERT INTO followup_xfer VALUES (?,?,?,?,?,?)", [
        (100, 0, V, L, 250_000_000, "0xloss"),   # victim pays its lookalike: loss
        (101, 0, V, L, 500_000, "0xsmall"),      # under 1 USDC: not a loss
        (102, 0, OTHER, L, 9_000_000, "0xo"),    # someone not poisoned by L: counted separately
        (103, 0, V, L2, 9_000_000, "0xl2"),      # V pays a lookalike that never poisoned V: not this victim's loss
    ])
    s = losses(con)
    assert (s["loss_payments"], s["victims_who_paid"], s["usdc_lost"]) == (1, 1, 250.0)
    assert (s["other_payments_into_lookalikes_ge_1usdc"], s["other_usdc"]) == (2, 18.0)
    assert con.execute("SELECT mimics, first_poison_block FROM followup_losses").fetchone() == (R, 10)
