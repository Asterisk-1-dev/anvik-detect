"""Tests for Rule 8.1 RAPID_ONWARD_TRANSFER."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.rapid_onward import RapidOnwardTransferRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_rapid_onward_true_positive(default_config: Config):
    # ACC1 receives 10,000 INR and sends 9,000 INR to ACC2 after 5 mins
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    rule = RapidOnwardTransferRule(default_config)
    findings = rule.run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RAPID_ONWARD_TRANSFER"
    assert "ACC1" in f.account_ids
    assert "ACC2" in f.account_ids
    assert f.evidence["forwarded_pct"] == 90.0
    assert f.evidence["gap_minutes"] == 5.0
    assert f.strength >= 0.5


def test_rapid_onward_true_negative_slow_gap(default_config: Config):
    # ACC1 receives 10,000 INR and sends 9,000 INR after 30 mins (threshold is 15 mins)
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:30:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    rule = RapidOnwardTransferRule(default_config)
    findings = rule.run(ctx)
    assert len(findings) == 0


def test_rapid_onward_boundary_percentage(default_config: Config):
    # Min forwarded pct is 80%. Test 79% (stays quiet) vs 80% (fires)
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    # 79%
    txns_below = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 7900.0),
    ]
    ds_below = build_dataset_from_dicts(accs, [], txns_below)
    ctx_below = RuleContext(ds_below, default_config, TransactionGraph(ds_below), FeatureStore(ds_below))
    assert len(RapidOnwardTransferRule(default_config).run(ctx_below)) == 0

    # 80%
    txns_at = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 8000.0),
    ]
    ds_at = build_dataset_from_dicts(accs, [], txns_at)
    ctx_at = RuleContext(ds_at, default_config, TransactionGraph(ds_at), FeatureStore(ds_at))
    assert len(RapidOnwardTransferRule(default_config).run(ctx_at)) == 1


def test_rapid_onward_lookalike_refund_to_sender(default_config: Config):
    # ACC0 sends to ACC1, ACC1 refunds back to ACC0 within 5 mins
    accs = [make_account("ACC1"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 5000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc0@synaxis", 5000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = RapidOnwardTransferRule(default_config).run(ctx)
    assert len(findings) == 0


def test_rapid_onward_lookalike_recurring_payee(default_config: Config):
    # ACC1 frequently pays ACC2 (rent or utility, e.g. 2 prior payments)
    # Then receives a transfer from ACC0 and pays ACC2 again within 5 mins. Should be suppressed.
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("PRIOR1", "2026-02-01 10:00:00", "acc1@synaxis", "acc2@synaxis", 5000.0),
        make_txn("PRIOR2", "2026-02-15 10:00:00", "acc1@synaxis", "acc2@synaxis", 5000.0),
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = RapidOnwardTransferRule(default_config).run(ctx)
    assert len(findings) == 0
