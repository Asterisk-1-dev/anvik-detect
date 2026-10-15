"""Tests for Rule 8.4 TRANSACTION_CYCLE."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.cycles import TransactionCycleRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_cycle_true_positive(default_config: Config):
    # A -> B -> C -> A within 1 hour, amounts 1000, 1000, 1000 (similarity 1.0)
    accs = [make_account("ACC_A"), make_account("ACC_B"), make_account("ACC_C")]
    txns = [
        make_txn("TXN_1", "2026-03-01 10:00:00", "acc_a@synaxis", "acc_b@synaxis", 1000.0),
        make_txn("TXN_2", "2026-03-01 10:20:00", "acc_b@synaxis", "acc_c@synaxis", 1000.0),
        make_txn("TXN_3", "2026-03-01 10:40:00", "acc_c@synaxis", "acc_a@synaxis", 1000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = TransactionCycleRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["cycle_length"] == 3
    assert f.evidence["amount_similarity_pct"] == 100.0
    assert len(f.txn_ids) == 3


def test_cycle_lookalike_unequal_amounts(default_config: Config):
    # A -> B -> C -> A, but amounts are 1000, 500, 1000 (min/max = 0.5 < 0.8)
    accs = [make_account("ACC_A"), make_account("ACC_B"), make_account("ACC_C")]
    txns = [
        make_txn("TXN_1", "2026-03-01 10:00:00", "acc_a@synaxis", "acc_b@synaxis", 1000.0),
        make_txn("TXN_2", "2026-03-01 10:20:00", "acc_b@synaxis", "acc_c@synaxis", 500.0),
        make_txn("TXN_3", "2026-03-01 10:40:00", "acc_c@synaxis", "acc_a@synaxis", 1000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = TransactionCycleRule(default_config).run(ctx)
    assert len(findings) == 0


def test_cycle_lookalike_spanning_days(default_config: Config):
    # A -> B -> C -> A, but span is 48 hours (max_span_hours = 6)
    accs = [make_account("ACC_A"), make_account("ACC_B"), make_account("ACC_C")]
    txns = [
        make_txn("TXN_1", "2026-03-01 10:00:00", "acc_a@synaxis", "acc_b@synaxis", 1000.0),
        make_txn("TXN_2", "2026-03-02 10:00:00", "acc_b@synaxis", "acc_c@synaxis", 1000.0),
        make_txn("TXN_3", "2026-03-03 10:00:00", "acc_c@synaxis", "acc_a@synaxis", 1000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = TransactionCycleRule(default_config).run(ctx)
    assert len(findings) == 0
