"""Tests for Rules 8.2 MULTI_SOURCE_FAN_IN and 8.3 FAN_OUT_SPLITTING."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.fan_in import MultiSourceFanInRule
from detection.rules.fan_out import FanOutSplittingRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_fan_in_true_positive(default_config: Config):
    # ACC_REC receives payments from 8 distinct first-time senders within 30 mins
    accs = [make_account(f"ACC_S_{i}") for i in range(8)] + [make_account("ACC_REC")]
    txns = [
        make_txn(f"TXN_{i}", f"2026-03-01 10:{i*3:02d}:00", f"acc_s_{i}@synaxis", "acc_rec@synaxis", 500.0)
        for i in range(8)
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = MultiSourceFanInRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["distinct_senders"] == 8
    assert f.evidence["first_time_share"] == 1.0


def test_fan_in_lookalike_merchant_repeat_senders(default_config: Config):
    # ACC_REC receives payments from 8 distinct senders, but 5 of them have paid earlier (repeat payers > 50%)
    accs = [make_account(f"ACC_S_{i}") for i in range(8)] + [make_account("ACC_REC")]
    prior_txns = [
        make_txn(f"PRIOR_{i}", f"2026-02-15 10:00:00", f"acc_s_{i}@synaxis", "acc_rec@synaxis", 100.0)
        for i in range(5)
    ]
    current_txns = [
        make_txn(f"TXN_{i}", f"2026-03-01 10:{i*3:02d}:00", f"acc_s_{i}@synaxis", "acc_rec@synaxis", 500.0)
        for i in range(8)
    ]
    ds = build_dataset_from_dicts(accs, [], prior_txns + current_txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = MultiSourceFanInRule(default_config).run(ctx)
    assert len(findings) == 0


def test_fan_out_true_positive(default_config: Config):
    # Inbound 10,000 INR; split into 3 outgoing of 3000, 3000, 3000 (total 9000, 90%, spread 0%)
    accs = [make_account("ACC_IN"), make_account("ACC_OUT_1"), make_account("ACC_OUT_2"), make_account("ACC_OUT_3"), make_account("SENDER")]
    txns = [
        make_txn("IN0", "2026-03-01 10:00:00", "sender@synaxis", "acc_in@synaxis", 10000.0),
        make_txn("OUT1", "2026-03-01 10:05:00", "acc_in@synaxis", "acc_out_1@synaxis", 3000.0),
        make_txn("OUT2", "2026-03-01 10:08:00", "acc_in@synaxis", "acc_out_2@synaxis", 3000.0),
        make_txn("OUT3", "2026-03-01 10:12:00", "acc_in@synaxis", "acc_out_3@synaxis", 3000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = FanOutSplittingRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["outgoing_count"] == 3
    assert f.evidence["amount_spread_pct"] == 0.0


def test_fan_out_lookalike_unequal_spread(default_config: Config):
    # Inbound 10,000 INR; outbound 3 transfers of 1000, 3000, 5000 (mean = 3000, spread = (5000-1000)/3000 = 133% > 25%)
    accs = [make_account("ACC_IN"), make_account("ACC_OUT_1"), make_account("ACC_OUT_2"), make_account("ACC_OUT_3"), make_account("SENDER")]
    txns = [
        make_txn("IN0", "2026-03-01 10:00:00", "sender@synaxis", "acc_in@synaxis", 10000.0),
        make_txn("OUT1", "2026-03-01 10:05:00", "acc_in@synaxis", "acc_out_1@synaxis", 1000.0),
        make_txn("OUT2", "2026-03-01 10:08:00", "acc_in@synaxis", "acc_out_2@synaxis", 3000.0),
        make_txn("OUT3", "2026-03-01 10:12:00", "acc_in@synaxis", "acc_out_3@synaxis", 5000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = FanOutSplittingRule(default_config).run(ctx)
    assert len(findings) == 0
