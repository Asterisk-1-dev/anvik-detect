"""Tests for Rules 8.6 NEW_ACCOUNT_BURST and 8.7 COLLECT_REQUEST_ABUSE."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.new_account_burst import NewAccountBurstRule
from detection.rules.collect_abuse import CollectRequestAbuseRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_new_account_burst_true_positive(default_config: Config):
    # ACC_BURST created 2026-03-01. On 2026-03-10 (age 9 days), does 12 transactions with other accounts.
    # Other accounts do only 1 transaction each, so median daily count is 1.
    # 12 >= 10 and 12 >= 4 * 1 -> fires!
    accs = [make_account("ACC_BURST", created_at="2026-03-01")]
    txns = []
    for i in range(12):
        other = f"ACC_OTHER_{i}"
        accs.append(make_account(other, created_at="2025-01-01"))
        txns.append(
            make_txn(f"TXN_{i}", f"2026-03-10 10:{i*2:02d}:00", "acc_burst@synaxis", f"{other.lower()}@synaxis", 100.0)
        )

    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = NewAccountBurstRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.account_ids[0] == "ACC_BURST"
    assert f.evidence["transactions_in_day"] == 12
    assert f.evidence["account_age_days"] == 9


def test_new_account_burst_lookalike_old_account(default_config: Config):
    # Old account (created 2024-01-01, age > 45 days) doing 12 txns should NOT fire
    accs = [make_account("ACC_OLD", created_at="2024-01-01")]
    txns = []
    for i in range(12):
        other = f"ACC_OTHER_{i}"
        accs.append(make_account(other, created_at="2025-01-01"))
        txns.append(
            make_txn(f"TXN_{i}", f"2026-03-10 10:{i*2:02d}:00", "acc_old@synaxis", f"{other.lower()}@synaxis", 100.0)
        )

    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = NewAccountBurstRule(default_config).run(ctx)
    assert len(findings) == 0


def test_collect_abuse_true_positive(default_config: Config):
    # ACC_INIT initiates 6 COLLECT requests to 5 distinct payers within 60 mins.
    # In COLLECT txns, money flows sender -> receiver (initiator is receiver).
    accs = [make_account("ACC_INIT")]
    txns = []
    for i in range(6):
        payer = f"ACC_P_{i % 5}"
        if i < 5:
            accs.append(make_account(payer))
        status = "FAILED" if i == 5 else "SUCCESS"
        txns.append(
            make_txn(
                f"TXN_C_{i}",
                f"2026-03-10 10:{i*5:02d}:00",
                f"{payer.lower()}@synaxis",
                "acc_init@synaxis",
                1000.0,
                txn_type="COLLECT",
                status=status,
            )
        )

    ds = build_dataset_from_dicts(accs, [], txns)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = CollectRequestAbuseRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.account_ids[0] == "ACC_INIT"
    assert f.evidence["collect_requests"] == 6
    assert f.evidence["distinct_payers"] == 5
    assert f.evidence["failed_collects"] == 1
