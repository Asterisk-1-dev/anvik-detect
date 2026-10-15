"""Integration tests for run_detection across multiple patterns and empty datasets."""

from datetime import datetime, timezone
import pytest
from detection.config import Config
from detection.engine import run_detection
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_empty_dataset_handling(default_config: Config):
    ds = build_dataset_from_dicts([], [], [])
    output = run_detection(ds, default_config, dataset_id="empty_test")
    assert output.count == 0
    assert output.alerts == []
    assert output.rings == []
    assert output.account_summaries == []
    assert output.meta.rules_run != []


def test_no_fraud_conclusion_in_any_alert(default_config: Config):
    # Setup multiple patterns in one dataset:
    # 1. Rapid onward: ACC1 -> ACC2
    # 2. Shared device: DEV999 across ACC1, ACC2, ACC3
    accs = [make_account("ACC0"), make_account("ACC1"), make_account("ACC2"), make_account("ACC3")]
    devs = [
        {"device_id": "DEV999", "account_id": "ACC1"},
        {"device_id": "DEV999", "account_id": "ACC2"},
        {"device_id": "DEV999", "account_id": "ACC3"},
    ]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0, device_id="DEV999"),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0, device_id="DEV999"),
    ]
    ds = build_dataset_from_dicts(accs, devs, txns)
    output = run_detection(ds, default_config, dataset_id="integration_test")

    assert output.count >= 2
    for alr in output.alerts:
        assert len(alr.alternative_explanations) >= 2
        assert len(alr.would_clear_if) >= 2
        assert alr.limitations != ""
        assert "This alone does not prove misuse." in alr.limitations

        # Check: the word "fraud" must NEVER be used as a conclusion in alert text
        full_text = (
            f"{alr.explanation} {alr.limitations} {' '.join(alr.alternative_explanations)} {' '.join(alr.would_clear_if)}"
        ).lower()

        # Disallowed phrases / conclusion statements
        assert "this is fraud" not in full_text
        assert "declared fraud" not in full_text
        assert "guilty of fraud" not in full_text
        assert "proves fraud" not in full_text
        assert "is a fraudulent account" not in full_text


def test_input_dataframes_not_mutated(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    orig_txns_len = len(ds.transactions)
    orig_accs_len = len(ds.accounts)

    output = run_detection(ds, default_config)
    assert len(ds.transactions) == orig_txns_len
    assert len(ds.accounts) == orig_accs_len
