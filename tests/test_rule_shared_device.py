"""Tests for Rule 8.8 SHARED_DEVICE."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.shared_device import SharedDeviceRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_shared_device_informational_true_positive(default_config: Config):
    # DEV_999 is linked to 3 accounts in devices.csv
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC3")]
    devs = [
        {"device_id": "DEV_999", "account_id": "ACC1"},
        {"device_id": "DEV_999", "account_id": "ACC2"},
        {"device_id": "DEV_999", "account_id": "ACC3"},
    ]
    ds = build_dataset_from_dicts(accs, devs, [])
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = SharedDeviceRule(default_config).run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.informational_only is True
    assert f.evidence["device_id"] == "DEV_999"
    assert len(f.account_ids) == 3


def test_shared_device_true_negative_below_threshold(default_config: Config):
    # Device linked to only 2 accounts (min_accounts is 3)
    accs = [make_account("ACC1"), make_account("ACC2")]
    devs = [
        {"device_id": "DEV_999", "account_id": "ACC1"},
        {"device_id": "DEV_999", "account_id": "ACC2"},
    ]
    ds = build_dataset_from_dicts(accs, devs, [])
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = SharedDeviceRule(default_config).run(ctx)
    assert len(findings) == 0
