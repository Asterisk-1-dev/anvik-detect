"""Tests verifying byte-identical output across repeated runs."""

import json
from datetime import datetime, timezone
import pytest
from detection.config import Config
from detection.engine import run_detection
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_determinism_byte_identical(default_config: Config):
    accs = [
        make_account("ACC0"),
        make_account("ACC1"),
        make_account("ACC2"),
        make_account("ACC3"),
    ]
    devs = [
        {"device_id": "DEV1", "account_id": "ACC1"},
        {"device_id": "DEV1", "account_id": "ACC2"},
        {"device_id": "DEV1", "account_id": "ACC3"},
    ]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0, device_id="DEV1"),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0, device_id="DEV1"),
    ]

    fixed_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    ds1 = build_dataset_from_dicts(accs, devs, txns)
    out1 = run_detection(ds1, default_config, dataset_id="det_test", generated_at=fixed_time)
    bytes1 = json.dumps(out1.model_dump(mode="json"), indent=2, ensure_ascii=False).encode("utf-8")

    ds2 = build_dataset_from_dicts(accs, devs, txns)
    out2 = run_detection(ds2, default_config, dataset_id="det_test", generated_at=fixed_time)
    bytes2 = json.dumps(out2.model_dump(mode="json"), indent=2, ensure_ascii=False).encode("utf-8")

    assert bytes1 == bytes2
