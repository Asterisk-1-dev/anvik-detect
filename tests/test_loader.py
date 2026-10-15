"""Tests for data loading, validation, and config loading."""

import pytest
import pandas as pd
from pathlib import Path
from detection.config import Config, load_config
from detection.loader import load_dataset
from tests.conftest import make_account, make_txn


def test_config_defaults(tmp_path: Path):
    cfg = load_config()
    assert cfg.general.assume_timezone == "UTC"
    assert cfg.rapid_onward_transfer.min_inbound_inr == 1000.0
    assert cfg.rapid_onward_transfer.max_gap_minutes == 15.0
    assert cfg.config_hash.startswith("sha256:")


def test_config_from_file(tmp_path: Path):
    cfg_file = tmp_path / "custom_config.yaml"
    cfg_file.write_text(
        """
general:
  assume_timezone: Asia/Kolkata
rapid_onward_transfer:
  min_inbound_inr: 500
"""
    )
    cfg = load_config(cfg_file)
    assert cfg.general.assume_timezone == "Asia/Kolkata"
    assert cfg.rapid_onward_transfer.min_inbound_inr == 500.0
    assert cfg.multi_source_fan_in.min_distinct_senders == 8  # default retained


def test_loader_valid_and_warnings(tmp_path: Path):
    # Setup files
    accounts_csv = tmp_path / "accounts.csv"
    accounts_csv.write_text(
        "account_id,holder_name,vpa,bank,created_at\n"
        "ACC1,User 1,acc1@upi,BANK1,2026-01-01\n"
        "ACC2,User 2,acc2@upi,BANK2,2026-01-02\n"
        "ACC2,User 2 Dup,acc2_dup@upi,BANK2,2026-01-02\n"  # dup acc
    )

    devices_csv = tmp_path / "devices.csv"
    devices_csv.write_text(
        "device_id,account_id\n"
        "DEV1,ACC1\n"
        "DEV1,ACC2\n"
    )

    txns_csv = tmp_path / "transactions.csv"
    txns_csv.write_text(
        "txn_id,timestamp,sender_vpa,receiver_vpa,amount,txn_type,status,device_id\n"
        "TXN1,2026-02-01 10:00:00,acc1@upi,acc2@upi,1500,PAY,SUCCESS,DEV1\n"
        "TXN1,2026-02-01 10:00:00,acc1@upi,acc2@upi,1500,PAY,SUCCESS,DEV1\n"  # dup txn
        "TXN2,2026-02-01 10:05:00,acc1@upi,acc1@upi,500,PAY,SUCCESS,DEV1\n"   # self transfer
        "TXN3,2026-02-01 10:10:00,acc1@upi,unknown@upi,200,PAY,SUCCESS,DEV1\n" # unknown vpa
        "TXN4,2026-02-01 10:15:00,acc2@upi,acc1@upi,-10,PAY,SUCCESS,DEV1\n"    # negative amount
    )

    dataset = load_dataset(tmp_path)
    assert len(dataset.accounts) == 2
    assert len(dataset.successful_txns) == 1
    assert dataset.successful_txns.iloc[0]["txn_id"] == "TXN1"
    assert len(dataset.validation_warnings) > 0
    assert dataset.dropped_rows["transactions"] >= 4
    # Complaints is missing, should be empty df without crashing
    assert dataset.complaints.empty
