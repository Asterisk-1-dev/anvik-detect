"""Shared test fixtures and dataset builders for RingScope tests."""

from datetime import datetime, timezone
from typing import List, Optional
import pandas as pd
import pytest
from detection.config import Config, load_config
from detection.loader import Dataset


def make_account(
    account_id: str,
    holder_name: str = "Test User",
    vpa: Optional[str] = None,
    bank: str = "SYNAXIS",
    created_at: str = "2026-01-01",
) -> dict:
    if vpa is None:
        vpa = f"{account_id.lower()}@synaxis"
    return {
        "account_id": account_id,
        "holder_name": holder_name,
        "vpa": vpa,
        "bank": bank,
        "created_at": created_at,
    }


def make_txn(
    txn_id: str,
    timestamp: str,
    sender_vpa: str,
    receiver_vpa: str,
    amount: float,
    txn_type: str = "PAY",
    status: str = "SUCCESS",
    device_id: str = "DEV001",
) -> dict:
    return {
        "txn_id": txn_id,
        "timestamp": timestamp,
        "sender_vpa": sender_vpa,
        "receiver_vpa": receiver_vpa,
        "amount": str(amount),
        "txn_type": txn_type,
        "status": status,
        "device_id": device_id,
    }


def build_dataset_from_dicts(
    accounts_rows: List[dict],
    devices_rows: List[dict],
    txns_rows: List[dict],
    complaints_rows: Optional[List[dict]] = None,
    assume_timezone: str = "UTC",
) -> Dataset:
    acc_df = pd.DataFrame(accounts_rows, columns=["account_id", "holder_name", "vpa", "bank", "created_at"])
    dev_df = pd.DataFrame(devices_rows, columns=["device_id", "account_id"])
    txns_df = pd.DataFrame(
        txns_rows,
        columns=[
            "txn_id",
            "timestamp",
            "sender_vpa",
            "receiver_vpa",
            "amount",
            "txn_type",
            "status",
            "device_id",
        ],
    )
    comp_df = (
        pd.DataFrame(complaints_rows, columns=["complaint_id", "victim_vpa", "txn_id", "complaint_date"])
        if complaints_rows
        else pd.DataFrame(columns=["complaint_id", "victim_vpa", "txn_id", "complaint_date"])
    )

    vpa_to_acc = dict(zip(acc_df["vpa"], acc_df["account_id"]))
    acc_to_vpa = dict(zip(acc_df["account_id"], acc_df["vpa"]))

    txns_clean = txns_df.copy()
    txns_clean["amount_inr"] = pd.to_numeric(txns_clean["amount"], errors="coerce").astype(float)
    ts_parsed = pd.to_datetime(txns_clean["timestamp"], errors="coerce")
    if ts_parsed.dt.tz is None:
        ts_parsed = ts_parsed.dt.tz_localize(assume_timezone)
    else:
        ts_parsed = ts_parsed.dt.tz_convert("UTC")
    txns_clean["timestamp"] = ts_parsed
    txns_clean["sender_account_id"] = txns_clean["sender_vpa"].map(vpa_to_acc)
    txns_clean["receiver_account_id"] = txns_clean["receiver_vpa"].map(vpa_to_acc)
    txns_clean = txns_clean.sort_values(by=["timestamp", "txn_id"]).reset_index(drop=True)

    succ_txns = (
        txns_clean[txns_clean["status"] == "SUCCESS"]
        .sort_values(by=["timestamp", "txn_id"])
        .reset_index(drop=True)
    )

    return Dataset(
        accounts=acc_df.reset_index(drop=True),
        devices=dev_df.reset_index(drop=True),
        transactions=txns_clean,
        complaints=comp_df.reset_index(drop=True),
        successful_txns=succ_txns,
        validation_warnings=[],
        dropped_rows={"accounts": 0, "devices": 0, "transactions": 0, "complaints": 0},
        vpa_to_account=vpa_to_acc,
        account_to_vpa=acc_to_vpa,
    )


@pytest.fixture
def default_config() -> Config:
    return load_config()
