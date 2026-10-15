"""Data loading, validation, and typed Dataset encapsulation."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class Dataset:
    """Encapsulates all input dataframes for the detection engine."""
    accounts: pd.DataFrame
    devices: pd.DataFrame
    transactions: pd.DataFrame
    complaints: pd.DataFrame
    successful_txns: pd.DataFrame
    validation_warnings: List[str] = field(default_factory=list)
    dropped_rows: Dict[str, int] = field(default_factory=dict)
    vpa_to_account: Dict[str, str] = field(default_factory=dict)
    account_to_vpa: Dict[str, str] = field(default_factory=dict)


def load_dataset(input_dir: str | Path, assume_timezone: str = "UTC") -> Dataset:
    """Load and validate the 4 CSV files (accounts, devices, transactions, complaints).

    Collects warnings and drops invalid rows without crashing (except if required
    files or columns are missing).
    """
    path = Path(input_dir)
    if not path.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {path}")

    # Check required files
    accounts_file = path / "accounts.csv"
    devices_file = path / "devices.csv"
    transactions_file = path / "transactions.csv"
    complaints_file = path / "complaints.csv"

    for req_file in [accounts_file, devices_file, transactions_file]:
        if not req_file.is_file():
            raise FileNotFoundError(f"Required input file missing: {req_file.name}")

    validation_warnings: List[str] = []
    dropped_counts: Dict[str, int] = {
        "accounts": 0,
        "devices": 0,
        "transactions": 0,
        "complaints": 0,
    }

    # 1. Load accounts
    accounts_df = pd.read_csv(accounts_file, dtype=str)
    req_acc_cols = {"account_id", "holder_name", "vpa", "bank", "created_at"}
    if not req_acc_cols.issubset(accounts_df.columns):
        raise ValueError(f"accounts.csv missing required columns: {req_acc_cols - set(accounts_df.columns)}")

    # Clean accounts
    orig_acc_len = len(accounts_df)
    accounts_df = accounts_df.dropna(subset=["account_id", "vpa"]).copy()
    accounts_df["account_id"] = accounts_df["account_id"].str.strip()
    accounts_df["vpa"] = accounts_df["vpa"].str.strip()
    accounts_df = accounts_df.drop_duplicates(subset=["vpa"], keep="first")
    accounts_df = accounts_df.drop_duplicates(subset=["account_id"], keep="first")
    acc_dropped = orig_acc_len - len(accounts_df)
    if acc_dropped > 0:
        dropped_counts["accounts"] += acc_dropped
        validation_warnings.append(f"Dropped {acc_dropped} invalid or duplicate rows from accounts.csv")

    vpa_to_acc = dict(zip(accounts_df["vpa"], accounts_df["account_id"]))
    acc_to_vpa = dict(zip(accounts_df["account_id"], accounts_df["vpa"]))

    # 2. Load devices
    devices_df = pd.read_csv(devices_file, dtype=str)
    req_dev_cols = {"device_id", "account_id"}
    if not req_dev_cols.issubset(devices_df.columns):
        raise ValueError(f"devices.csv missing required columns: {req_dev_cols - set(devices_df.columns)}")

    orig_dev_len = len(devices_df)
    devices_df = devices_df.dropna(subset=["device_id", "account_id"]).copy()
    devices_df["device_id"] = devices_df["device_id"].str.strip()
    devices_df["account_id"] = devices_df["account_id"].str.strip()
    devices_df = devices_df.drop_duplicates()
    dev_dropped = orig_dev_len - len(devices_df)
    if dev_dropped > 0:
        dropped_counts["devices"] += dev_dropped
        validation_warnings.append(f"Dropped {dev_dropped} invalid or duplicate rows from devices.csv")

    # 3. Load transactions
    txns_df = pd.read_csv(transactions_file, dtype=str)
    req_txn_cols = {
        "txn_id",
        "timestamp",
        "sender_vpa",
        "receiver_vpa",
        "amount",
        "txn_type",
        "status",
        "device_id",
    }
    if not req_txn_cols.issubset(txns_df.columns):
        raise ValueError(f"transactions.csv missing required columns: {req_txn_cols - set(txns_df.columns)}")

    orig_txns_len = len(txns_df)
    # Strip strings
    for col in ["txn_id", "timestamp", "sender_vpa", "receiver_vpa", "txn_type", "status", "device_id"]:
        txns_df[col] = txns_df[col].astype(str).str.strip()

    # Check duplicate txn_id
    dup_txns = txns_df.duplicated(subset=["txn_id"], keep="first")
    if dup_txns.any():
        num_dup = int(dup_txns.sum())
        validation_warnings.append(f"Found and dropped {num_dup} duplicate txn_id in transactions.csv")
        txns_df = txns_df[~dup_txns].copy()

    # Parse amounts
    amount_numeric = pd.to_numeric(txns_df["amount"], errors="coerce")
    invalid_amount = amount_numeric.isna() | (amount_numeric <= 0)
    if invalid_amount.any():
        num_inv_amt = int(invalid_amount.sum())
        validation_warnings.append(f"Found and dropped {num_inv_amt} transactions with invalid or non-positive amount")
        txns_df = txns_df[~invalid_amount].copy()
        amount_numeric = amount_numeric[~invalid_amount]

    txns_df["amount_inr"] = amount_numeric.astype(float)

    # Parse timestamps
    ts_parsed = pd.to_datetime(txns_df["timestamp"], errors="coerce")
    invalid_ts = ts_parsed.isna()
    if invalid_ts.any():
        num_inv_ts = int(invalid_ts.sum())
        validation_warnings.append(f"Found and dropped {num_inv_ts} transactions with unparseable timestamps")
        txns_df = txns_df[~invalid_ts].copy()
        ts_parsed = ts_parsed[~invalid_ts]

    # Localize or convert to UTC
    if ts_parsed.dt.tz is None:
        ts_parsed = ts_parsed.dt.tz_localize(assume_timezone)
    else:
        ts_parsed = ts_parsed.dt.tz_convert("UTC")

    txns_df["timestamp"] = ts_parsed

    # Map account IDs from VPAs
    txns_df["sender_account_id"] = txns_df["sender_vpa"].map(vpa_to_acc)
    txns_df["receiver_account_id"] = txns_df["receiver_vpa"].map(vpa_to_acc)

    # Check unknown VPAs
    unknown_vpa = txns_df["sender_account_id"].isna() | txns_df["receiver_account_id"].isna()
    if unknown_vpa.any():
        num_unk_vpa = int(unknown_vpa.sum())
        validation_warnings.append(f"Found and dropped {num_unk_vpa} transactions with unknown VPAs")
        txns_df = txns_df[~unknown_vpa].copy()

    # Self-transfers check (sender == receiver)
    self_transfers = txns_df["sender_account_id"] == txns_df["receiver_account_id"]
    if self_transfers.any():
        num_self = int(self_transfers.sum())
        validation_warnings.append(f"Found and dropped {num_self} self-transfer transactions (sender == receiver)")
        txns_df = txns_df[~self_transfers].copy()

    txns_dropped = orig_txns_len - len(txns_df)
    dropped_counts["transactions"] = txns_dropped

    # Sort all transactions deterministically
    txns_df = txns_df.sort_values(by=["timestamp", "txn_id"]).reset_index(drop=True)

    # Filter successful transactions
    successful_txns = (
        txns_df[txns_df["status"] == "SUCCESS"]
        .sort_values(by=["timestamp", "txn_id"])
        .reset_index(drop=True)
    )

    # 4. Load complaints (optional / may be absent or empty)
    complaints_df = pd.DataFrame(columns=["complaint_id", "victim_vpa", "txn_id", "complaint_date"])
    if complaints_file.is_file():
        try:
            raw_comp = pd.read_csv(complaints_file, dtype=str)
            req_comp_cols = {"complaint_id", "victim_vpa", "txn_id", "complaint_date"}
            if req_comp_cols.issubset(raw_comp.columns):
                raw_comp = raw_comp.dropna(subset=["complaint_id", "txn_id"]).copy()
                for c in req_comp_cols:
                    raw_comp[c] = raw_comp[c].astype(str).str.strip()

                # Verify txn_id exists
                all_txns_set = set(txns_df["txn_id"])
                missing_txns = ~raw_comp["txn_id"].isin(all_txns_set)
                if missing_txns.any():
                    num_miss = int(missing_txns.sum())
                    validation_warnings.append(f"Found and dropped {num_miss} complaints referencing unknown txn_ids")
                    raw_comp = raw_comp[~missing_txns].copy()

                complaints_df = raw_comp.drop_duplicates().reset_index(drop=True)
            else:
                validation_warnings.append(
                    f"complaints.csv missing required columns: {req_comp_cols - set(raw_comp.columns)}"
                )
        except Exception as e:
            validation_warnings.append(f"Failed to read complaints.csv: {e}")
    else:
        logger.info("complaints.csv not found; running without complaints.")

    dropped_counts["complaints"] = 0

    return Dataset(
        accounts=accounts_df.reset_index(drop=True),
        devices=devices_df.reset_index(drop=True),
        transactions=txns_df,
        complaints=complaints_df,
        successful_txns=successful_txns,
        validation_warnings=validation_warnings,
        dropped_rows=dropped_counts,
        vpa_to_account=vpa_to_acc,
        account_to_vpa=acc_to_vpa,
    )
