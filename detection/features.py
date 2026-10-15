"""Shared per-account and per-pair helper computations."""

from typing import Dict, List, Set, Tuple
import pandas as pd
from detection.loader import Dataset


class FeatureStore:
    """Caches pre-computed indices and lookup tables for high performance."""

    def __init__(self, dataset: Dataset):
        self.dataset = dataset
        self._inbound_by_acc: Dict[str, pd.DataFrame] = {}
        self._outbound_by_acc: Dict[str, pd.DataFrame] = {}
        self._pair_txns: Dict[Tuple[str, str], pd.DataFrame] = {}
        self._prior_payment_counts: Dict[Tuple[str, str], List[pd.Timestamp]] = {}
        self._init_indices()

    def _init_indices(self) -> None:
        succ = self.dataset.successful_txns
        if succ.empty:
            return

        # Group by receiver (inbound)
        for acc_id, group in succ.groupby("receiver_account_id"):
            self._inbound_by_acc[str(acc_id)] = group.sort_values(by=["timestamp", "txn_id"]).reset_index(drop=True)

        # Group by sender (outbound)
        for acc_id, group in succ.groupby("sender_account_id"):
            self._outbound_by_acc[str(acc_id)] = group.sort_values(by=["timestamp", "txn_id"]).reset_index(drop=True)

    def get_inbound(self, account_id: str) -> pd.DataFrame:
        """Get inbound successful transactions for an account."""
        return self._inbound_by_acc.get(account_id, pd.DataFrame(columns=self.dataset.successful_txns.columns))

    def get_outbound(self, account_id: str) -> pd.DataFrame:
        """Get outbound successful transactions from an account."""
        return self._outbound_by_acc.get(account_id, pd.DataFrame(columns=self.dataset.successful_txns.columns))

    def count_prior_outbound(self, sender_id: str, receiver_id: str, before_time: pd.Timestamp) -> int:
        """Count how many times `sender_id` had successfully paid `receiver_id` strictly before `before_time`."""
        out_df = self.get_outbound(sender_id)
        if out_df.empty:
            return 0
        matches = out_df[(out_df["receiver_account_id"] == receiver_id) & (out_df["timestamp"] < before_time)]
        return len(matches)
