"""NetworkX graph construction and fast temporal query helpers."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import networkx as nx
import pandas as pd
from detection.loader import Dataset


class TransactionGraph:
    """MultiDiGraph of accounts and SUCCESS transactions with fast indexing."""

    def __init__(self, dataset: Dataset):
        self.dataset = dataset
        self.graph = nx.MultiDiGraph()
        self._build_graph()

    def _build_graph(self) -> None:
        """Populate nodes from accounts and edges from successful transactions."""
        # Add account nodes
        for _, row in self.dataset.accounts.iterrows():
            acc_id = row["account_id"]
            self.graph.add_node(
                acc_id,
                vpa=row.get("vpa", ""),
                bank=row.get("bank", ""),
                created_at=row.get("created_at", ""),
            )

        # Add transaction edges
        # Edge key = txn_id
        for _, row in self.dataset.successful_txns.iterrows():
            sender = row["sender_account_id"]
            receiver = row["receiver_account_id"]
            txn_id = row["txn_id"]

            # Ensure nodes exist even if account was missing from accounts table
            if not self.graph.has_node(sender):
                self.graph.add_node(sender, vpa=row.get("sender_vpa", ""), bank="", created_at="")
            if not self.graph.has_node(receiver):
                self.graph.add_node(receiver, vpa=row.get("receiver_vpa", ""), bank="", created_at="")

            self.graph.add_edge(
                sender,
                receiver,
                key=txn_id,
                txn_id=txn_id,
                amount_inr=float(row["amount_inr"]),
                timestamp=row["timestamp"],
                txn_type=row["txn_type"],
                device_id=row["device_id"],
            )

    def out_edges_after(
        self, account: str, t: datetime, window: timedelta
    ) -> List[Dict[str, Any]]:
        """Return outbound edges from `account` within `(t, t + window]`, sorted by timestamp."""
        if not self.graph.has_node(account):
            return []

        out_txns = []
        t_end = t + window
        for _, receiver, txn_id, data in self.graph.out_edges(account, keys=True, data=True):
            ts = data["timestamp"]
            if t < ts <= t_end:
                out_txns.append(
                    {
                        "receiver": receiver,
                        "txn_id": txn_id,
                        **data,
                    }
                )
        out_txns.sort(key=lambda x: (x["timestamp"], x["txn_id"]))
        return out_txns

    def in_edges_before(
        self, account: str, t: datetime, window: timedelta
    ) -> List[Dict[str, Any]]:
        """Return inbound edges to `account` within `[t - window, t)`, sorted by timestamp."""
        if not self.graph.has_node(account):
            return []

        in_txns = []
        t_start = t - window
        for sender, _, txn_id, data in self.graph.in_edges(account, keys=True, data=True):
            ts = data["timestamp"]
            if t_start <= ts < t:
                in_txns.append(
                    {
                        "sender": sender,
                        "txn_id": txn_id,
                        **data,
                    }
                )
        in_txns.sort(key=lambda x: (x["timestamp"], x["txn_id"]))
        return in_txns

    def to_aggregated_digraph(self) -> nx.DiGraph:
        """Project the MultiDiGraph to a simple DiGraph with aggregated amount and count per pair.

        Used for cycle candidate pruning and topology analysis.
        """
        simple_g = nx.DiGraph()
        for u, v, data in self.graph.edges(data=True):
            amt = data["amount_inr"]
            if simple_g.has_edge(u, v):
                simple_g[u][v]["total_amount"] += amt
                simple_g[u][v]["count"] += 1
            else:
                simple_g.add_edge(u, v, total_amount=amt, count=1)
        return simple_g
