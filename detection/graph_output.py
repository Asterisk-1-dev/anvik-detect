"""Module for constructing directed transaction-network graphs for alerts and rings."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd
from detection.config import Config, GraphConfig
from detection.loader import Dataset
from detection.models import Alert, EdgeDirection, EdgeKind, Graph, GraphEdge, GraphNode, NodeRole, Ring

# Precedence when an account receives multiple roles within one graph:
# potential_mule > origin_account > receiving_account > destination_account > linked_account
ROLE_PRECEDENCE: Dict[str, int] = {
    "potential_mule": 5,
    "origin_account": 4,
    "receiving_account": 3,
    "destination_account": 2,
    "linked_account": 1,
}

ROLE_LABELS: Dict[str, str] = {
    "origin_account": "Origin account",
    "receiving_account": "Receiving account",
    "potential_mule": "Potential mule",
    "destination_account": "Destination account",
    "linked_account": "Linked account",
    "shared_device": "Shared device",
    "origin_device": "Origin device",
    "collect_request": "Collect request",
}


def assign_role_by_precedence(current_role: Optional[str], candidate_role: str) -> str:
    """Return the higher precedence role between current and candidate."""
    if current_role is None:
        return candidate_role
    curr_score = ROLE_PRECEDENCE.get(current_role, 0)
    cand_score = ROLE_PRECEDENCE.get(candidate_role, 0)
    return candidate_role if cand_score > curr_score else current_role


class GraphBuilder:
    """Constructs directed transaction graphs for individual alerts and rings."""

    def __init__(self, dataset: Dataset, config: Config):
        self.dataset = dataset
        self.config = config
        self.graph_cfg: GraphConfig = config.graph

        # Pre-index complaints by txn_id
        self.complaints_by_txn: Dict[str, List[str]] = defaultdict(list)
        if not dataset.complaints.empty:
            for _, r in dataset.complaints.iterrows():
                t_id = str(r["txn_id"]).strip()
                c_id = str(r["complaint_id"]).strip()
                if t_id and c_id:
                    self.complaints_by_txn[t_id].append(c_id)

        # Pre-index device to accounts & account to devices from devices.csv
        self.device_to_accounts: Dict[str, Set[str]] = defaultdict(set)
        self.account_to_devices: Dict[str, Set[str]] = defaultdict(set)
        if not dataset.devices.empty:
            for _, r in dataset.devices.iterrows():
                d_id = str(r["device_id"]).strip()
                a_id = str(r["account_id"]).strip()
                if d_id and a_id:
                    self.device_to_accounts[d_id].add(a_id)
                    self.account_to_devices[a_id].add(d_id)

        # Map txn_id to device_id and other transaction details
        self.txns_by_id: Dict[str, Dict[str, Any]] = {}
        if not dataset.transactions.empty:
            for _, r in dataset.transactions.iterrows():
                t_id = str(r["txn_id"]).strip()
                self.txns_by_id[t_id] = {
                    "txn_id": t_id,
                    "sender_account_id": r["sender_account_id"],
                    "receiver_account_id": r["receiver_account_id"],
                    "sender_vpa": r["sender_vpa"],
                    "receiver_vpa": r["receiver_vpa"],
                    "amount_inr": float(r["amount_inr"]),
                    "timestamp": r["timestamp"],
                    "txn_type": r["txn_type"],
                    "status": r["status"],
                    "device_id": str(r.get("device_id", "")).strip(),
                }

        # Fast lookup for successful transactions by account
        self.succ_inbound: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.succ_outbound: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        if not dataset.successful_txns.empty:
            for _, r in dataset.successful_txns.iterrows():
                d = {
                    "txn_id": str(r["txn_id"]).strip(),
                    "sender_account_id": r["sender_account_id"],
                    "receiver_account_id": r["receiver_account_id"],
                    "amount_inr": float(r["amount_inr"]),
                    "timestamp": r["timestamp"],
                    "txn_type": r["txn_type"],
                    "status": r["status"],
                    "device_id": str(r.get("device_id", "")).strip(),
                }
                self.succ_inbound[r["receiver_account_id"]].append(d)
                self.succ_outbound[r["sender_account_id"]].append(d)

        # Accounts metadata lookup
        self.accounts_meta: Dict[str, Dict[str, str]] = {}
        if not dataset.accounts.empty:
            for _, r in dataset.accounts.iterrows():
                a_id = str(r["account_id"]).strip()
                self.accounts_meta[a_id] = {
                    "vpa": str(r.get("vpa", "")).strip(),
                    "bank": str(r.get("bank", "")).strip(),
                }

    def _determine_roles_for_alert(self, alert: Alert) -> Dict[str, str]:
        """Determine initial account roles according to the 2.4 specification table."""
        rule_id = alert.rule_id
        ev = alert.evidence
        roles: Dict[str, str] = {}

        if rule_id == "RAPID_ONWARD_TRANSFER":
            # origin_account: sender of the inbound transaction
            in_txn_id = ev.get("inbound_txn_id")
            if in_txn_id and in_txn_id in self.txns_by_id:
                sender = self.txns_by_id[in_txn_id]["sender_account_id"]
                roles[sender] = "origin_account"

            # potential_mule: the account that forwards (first account_ids or in evidence)
            if alert.account_ids:
                roles[alert.account_ids[0]] = "potential_mule"

            # destination_account: receivers of the forwarded transactions
            for r_acc in ev.get("outbound_receivers", []):
                roles[r_acc] = "destination_account"

        elif rule_id == "MULTI_SOURCE_FAN_IN":
            # receiving account is potential_mule
            rec_acc = alert.account_ids[0] if alert.account_ids else None
            if rec_acc:
                roles[rec_acc] = "potential_mule"
            # origin_account: distinct senders of supporting transactions
            for t_id in alert.txn_ids:
                if t_id in self.txns_by_id:
                    s_acc = self.txns_by_id[t_id]["sender_account_id"]
                    if s_acc != rec_acc:
                        roles[s_acc] = "origin_account"

        elif rule_id == "FAN_OUT_SPLITTING":
            # sender of inbound transaction is origin_account
            # first txn in alert.txn_ids is inbound txn
            split_acc = alert.account_ids[0] if alert.account_ids else None
            if split_acc:
                roles[split_acc] = "potential_mule"

            if alert.txn_ids:
                first_txn = alert.txn_ids[0]
                if first_txn in self.txns_by_id:
                    s_acc = self.txns_by_id[first_txn]["sender_account_id"]
                    roles[s_acc] = "origin_account"

            # receivers of split transfers are destination_account
            for t_id in alert.txn_ids[1:]:
                if t_id in self.txns_by_id:
                    r_acc = self.txns_by_id[t_id]["receiver_account_id"]
                    roles[r_acc] = "destination_account"

        elif rule_id == "TRANSACTION_CYCLE":
            # sender of earliest transaction in cycle is origin_account
            # all other cycle accounts are linked_account
            if alert.txn_ids:
                earliest_t = alert.txn_ids[0]
                if earliest_t in self.txns_by_id:
                    roles[self.txns_by_id[earliest_t]["sender_account_id"]] = "origin_account"
            for acc in alert.account_ids:
                if acc not in roles:
                    roles[acc] = "linked_account"

        elif rule_id == "COMPLAINT_CONVERGENCE":
            # victim account of each complaint is origin_account
            # converging account is potential_mule
            # accounts on trails between victim and converging account are receiving_account
            # accounts at the ends of trails are destination_account
            conv_acc = alert.account_ids[0] if alert.account_ids else None

            trails = ev.get("trails", [])
            for tr in trails:
                path = tr.get("path", [])
                if path:
                    # Seed / victim account is path[0] or complaint victim
                    if path[0] != conv_acc:
                        roles[path[0]] = "origin_account"
                    # End of trail (if path extends beyond conv_acc)
                    if len(path) > 1 and path[-1] != conv_acc:
                        roles[path[-1]] = "destination_account"
                    # Intermediate accounts
                    for intermediate in path[1:-1]:
                        if intermediate != conv_acc:
                            roles[intermediate] = "receiving_account"

            if conv_acc:
                roles[conv_acc] = "potential_mule"

        elif rule_id == "NEW_ACCOUNT_BURST":
            if alert.account_ids:
                roles[alert.account_ids[0]] = "potential_mule"

        elif rule_id == "COLLECT_REQUEST_ABUSE":
            # requesting account is potential_mule
            req_acc = alert.account_ids[0] if alert.account_ids else None
            if req_acc:
                roles[req_acc] = "potential_mule"
            # payers are origin_account
            for t_id in alert.txn_ids:
                if t_id in self.txns_by_id:
                    s_acc = self.txns_by_id[t_id]["sender_account_id"]
                    if s_acc != req_acc:
                        roles[s_acc] = "origin_account"

        elif rule_id == "SHARED_DEVICE":
            # all accounts on device are linked_account
            for acc in alert.account_ids:
                roles[acc] = "linked_account"

        return roles

    def build_alert_graph(self, alert: Alert) -> Tuple[Graph, List[str]]:
        """Build directed transaction network graph for a single alert.

        Returns (graph, linked_txn_ids).
        """
        if not self.graph_cfg.enabled:
            return Graph(), []

        flagged_accounts: Set[str] = set(alert.account_ids)
        supporting_txn_ids: Set[str] = set(alert.txn_ids)

        # 1. Supporting edges
        supporting_edges_data: List[Dict[str, Any]] = []
        for t_id in alert.txn_ids:
            if t_id in self.txns_by_id:
                supporting_edges_data.append(self.txns_by_id[t_id])

        # Find per-account time bounds for supporting transactions
        acc_first_time: Dict[str, datetime] = {}
        acc_last_time: Dict[str, datetime] = {}
        for ed in supporting_edges_data:
            ts = ed["timestamp"]
            for a in [ed["sender_account_id"], ed["receiver_account_id"]]:
                if a in flagged_accounts:
                    if a not in acc_first_time or ts < acc_first_time[a]:
                        acc_first_time[a] = ts
                    if a not in acc_last_time or ts > acc_last_time[a]:
                        acc_last_time[a] = ts

        # Fallback if supporting txns didn't directly include flagged acc
        for a in flagged_accounts:
            if a not in acc_first_time:
                acc_first_time[a] = datetime.now(timezone.utc)
                acc_last_time[a] = datetime.now(timezone.utc)

        # 2. Context edges (Upstream & Downstream)
        # Search candidate context edges up to context_hops
        win_delta = timedelta(hours=self.graph_cfg.context_window_hours)
        selected_context_edges: List[Tuple[Dict[str, Any], EdgeDirection, float]] = []
        visited_context_txns: Set[str] = set(supporting_txn_ids)

        # Hop 0 accounts are flagged accounts
        curr_hop_accounts = set(flagged_accounts)
        curr_acc_first = dict(acc_first_time)
        curr_acc_last = dict(acc_last_time)

        for hop in range(self.graph_cfg.context_hops):
            next_hop_accounts: Set[str] = set()
            cand_edges_hop: List[Tuple[Dict[str, Any], EdgeDirection, float]] = []

            for acc in curr_hop_accounts:
                t_first = curr_acc_first.get(acc, datetime.now(timezone.utc))
                t_last = curr_acc_last.get(acc, datetime.now(timezone.utc))

                # Upstream: inbound before t_first within context_window_hours
                for in_tx in self.succ_inbound.get(acc, []):
                    t_id = in_tx["txn_id"]
                    if t_id in visited_context_txns:
                        continue
                    ts = in_tx["timestamp"]
                    if t_first - win_delta <= ts < t_first:
                        diff_sec = (t_first - ts).total_seconds()
                        cand_edges_hop.append((in_tx, "upstream", diff_sec))

                # Downstream: outbound after t_last within context_window_hours
                for out_tx in self.succ_outbound.get(acc, []):
                    t_id = out_tx["txn_id"]
                    if t_id in visited_context_txns:
                        continue
                    ts = out_tx["timestamp"]
                    if t_last < ts <= t_last + win_delta:
                        diff_sec = (ts - t_last).total_seconds()
                        cand_edges_hop.append((out_tx, "downstream", diff_sec))

            # Sort candidate edges by closeness in time, then txn_id
            cand_edges_hop.sort(key=lambda x: (x[2], x[0]["txn_id"]))

            for tx_info, direction, diff in cand_edges_hop:
                t_id = tx_info["txn_id"]
                if t_id not in visited_context_txns:
                    visited_context_txns.add(t_id)
                    selected_context_edges.append((tx_info, direction, diff))
                    s_acc = tx_info["sender_account_id"]
                    r_acc = tx_info["receiver_account_id"]
                    next_hop_accounts.add(s_acc)
                    next_hop_accounts.add(r_acc)
                    # Track times for next hop
                    ts = tx_info["timestamp"]
                    for na in [s_acc, r_acc]:
                        if na not in curr_acc_first or ts < curr_acc_first[na]:
                            curr_acc_first[na] = ts
                        if na not in curr_acc_last or ts > curr_acc_last[na]:
                            curr_acc_last[na] = ts

            curr_hop_accounts = next_hop_accounts - flagged_accounts

        # Truncate context edges if exceeding max_context_edges
        omitted_edges_count = 0
        truncated = False

        if len(selected_context_edges) > self.graph_cfg.max_context_edges:
            omitted_edges_count += len(selected_context_edges) - self.graph_cfg.max_context_edges
            selected_context_edges = selected_context_edges[: self.graph_cfg.max_context_edges]
            truncated = True

        # Build GraphEdge objects for payments
        graph_edges: List[GraphEdge] = []
        linked_txn_ids_set: Set[str] = set()

        for s_tx in supporting_edges_data:
            t_id = s_tx["txn_id"]
            comp_ids = self.complaints_by_txn.get(t_id, [])
            edge = GraphEdge(
                id=t_id,
                kind="payment",
                source=s_tx["sender_account_id"],
                target=s_tx["receiver_account_id"],
                txn_type=s_tx["txn_type"],
                status=s_tx["status"],
                amount_inr=round(s_tx["amount_inr"], 2),
                timestamp=s_tx["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                sequence=None,
                is_supporting=True,
                direction="supporting",
                reported=bool(comp_ids),
                complaint_ids=sorted(comp_ids),
                alert_ids=[alert.alert_id],
            )
            graph_edges.append(edge)

        for c_tx, direction, _ in selected_context_edges:
            t_id = c_tx["txn_id"]
            comp_ids = self.complaints_by_txn.get(t_id, [])
            edge = GraphEdge(
                id=t_id,
                kind="payment",
                source=c_tx["sender_account_id"],
                target=c_tx["receiver_account_id"],
                txn_type=c_tx["txn_type"],
                status=c_tx["status"],
                amount_inr=round(c_tx["amount_inr"], 2),
                timestamp=c_tx["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                sequence=None,
                is_supporting=False,
                direction=direction,
                reported=bool(comp_ids),
                complaint_ids=sorted(comp_ids),
                alert_ids=[],
            )
            graph_edges.append(edge)
            linked_txn_ids_set.add(t_id)

        # 3. Account nodes touched by any payment edge or in flagged accounts
        touched_accounts: Set[str] = set(flagged_accounts)
        for e in graph_edges:
            touched_accounts.add(e.source)
            touched_accounts.add(e.target)

        rule_roles = self._determine_roles_for_alert(alert)
        account_nodes_dict: Dict[str, GraphNode] = {}

        for a_id in sorted(touched_accounts):
            role_str = rule_roles.get(a_id, "linked_account")
            is_flagged = a_id in flagged_accounts
            acc_meta = self.accounts_meta.get(a_id, {})
            node = GraphNode(
                id=a_id,
                type="account",
                role=role_str,  # type: ignore
                label=ROLE_LABELS.get(role_str, "Linked account"),
                vpa=acc_meta.get("vpa"),
                bank=acc_meta.get("bank"),
                accounts_on_device=None,
                flagged=is_flagged,
                alert_ids=[alert.alert_id] if is_flagged else [],
            )
            account_nodes_dict[a_id] = node

        # 4. Device nodes (if include_devices)
        device_nodes: List[GraphNode] = []
        device_edges: List[GraphEdge] = []

        if self.graph_cfg.include_devices:
            # Shared devices: device linked in devices.csv to 2+ accounts present in this graph
            shared_dev_added: Set[str] = set()
            for dev_id, acc_set in self.device_to_accounts.items():
                in_graph_accs = acc_set.intersection(touched_accounts)
                if len(in_graph_accs) >= 2:
                    shared_dev_added.add(dev_id)
                    dev_node = GraphNode(
                        id=dev_id,
                        type="device",
                        role="shared_device",
                        label="Shared device",
                        vpa=None,
                        bank=None,
                        accounts_on_device=len(acc_set),
                        flagged=False,
                        alert_ids=[],
                    )
                    device_nodes.append(dev_node)
                    for acc in sorted(in_graph_accs):
                        link_edge = GraphEdge(
                            id=f"LNK-{dev_id}-{acc}",
                            kind="device_link",
                            source=dev_id,
                            target=acc,
                            txn_type=None,
                            status=None,
                            amount_inr=None,
                            timestamp=None,
                            sequence=None,
                            is_supporting=False,
                            direction="context",
                            reported=None,
                            complaint_ids=[],
                            alert_ids=[],
                        )
                        device_edges.append(link_edge)

            # Origin device: device used on earliest supporting transaction linked to sender
            if supporting_edges_data:
                earliest_supp_tx = min(supporting_edges_data, key=lambda x: (x["timestamp"], x["txn_id"]))
                orig_dev_id = earliest_supp_tx.get("device_id")
                if orig_dev_id and orig_dev_id not in shared_dev_added:
                    dev_node = GraphNode(
                        id=orig_dev_id,
                        type="device",
                        role="origin_device",
                        label="Origin device",
                        vpa=None,
                        bank=None,
                        accounts_on_device=len(self.device_to_accounts.get(orig_dev_id, set())),
                        flagged=False,
                        alert_ids=[],
                    )
                    device_nodes.append(dev_node)
                    link_edge = GraphEdge(
                        id=f"LNK-{orig_dev_id}-{earliest_supp_tx['sender_account_id']}",
                        kind="device_link",
                        source=orig_dev_id,
                        target=earliest_supp_tx["sender_account_id"],
                        txn_type=None,
                        status=None,
                        amount_inr=None,
                        timestamp=None,
                        sequence=None,
                        is_supporting=False,
                        direction="context",
                        reported=None,
                        complaint_ids=[],
                        alert_ids=[],
                    )
                    device_edges.append(link_edge)

        # 5. Collect-request nodes (if collect_request_as_node)
        collect_nodes: List[GraphNode] = []
        collect_edges: List[GraphEdge] = []
        if self.graph_cfg.collect_request_as_node:
            for pe in graph_edges:
                if pe.txn_type == "COLLECT":
                    t_id = pe.id
                    req_node = GraphNode(
                        id=f"REQ-{t_id}",
                        type="collect_request",
                        role="collect_request",
                        label="Collect request",
                        vpa=None,
                        bank=None,
                        accounts_on_device=None,
                        flagged=False,
                        alert_ids=[],
                    )
                    collect_nodes.append(req_node)
                    # Link from requester (target/receiver of payment) to request node
                    c_link = GraphEdge(
                        id=f"RQL-{t_id}",
                        kind="request_link",
                        source=pe.target,
                        target=f"REQ-{t_id}",
                        txn_type=None,
                        status=None,
                        amount_inr=None,
                        timestamp=None,
                        sequence=None,
                        is_supporting=False,
                        direction="context",
                        reported=None,
                        complaint_ids=[],
                        alert_ids=[],
                    )
                    collect_edges.append(c_link)

        # Combine nodes and check max_nodes constraint
        all_nodes = list(account_nodes_dict.values()) + device_nodes + collect_nodes
        all_edges = graph_edges + device_edges + collect_edges

        # Enforce max_nodes if exceeded
        if len(all_nodes) > self.graph_cfg.max_nodes:
            # Drop context accounts / devices if needed, keeping flagged accounts
            # In practice, with default max_context_edges=25 and max_nodes=40 this is rare
            all_nodes = all_nodes[: self.graph_cfg.max_nodes]
            valid_node_ids = {n.id for n in all_nodes}
            # Remove any edges pointing to dropped nodes
            kept_edges = []
            for e in all_edges:
                if e.source in valid_node_ids and e.target in valid_node_ids:
                    kept_edges.append(e)
                else:
                    omitted_edges_count += 1
                    truncated = True
            all_edges = kept_edges

        # 6. Sorting & Sequence assignment
        # Sort nodes by id
        all_nodes.sort(key=lambda n: n.id)

        # Sort edges: payments first by (timestamp, id), non-payments after by id
        payment_edges = [e for e in all_edges if e.kind == "payment"]
        non_payment_edges = [e for e in all_edges if e.kind != "payment"]

        payment_edges.sort(key=lambda e: (e.timestamp or "", e.id))
        non_payment_edges.sort(key=lambda e: e.id)

        # Assign 1-based sequence to payment edges
        for idx, pe in enumerate(payment_edges, start=1):
            pe.sequence = idx

        sorted_edges = payment_edges + non_payment_edges

        # Build sorted linked_txn_ids (non-supporting payment edge IDs sorted by timestamp then txn_id)
        linked_txns_sorted = [
            pe.id for pe in payment_edges if not pe.is_supporting
        ]

        graph = Graph(
            nodes=all_nodes,
            edges=sorted_edges,
            truncated=truncated,
            omitted_edges=omitted_edges_count,
            disclaimer="Roles are investigative hypotheses to support review, not findings of wrongdoing.",
        )

        return graph, linked_txns_sorted

    def build_ring_graph(self, ring: Ring, ring_alerts: List[Alert]) -> Graph:
        """Build directed transaction network graph for a ring as the union of its alerts' graphs."""
        if not self.graph_cfg.enabled:
            return Graph()

        flagged_ring_accounts: Set[str] = set(ring.account_ids)

        # Map nodes by id
        merged_nodes_dict: Dict[str, GraphNode] = {}
        # Map payment edges and non-payment edges by id
        merged_edges_dict: Dict[str, GraphEdge] = {}
        total_omitted = 0
        is_truncated = False

        for alr in ring_alerts:
            if not alr.graph:
                continue
            if alr.graph.truncated:
                is_truncated = True
            total_omitted += alr.graph.omitted_edges

            for node in alr.graph.nodes:
                if node.id not in merged_nodes_dict:
                    # Clone node
                    node_copy = node.model_copy(deep=True)
                    node_copy.flagged = node_copy.id in flagged_ring_accounts
                    node_copy.alert_ids = [alr.alert_id] if node_copy.flagged else []
                    merged_nodes_dict[node.id] = node_copy
                else:
                    existing = merged_nodes_dict[node.id]
                    # Merge alert_ids
                    if node.id in flagged_ring_accounts:
                        existing.flagged = True
                        if alr.alert_id not in existing.alert_ids:
                            existing.alert_ids.append(alr.alert_id)
                            existing.alert_ids.sort()
                    # Apply role precedence
                    if existing.type == "account" and node.type == "account":
                        higher_role = assign_role_by_precedence(existing.role, node.role)
                        existing.role = higher_role  # type: ignore
                        existing.label = ROLE_LABELS.get(higher_role, existing.label)

            for edge in alr.graph.edges:
                if edge.id not in merged_edges_dict:
                    edge_copy = edge.model_copy(deep=True)
                    merged_edges_dict[edge.id] = edge_copy
                else:
                    existing_e = merged_edges_dict[edge.id]
                    if edge.is_supporting:
                        existing_e.is_supporting = True
                        existing_e.direction = "supporting"
                    for a_id in edge.alert_ids:
                        if a_id not in existing_e.alert_ids:
                            existing_e.alert_ids.append(a_id)
                            existing_e.alert_ids.sort()

        # Separate payment and non-payment edges
        payment_edges = [e for e in merged_edges_dict.values() if e.kind == "payment"]
        non_payment_edges = [e for e in merged_edges_dict.values() if e.kind != "payment"]

        # Cap enforcement: max_ring_edges, max_ring_nodes
        # Never drop supporting edges for the sake of the cap: drop context edges first
        supporting_payments = [e for e in payment_edges if e.is_supporting]
        context_payments = [e for e in payment_edges if not e.is_supporting]

        # Order context edges by closeness (we can sort by timestamp desc or preserve order)
        context_payments.sort(key=lambda e: (e.timestamp or "", e.id))

        total_edges_count = len(payment_edges) + len(non_payment_edges)
        if total_edges_count > self.graph_cfg.max_ring_edges:
            is_truncated = True
            allowed_context = max(0, self.graph_cfg.max_ring_edges - len(supporting_payments))
            # Drop from non_payment and context_payments
            if len(context_payments) > allowed_context:
                dropped = len(context_payments) - allowed_context
                total_omitted += dropped
                context_payments = context_payments[:allowed_context]
                # If still over, drop non-payment edges
                if len(supporting_payments) + len(context_payments) + len(non_payment_edges) > self.graph_cfg.max_ring_edges:
                    allowed_non_pay = max(0, self.graph_cfg.max_ring_edges - len(supporting_payments) - len(context_payments))
                    dropped_np = len(non_payment_edges) - allowed_non_pay
                    total_omitted += dropped_np
                    non_payment_edges = non_payment_edges[:allowed_non_pay]
            else:
                remaining_quota = self.graph_cfg.max_ring_edges - len(supporting_payments) - len(context_payments)
                if len(non_payment_edges) > remaining_quota:
                    dropped_np = len(non_payment_edges) - remaining_quota
                    total_omitted += dropped_np
                    non_payment_edges = non_payment_edges[:remaining_quota]

        kept_payments = supporting_payments + context_payments
        kept_payments.sort(key=lambda e: (e.timestamp or "", e.id))
        non_payment_edges.sort(key=lambda e: e.id)

        # Recompute 1-based sequence over merged payment edges
        for idx, pe in enumerate(kept_payments, start=1):
            pe.sequence = idx

        all_ring_edges = kept_payments + non_payment_edges

        # Enforce max_ring_nodes
        ring_nodes = list(merged_nodes_dict.values())
        if len(ring_nodes) > self.graph_cfg.max_ring_nodes:
            is_truncated = True
            # Keep nodes used in edges, especially flagged accounts
            used_node_ids = {e.source for e in all_ring_edges} | {e.target for e in all_ring_edges}
            ring_nodes = [n for n in ring_nodes if n.id in used_node_ids or n.flagged]
            if len(ring_nodes) > self.graph_cfg.max_ring_nodes:
                ring_nodes = ring_nodes[: self.graph_cfg.max_ring_nodes]
                valid_ids = {n.id for n in ring_nodes}
                all_ring_edges = [e for e in all_ring_edges if e.source in valid_ids and e.target in valid_ids]

        ring_nodes.sort(key=lambda n: n.id)

        return Graph(
            nodes=ring_nodes,
            edges=all_ring_edges,
            truncated=is_truncated,
            omitted_edges=total_omitted,
            disclaimer="Roles are investigative hypotheses to support review, not findings of wrongdoing.",
        )
