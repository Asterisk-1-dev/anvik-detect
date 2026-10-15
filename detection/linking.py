"""Linking of related alerts, connected graph rings, and account summaries."""

from collections import defaultdict
from typing import Dict, List, Set, Tuple
from detection.models import AccountSummary, Alert, PriorityLevel, Ring


PRIORITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}


def higher_priority(p1: PriorityLevel, p2: PriorityLevel) -> PriorityLevel:
    return p1 if PRIORITY_WEIGHT[p1] >= PRIORITY_WEIGHT[p2] else p2


class UnionFind:
    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
            return x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str) -> None:
        root_x = self.find(x)
        root_y = self.find(y)
        if root_x != root_y:
            # Deterministic union: smaller string becomes parent
            if root_x < root_y:
                self.parent[root_y] = root_x
            else:
                self.parent[root_x] = root_y


def link_alerts_and_rings(
    alerts: List[Alert], direct_edges_between_flagged: Set[Tuple[str, str]] | None = None
) -> Tuple[List[Alert], List[Ring], List[AccountSummary]]:
    """Link related alerts, discover rings using Union-Find, and build account summaries.

    Rules:
    - related_alert_ids: alerts that share any account or any transaction ID (symmetric, sorted).
    - Rings: union-find over accounts in non-context alerts + direct transactions between flagged accounts.
      Context-only (SHARED_DEVICE) alerts attach to a ring if their accounts are already in it, but never
      create or merge rings by themselves.
    - Each group becomes RING-01, RING-02... ordered by highest priority (high first), then size descending,
      then root account ID.
    - account_summaries: per flagged account, its alert IDs and highest priority.
    """
    if not alerts:
        return [], [], []

    # 1. Compute related_alert_ids
    # Map account -> list of alert_ids, txn -> list of alert_ids
    acc_to_alerts: Dict[str, Set[str]] = defaultdict(set)
    txn_to_alerts: Dict[str, Set[str]] = defaultdict(set)

    for alr in alerts:
        for acc in alr.account_ids:
            acc_to_alerts[acc].add(alr.alert_id)
        for txn in alr.txn_ids:
            txn_to_alerts[txn].add(alr.alert_id)

    for alr in alerts:
        related: Set[str] = set()
        for acc in alr.account_ids:
            related.update(acc_to_alerts[acc])
        for txn in alr.txn_ids:
            related.update(txn_to_alerts[txn])
        related.discard(alr.alert_id)
        alr.related_alert_ids = sorted(list(related))

    # 2. Build rings using Union-Find
    uf = UnionFind()
    flagged_non_context_accs: Set[str] = set()

    for alr in alerts:
        if not alr.informational_only and alr.rule_id != "SHARED_DEVICE":
            accs = sorted(alr.account_ids)
            if accs:
                flagged_non_context_accs.update(accs)
                first_acc = accs[0]
                for other_acc in accs[1:]:
                    uf.union(first_acc, other_acc)

    # Union direct transaction connections between non-context flagged accounts
    if direct_edges_between_flagged:
        for u, v in direct_edges_between_flagged:
            if u in flagged_non_context_accs and v in flagged_non_context_accs:
                uf.union(u, v)

    # Group flagged accounts by component root
    comp_to_accs: Dict[str, Set[str]] = defaultdict(set)
    for acc in flagged_non_context_accs:
        root = uf.find(acc)
        comp_to_accs[root].add(acc)

    # Map account -> ring component root
    acc_to_root: Dict[str, str] = {acc: uf.find(acc) for acc in flagged_non_context_accs}

    # Find which alerts belong to each component
    comp_to_alerts: Dict[str, List[Alert]] = defaultdict(list)
    for alr in alerts:
        if not alr.informational_only and alr.rule_id != "SHARED_DEVICE":
            # Finding root of first account
            if alr.account_ids and alr.account_ids[0] in acc_to_root:
                root = acc_to_root[alr.account_ids[0]]
                comp_to_alerts[root].append(alr)
        else:
            # Informational / context alert (e.g. SHARED_DEVICE):
            # Attach to existing component if accounts overlap with that component
            attached = False
            for acc in alr.account_ids:
                if acc in acc_to_root:
                    root = acc_to_root[acc]
                    comp_to_alerts[root].append(alr)
                    attached = True
                    break

    # Determine priority and highest score for each component and sort them deterministically
    component_metas = []
    for root, accs in comp_to_accs.items():
        comp_alrs = comp_to_alerts.get(root, [])
        highest_p: PriorityLevel = "low"
        highest_s: float = 0.0
        for alr in comp_alrs:
            highest_p = higher_priority(highest_p, alr.priority)
            if alr.score > highest_s:
                highest_s = alr.score
        component_metas.append(
            {
                "root": root,
                "accounts": sorted(list(accs)),
                "alerts": sorted([a.alert_id for a in comp_alrs]),
                "highest_priority": highest_p,
                "highest_score": round(highest_s, 2),
            }
        )

    # Sort components: priority weight desc, highest score desc, size desc, root asc
    component_metas.sort(
        key=lambda c: (
            -PRIORITY_WEIGHT[c["highest_priority"]],
            -c["highest_score"],
            -len(c["accounts"]),
            c["root"],
        )
    )

    rings: List[Ring] = []
    alert_id_to_ring_id: Dict[str, str] = {}

    for idx, c in enumerate(component_metas, start=1):
        ring_id = f"RING-{idx:02d}"
        rings.append(
            Ring(
                ring_id=ring_id,
                account_ids=c["accounts"],
                alert_ids=c["alerts"],
                highest_priority=c["highest_priority"],
                highest_score=c["highest_score"],
            )
        )
        for a_id in c["alerts"]:
            if a_id not in alert_id_to_ring_id:
                alert_id_to_ring_id[a_id] = ring_id

    # Assign ring_id back to alerts
    for alr in alerts:
        alr.ring_id = alert_id_to_ring_id.get(alr.alert_id)

    # 3. Build Account Summaries
    all_flagged_accs: Set[str] = set()
    for alr in alerts:
        all_flagged_accs.update(alr.account_ids)

    account_summaries: List[AccountSummary] = []
    for acc in sorted(all_flagged_accs):
        acc_alerts = sorted(list(acc_to_alerts[acc]))
        acc_priority: PriorityLevel = "low"
        acc_score: float = 0.0
        for a_id in acc_alerts:
            # find alert
            for alr in alerts:
                if alr.alert_id == a_id:
                    acc_priority = higher_priority(acc_priority, alr.priority)
                    if alr.score > acc_score:
                        acc_score = alr.score
                    break

        account_summaries.append(
            AccountSummary(
                account_id=acc,
                alert_ids=acc_alerts,
                highest_priority=acc_priority,
                highest_score=round(acc_score, 2),
            )
        )

    return alerts, rings, account_summaries
