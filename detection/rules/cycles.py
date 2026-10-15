"""Rule 8.4: Transaction Cycle detection (bounded DFS with topological pruning)."""

import logging
from datetime import timedelta
from typing import Dict, List, Set, Tuple
import networkx as nx
import pandas as pd
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_down, scale_up

logger = logging.getLogger(__name__)


def canonical_rotation(cycle: List[str]) -> Tuple[str, ...]:
    """Return the lexicographically smallest rotation of a cycle."""
    n = len(cycle)
    rotations = [cycle[i:] + cycle[:i] for i in range(n)]
    return tuple(min(rotations))


class TransactionCycleRule(BaseRule):
    """Detects closed circular money flows (A -> B -> C -> A) within a short time span and with similar amounts."""

    rule_id = "TRANSACTION_CYCLE"
    title = "Transaction cycle"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.transaction_cycle
        if not cfg.enabled:
            return []

        succ = ctx.dataset.successful_txns
        if succ.empty:
            return []

        # Filter transactions meeting min_amount_inr
        filtered_txns = succ[succ["amount_inr"] >= cfg.min_amount_inr]
        if filtered_txns.empty:
            return []

        # Build aggregated DiGraph for candidate topology pruning
        agg_graph = nx.DiGraph()
        for _, row in filtered_txns.iterrows():
            u = row["sender_account_id"]
            v = row["receiver_account_id"]
            if agg_graph.has_edge(u, v):
                agg_graph[u][v]["count"] += 1
            else:
                agg_graph.add_edge(u, v, count=1)

        # Strongly connected components with >= min_length nodes
        sccs = [scc for scc in nx.strongly_connected_components(agg_graph) if len(scc) >= cfg.min_length]
        if not sccs:
            return []

        max_span_delta = timedelta(hours=cfg.max_span_hours)

        # Pre-group filtered transactions by sender and receiver pair for fast edge lookup
        pair_txns: Dict[Tuple[str, str], List[dict]] = {}
        for _, r in filtered_txns.iterrows():
            pair = (r["sender_account_id"], r["receiver_account_id"])
            if pair not in pair_txns:
                pair_txns[pair] = []
            pair_txns[pair].append(
                {
                    "txn_id": r["txn_id"],
                    "timestamp": r["timestamp"],
                    "amount_inr": float(r["amount_inr"]),
                }
            )

        # Find simple cycles bounded by [min_length, max_length] within SCCs
        seen_canonical: Set[Tuple[str, ...]] = set()
        valid_cycle_findings: List[RawFinding] = []

        for scc in sccs:
            subgraph = agg_graph.subgraph(scc)
            # Find bounded simple cycles
            # Use bounded DFS from each node in the SCC
            nodes_list = sorted(list(scc))
            for start_node in nodes_list:
                # DFS state: (current_node, path, visited_set)
                stack = [(start_node, [start_node], {start_node})]
                while stack:
                    curr, path, visited = stack.pop()
                    length = len(path)

                    for neighbor in subgraph.successors(curr):
                        if neighbor == start_node and length >= cfg.min_length:
                            # Found cycle candidate
                            canon = canonical_rotation(path)
                            if canon not in seen_canonical:
                                seen_canonical.add(canon)
                                # Validate time-respecting transactions along the cycle
                                res = self._validate_cycle_transactions(
                                    path, pair_txns, max_span_delta, cfg.min_amount_similarity
                                )
                                if res is not None:
                                    ordered_txns, span_minutes, similarity_pct, strength, sliders = res
                                    involved_accs = list(path)
                                    all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

                                    evidence = {
                                        "cycle_accounts": involved_accs,
                                        "cycle_length": len(path),
                                        "total_span_minutes": round(span_minutes, 2),
                                        "amount_similarity_pct": round(similarity_pct, 2),
                                        "cycle_txn_ids": ordered_txns,
                                        "_sliders": sliders,
                                        "_suspicion": strength,
                                    }

                                    finding = RawFinding(
                                        rule_id=self.rule_id,
                                        account_ids=involved_accs,
                                        vpas=all_vpas,
                                        txn_ids=ordered_txns,
                                        evidence=evidence,
                                        strength=strength,
                                        complaint_ids=[],
                                        focal_account_ids=involved_accs,
                                        informational_only=False,
                                    )
                                    valid_cycle_findings.append(finding)
                        elif neighbor not in visited and length < cfg.max_length:
                            stack.append((neighbor, path + [neighbor], visited | {neighbor}))

        # Cap at max_cycles_reported, keeping the highest strength
        valid_cycle_findings.sort(key=lambda f: -f.strength)
        return valid_cycle_findings[: cfg.max_cycles_reported]

    def _validate_cycle_transactions(
        self,
        cycle_nodes: List[str],
        pair_txns: Dict[Tuple[str, str], List[dict]],
        max_span: timedelta,
        min_similarity: float,
    ) -> Tuple[List[str], float, float, float] | None:
        """Find a sequence of time-respecting transactions along the cycle satisfying amount similarity and span."""
        n = len(cycle_nodes)
        hops = [(cycle_nodes[i], cycle_nodes[(i + 1) % n]) for i in range(n)]

        # Each hop must have at least one transaction
        for hop in hops:
            if hop not in pair_txns or not pair_txns[hop]:
                return None

        # Search for a sequence of txns (t_0, t_1, ..., t_{n-1}) such that:
        # t_0.timestamp < t_1.timestamp < ... < t_{n-1}.timestamp
        # t_{n-1}.timestamp - t_0.timestamp <= max_span
        # min(amounts) / max(amounts) >= min_similarity

        # Recursive search over hops
        best_match = None

        def search_hop(hop_idx: int, prev_time, chosen_txns):
            nonlocal best_match
            if best_match is not None:
                return  # One valid time-respecting sequence per cycle is sufficient

            if hop_idx == n:
                # Check span and similarity
                start_time = chosen_txns[0]["timestamp"]
                end_time = chosen_txns[-1]["timestamp"]
                span = end_time - start_time
                if span <= max_span:
                    amts = [tx["amount_inr"] for tx in chosen_txns]
                    sim = min(amts) / max(amts)
                    if sim >= min_similarity:
                        span_mins = span.total_seconds() / 60.0
                        span_hours = span_mins / 60.0
                        cfg_s = self.config.sliders.transaction_cycle
                        s_sim = scale_up(sim, cfg_s.amount_similarity.low, cfg_s.amount_similarity.high)
                        s_span = scale_down(span_hours, cfg_s.span_hours.cutoff, cfg_s.span_hours.best)
                        suspicion = (s_sim + s_span) / 2.0
                        best_match = (
                            [tx["txn_id"] for tx in chosen_txns],
                            span_mins,
                            sim * 100.0,
                            suspicion,
                            {"amount_similarity": round(s_sim, 4), "span_hours": round(s_span, 4)},
                        )
                return

            hop_pair = hops[hop_idx]
            for tx in pair_txns[hop_pair]:
                if prev_time is None or tx["timestamp"] > prev_time:
                    search_hop(hop_idx + 1, tx["timestamp"], chosen_txns + [tx])

        search_hop(0, None, [])
        return best_match
