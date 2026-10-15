"""Rule 8.5: Complaint Convergence (Money-trail tracing)."""

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Set, Tuple
import pandas as pd
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_down, scale_up

logger = logging.getLogger(__name__)


class ComplaintConvergenceRule(BaseRule):
    """Traces funds downstream from complained-about transactions using proportional tracing.

    Fires when an account is reached by traces originating from >= min_converging_complaints
    different complaints.
    """

    rule_id = "COMPLAINT_CONVERGENCE"
    title = "Complaint convergence"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.complaint_convergence
        if not cfg.enabled:
            return []

        if ctx.dataset.complaints.empty or len(ctx.dataset.complaints) == 0:
            logger.info("Skipping COMPLAINT_CONVERGENCE: complaints dataset is empty")
            return []

        findings: List[RawFinding] = []
        succ = ctx.dataset.successful_txns
        if succ.empty:
            return []

        # Map txn_id to transaction row
        succ_by_txn = {row["txn_id"]: row for _, row in succ.iterrows()}

        # Data structure: reached_accounts[account_id][complaint_id] = list of paths
        # path = {"path": [acc_ids], "txns": [txn_ids], "traced_inr": float, "hops": int}
        reached_by_complaint: Dict[str, Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))
        # Track still_held_inr per (account_id, complaint_id)
        held_by_complaint: Dict[str, float] = defaultdict(float)

        window_delta = timedelta(hours=cfg.trace_window_hours)

        # Trace each complaint
        for _, comp_row in ctx.dataset.complaints.iterrows():
            comp_id = comp_row["complaint_id"]
            seed_txn_id = comp_row["txn_id"]

            if seed_txn_id not in succ_by_txn:
                continue

            seed_txn = succ_by_txn[seed_txn_id]
            seed_receiver = seed_txn["receiver_account_id"]
            seed_time = seed_txn["timestamp"]
            seed_amt = float(seed_txn["amount_inr"])

            if seed_amt < cfg.min_traced_amount_inr:
                continue

            # Queue of parcels to trace forward:
            # (current_acc, arrival_time, traced_remaining, current_path_accs, current_path_txns, hop)
            queue = [
                (
                    seed_receiver,
                    seed_time,
                    seed_amt,
                    [seed_receiver],
                    [seed_txn_id],
                    1,
                )
            ]

            while queue:
                curr_acc, arr_time, traced_rem, path_accs, path_txns, hop = queue.pop(0)

                # Record reaching curr_acc
                reached_by_complaint[curr_acc][comp_id].append(
                    {
                        "path": path_accs,
                        "txns": path_txns,
                        "traced_inr": traced_rem,
                        "hops": hop,
                    }
                )

                if hop >= cfg.max_hops:
                    held_by_complaint[curr_acc] += traced_rem
                    continue

                # Find outbound transactions in (arr_time, arr_time + window_delta]
                outbounds = ctx.features.get_outbound(curr_acc)
                cands = outbounds[
                    (outbounds["timestamp"] > arr_time)
                    & (outbounds["timestamp"] <= arr_time + window_delta)
                ]

                if cands.empty:
                    held_by_complaint[curr_acc] += traced_rem
                    continue

                total_out_in_window = float(cands["amount_inr"].sum())
                if total_out_in_window <= 0:
                    held_by_complaint[curr_acc] += traced_rem
                    continue

                # Proportional tracing: each outbound takes (cand.amount / total_out_in_window) * traced_rem
                # or min(txn.amount, remaining)
                forwarded_from_parcel = 0.0
                for _, out_row in cands.iterrows():
                    out_amt = float(out_row["amount_inr"])
                    out_txn_id = out_row["txn_id"]
                    out_next_acc = out_row["receiver_account_id"]
                    out_time = out_row["timestamp"]

                    if out_next_acc in path_accs:
                        # Prevent simple cycle loops in tracing
                        continue

                    # Proportion of this outbound relative to total outbound window
                    share = out_amt / total_out_in_window
                    traced_next = traced_rem * share

                    if traced_next >= cfg.min_traced_amount_inr:
                        forwarded_from_parcel += traced_next
                        queue.append(
                            (
                                out_next_acc,
                                out_time,
                                traced_next,
                                path_accs + [out_next_acc],
                                path_txns + [out_txn_id],
                                hop + 1,
                            )
                        )

                unforwarded = max(0.0, traced_rem - forwarded_from_parcel)
                if unforwarded > 0:
                    held_by_complaint[curr_acc] += unforwarded

        # Check convergence on accounts
        for acc_id, complaints_dict in reached_by_complaint.items():
            num_complaints = len(complaints_dict)
            if num_complaints >= cfg.min_converging_complaints:
                # Build trails and collect all txns and involved accounts
                all_trails = []
                all_txns_set: Set[str] = set()
                all_accs_set: Set[str] = {acc_id}
                total_traced = 0.0
                max_hops_observed = 0

                for c_id, path_list in complaints_dict.items():
                    for p in path_list:
                        all_trails.append(
                            {
                                "complaint_id": c_id,
                                "path": p["path"],
                                "txn_ids": p["txns"],
                                "traced_inr": round(p["traced_inr"], 2),
                                "hops": p["hops"],
                            }
                        )
                        total_traced += p["traced_inr"]
                        all_txns_set.update(p["txns"])
                        all_accs_set.update(p["path"])
                        if p["hops"] > max_hops_observed:
                            max_hops_observed = p["hops"]

                # Calculate avg_hops: mean of minimum hops for each converging complaint
                hops_per_complaint = [
                    min(p["hops"] for p in path_list)
                    for path_list in complaints_dict.values()
                ]
                avg_hops = sum(hops_per_complaint) / max(1, len(hops_per_complaint))

                # Sliders suspicion calculation
                cfg_s = self.config.sliders.complaint_convergence
                s_comp = scale_up(num_complaints, cfg_s.complaints.low, cfg_s.complaints.high)
                s_amt = scale_up(total_traced, cfg_s.traced_inr.low, cfg_s.traced_inr.high)
                s_hops = scale_down(avg_hops, cfg_s.avg_hops.cutoff, cfg_s.avg_hops.best)
                suspicion = (s_comp + s_amt + s_hops) / 3.0

                involved_accs = [acc_id] + sorted(list(all_accs_set - {acc_id}))
                all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

                # Reported total INR across the seed complaints
                reported_total = 0.0
                for c_id in complaints_dict.keys():
                    comp_txns = ctx.dataset.complaints[ctx.dataset.complaints["complaint_id"] == c_id]
                    for _, crow in comp_txns.iterrows():
                        if crow["txn_id"] in succ_by_txn:
                            reported_total += float(succ_by_txn[crow["txn_id"]]["amount_inr"])

                evidence = {
                    "complaints_converging": num_complaints,
                    "complaint_ids": sorted(list(complaints_dict.keys())),
                    "max_hops": max_hops_observed,
                    "avg_hops": round(avg_hops, 2),
                    "reported_total_inr": round(reported_total, 2),
                    "traced_total_inr": round(total_traced, 2),
                    "still_held_inr": round(held_by_complaint.get(acc_id, 0.0), 2),
                    "trails": all_trails,
                    "_sliders": {
                        "complaints": round(s_comp, 4),
                        "traced_inr": round(s_amt, 4),
                        "avg_hops": round(s_hops, 4),
                    },
                    "_suspicion": suspicion,
                }

                findings.append(
                    RawFinding(
                        rule_id=self.rule_id,
                        account_ids=involved_accs,
                        vpas=all_vpas,
                        txn_ids=sorted(list(all_txns_set)),
                        evidence=evidence,
                        strength=suspicion,
                        complaint_ids=sorted(list(complaints_dict.keys())),
                        focal_account_ids=[acc_id],
                        informational_only=False,
                    )
                )

        return findings
