"""Rule 8.2: Multi-Source Fan-In detection."""

import logging
from datetime import timedelta
from typing import List, Set, Tuple
import numpy as np
import pandas as pd
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_up

logger = logging.getLogger(__name__)


class MultiSourceFanInRule(BaseRule):
    """Detects accounts receiving inbound payments from many distinct, mostly first-time payers in a short window."""

    rule_id = "MULTI_SOURCE_FAN_IN"
    title = "Multi-source fan-in"

    def __init__(self, config: Config):
        super().__init__(config)
        self.warmup_skipped_occurred = False

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.multi_source_fan_in
        if not cfg.enabled:
            return []

        findings: List[RawFinding] = []
        succ = ctx.dataset.successful_txns
        if succ.empty:
            return []

        # Only PAY transactions are evaluated
        pay_txns = succ[succ["txn_type"] == "PAY"]
        if pay_txns.empty:
            return []

        dataset_first_tx = succ["timestamp"].min()
        dataset_last_tx = succ["timestamp"].max()
        warmup_delta = timedelta(days=cfg.warmup_days)
        has_warmup_period = (dataset_last_tx - dataset_first_tx) >= warmup_delta

        receiver_accounts = sorted(pay_txns["receiver_account_id"].unique())
        window_delta = timedelta(minutes=cfg.window_minutes)

        for receiver_id in receiver_accounts:
            rx_txns = pay_txns[pay_txns["receiver_account_id"] == receiver_id].sort_values(
                by=["timestamp", "txn_id"]
            ).reset_index(drop=True)

            if len(rx_txns) < cfg.min_distinct_senders:
                continue

            # Slide window over inbound transactions
            # Merge overlapping windows into one finding, reporting the highest distinct-sender window
            candidate_windows = []

            for i in range(len(rx_txns)):
                w_start = rx_txns.iloc[i]["timestamp"]
                w_end = w_start + window_delta

                # Warmup guard: skip findings whose window starts before dataset_first_transaction + warmup_days
                if has_warmup_period and w_start < dataset_first_tx + warmup_delta:
                    self.warmup_skipped_occurred = True
                    continue

                in_window = rx_txns[(rx_txns["timestamp"] >= w_start) & (rx_txns["timestamp"] <= w_end)]
                distinct_senders = in_window["sender_account_id"].unique()
                cnt_senders = len(distinct_senders)

                if cnt_senders >= cfg.min_distinct_senders:
                    # Check first-time status: no earlier SUCCESS transaction to this receiver in full history
                    first_time_count = 0
                    repeat_count = 0
                    for s_id in distinct_senders:
                        prior_txns = succ[
                            (succ["sender_account_id"] == s_id)
                            & (succ["receiver_account_id"] == receiver_id)
                            & (succ["timestamp"] < w_start)
                        ]
                        if prior_txns.empty:
                            first_time_count += 1
                        else:
                            repeat_count += 1

                    first_time_share = first_time_count / cnt_senders

                    # Own-history baseline guard:
                    # Compute the account's median daily distinct-sender count over its prior active days
                    prior_inbounds = pay_txns[
                        (pay_txns["receiver_account_id"] == receiver_id)
                        & (pay_txns["timestamp"] < w_start)
                    ]
                    if not prior_inbounds.empty:
                        prior_days_txns = prior_inbounds[prior_inbounds["timestamp"].dt.date < w_start.date()]
                        if not prior_days_txns.empty:
                            daily_sender_counts = (
                                prior_days_txns.groupby(prior_days_txns["timestamp"].dt.date)["sender_account_id"]
                                .nunique()
                                .tolist()
                            )
                            if len(daily_sender_counts) >= cfg.baseline_min_prior_active_days:
                                baseline = float(pd.Series(daily_sender_counts).median())
                                if cnt_senders < cfg.baseline_multiplier * baseline:
                                    logger.debug(
                                        f"Suppressing fan-in for {receiver_id}: {cnt_senders} senders < "
                                        f"{cfg.baseline_multiplier} * baseline {baseline}"
                                    )
                                    continue

                    if first_time_share >= cfg.min_first_time_sender_share:
                        candidate_windows.append(
                            {
                                "start": w_start,
                                "end": w_end,
                                "distinct_senders": cnt_senders,
                                "first_time_senders": first_time_count,
                                "first_time_share": first_time_share,
                                "txns": in_window,
                                "senders": list(distinct_senders),
                            }
                        )

            if not candidate_windows:
                continue

            # Merge overlapping windows
            # Sort candidate windows by start time
            candidate_windows.sort(key=lambda w: w["start"])
            merged_clusters: List[List[dict]] = []
            for w in candidate_windows:
                if not merged_clusters:
                    merged_clusters.append([w])
                else:
                    last_cluster = merged_clusters[-1]
                    # Check overlap with cluster's max end time
                    cluster_end = max(cw["end"] for cw in last_cluster)
                    if w["start"] <= cluster_end:
                        last_cluster.append(w)
                    else:
                        merged_clusters.append([w])

            # For each cluster, pick the window with the highest distinct_senders, list all supporting txn_ids
            for cluster in merged_clusters:
                best_win = max(cluster, key=lambda w: (w["distinct_senders"], w["first_time_share"]))
                all_txns_in_cluster = pd.concat([w["txns"] for w in cluster]).drop_duplicates(subset=["txn_id"])
                all_txns_in_cluster = all_txns_in_cluster.sort_values(by=["timestamp", "txn_id"])

                all_senders = sorted(list(all_txns_in_cluster["sender_account_id"].unique()))
                involved_accs = [receiver_id] + all_senders
                all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

                total_amt = float(all_txns_in_cluster["amount_inr"].sum())

                # Slider-based suspicion formula
                cfg_s = self.config.sliders.multi_source_fan_in
                s_senders = scale_up(best_win["distinct_senders"], cfg_s.distinct_senders.low, cfg_s.distinct_senders.high)
                s_first_time = scale_up(best_win["first_time_share"], cfg_s.first_time_share.low, cfg_s.first_time_share.high)
                suspicion = cfg_s.mix.count * s_senders + cfg_s.mix.strangers * s_first_time

                evidence = {
                    "distinct_senders": int(best_win["distinct_senders"]),
                    "first_time_senders": int(best_win["first_time_senders"]),
                    "first_time_share": round(float(best_win["first_time_share"]), 4),
                    "window_minutes": float(cfg.window_minutes),
                    "total_received_inr": round(total_amt, 2),
                    "window_start": best_win["start"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "window_end": best_win["end"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "_sliders": {
                        "distinct_senders": round(s_senders, 4),
                        "first_time_share": round(s_first_time, 4),
                    },
                    "_suspicion": suspicion,
                }

                findings.append(
                    RawFinding(
                        rule_id=self.rule_id,
                        account_ids=involved_accs,
                        vpas=all_vpas,
                        txn_ids=list(all_txns_in_cluster["txn_id"]),
                        evidence=evidence,
                        strength=suspicion,
                        complaint_ids=[],
                        focal_account_ids=[receiver_id],
                        informational_only=False,
                    )
                )

        return findings
