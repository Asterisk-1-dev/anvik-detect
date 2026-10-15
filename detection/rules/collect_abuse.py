"""Rule 8.7: Collect Request Abuse detection."""

import logging
from datetime import timedelta
from typing import List, Set
import pandas as pd
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_up

logger = logging.getLogger(__name__)


class CollectRequestAbuseRule(BaseRule):
    """Detects accounts initiating excessive COLLECT requests to multiple distinct counterparties in a short window."""

    rule_id = "COLLECT_REQUEST_ABUSE"
    title = "Collect request abuse"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.collect_request_abuse
        if not cfg.enabled:
            return []

        all_txns = ctx.dataset.transactions
        if all_txns.empty:
            return []

        findings: List[RawFinding] = []
        window_delta = timedelta(minutes=cfg.window_minutes)

        # In UPI COLLECT transactions, the party requesting funds is the receiver
        # (per collect_initiator: receiver in config). Money flows sender -> receiver.
        # Check collect requests
        if cfg.include_failed_in_attempts:
            eligible_collects = all_txns[
                (all_txns["txn_type"] == "COLLECT")
                & (all_txns["status"].isin(["SUCCESS", "FAILED"]))
            ]
        else:
            eligible_collects = all_txns[
                (all_txns["txn_type"] == "COLLECT") & (all_txns["status"] == "SUCCESS")
            ]

        if eligible_collects.empty:
            return []

        initiator_accounts = sorted(eligible_collects["receiver_account_id"].unique())

        for init_acc in initiator_accounts:
            c_txns = (
                eligible_collects[eligible_collects["receiver_account_id"] == init_acc]
                .sort_values(by=["timestamp", "txn_id"])
                .reset_index(drop=True)
            )

            if len(c_txns) < cfg.min_collect_txns:
                continue

            # Slide window over collect requests
            candidate_windows = []
            for i in range(len(c_txns)):
                w_start = c_txns.iloc[i]["timestamp"]
                w_end = w_start + window_delta

                in_window = c_txns[
                    (c_txns["timestamp"] >= w_start) & (c_txns["timestamp"] <= w_end)
                ]

                distinct_payers = in_window["sender_account_id"].unique()
                cnt_payers = len(distinct_payers)

                if len(in_window) >= cfg.min_collect_txns and cnt_payers >= cfg.min_distinct_payers:
                    # Inbound share check: collect requests vs total inbound transactions to init_acc in that window
                    all_inbound = all_txns[
                        (all_txns["receiver_account_id"] == init_acc)
                        & (all_txns["timestamp"] >= w_start)
                        & (all_txns["timestamp"] <= w_end)
                    ]
                    collect_share = len(in_window) / max(1, len(all_inbound))

                    if collect_share >= cfg.min_collect_share_of_inbound:
                        candidate_windows.append(
                            {
                                "start": w_start,
                                "end": w_end,
                                "collect_count": len(in_window),
                                "distinct_payers": cnt_payers,
                                "collect_share": collect_share,
                                "txns": in_window,
                            }
                        )

            if not candidate_windows:
                continue

            # Pick the window with the highest collect_count
            best_win = max(
                candidate_windows,
                key=lambda w: (w["collect_count"], w["distinct_payers"], w["collect_share"]),
            )

            best_txns = best_win["txns"]
            succ_count = int((best_txns["status"] == "SUCCESS").sum())
            fail_count = int((best_txns["status"] == "FAILED").sum())
            distinct_payer_ids = sorted(list(best_txns["sender_account_id"].unique()))

            # Check first-time payers
            first_time_count = 0
            for p_id in distinct_payer_ids:
                prior = all_txns[
                    (all_txns["sender_account_id"] == p_id)
                    & (all_txns["receiver_account_id"] == init_acc)
                    & (all_txns["timestamp"] < best_win["start"])
                ]
                if prior.empty:
                    first_time_count += 1

            # Slider suspicion formula
            cfg_s = self.config.sliders.collect_request_abuse
            s_req = scale_up(best_win["collect_count"], cfg_s.requests.low, cfg_s.requests.high)
            s_payers = scale_up(best_win["distinct_payers"], cfg_s.distinct_payers.low, cfg_s.distinct_payers.high)
            suspicion = (s_req + s_payers) / 2.0

            failed_share = round((fail_count / max(1, len(best_txns))) * 100.0, 2)

            involved_accs = [init_acc] + distinct_payer_ids
            all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

            evidence = {
                "collect_requests": int(best_win["collect_count"]),
                "successful_collects": succ_count,
                "failed_collects": fail_count,
                "failed_share_pct": failed_share,
                "distinct_payers": int(best_win["distinct_payers"]),
                "first_time_payers": first_time_count,
                "collect_share_pct": round(float(best_win["collect_share"]) * 100.0, 2),
                "window_minutes": float(cfg.window_minutes),
                "_sliders": {
                    "requests": round(s_req, 4),
                    "distinct_payers": round(s_payers, 4),
                },
                "_suspicion": suspicion,
            }

            findings.append(
                RawFinding(
                    rule_id=self.rule_id,
                    account_ids=involved_accs,
                    vpas=all_vpas,
                    txn_ids=list(best_txns["txn_id"]),
                    evidence=evidence,
                    strength=suspicion,
                    complaint_ids=[],
                    focal_account_ids=[init_acc],
                    informational_only=False,
                )
            )

        return findings
