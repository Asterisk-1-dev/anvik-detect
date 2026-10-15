"""Rule 8.6: New Account Burst detection."""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set
import numpy as np
import pandas as pd
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_up

logger = logging.getLogger(__name__)


class NewAccountBurstRule(BaseRule):
    """Detects recently created accounts showing a sudden spike in daily transaction volume."""

    rule_id = "NEW_ACCOUNT_BURST"
    title = "New account burst"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.new_account_burst
        if not cfg.enabled:
            return []

        succ = ctx.dataset.successful_txns
        if succ.empty or ctx.dataset.accounts.empty:
            return []

        findings: List[RawFinding] = []

        # Parse account creation dates
        # accounts: account_id, holder_name, vpa, bank, created_at
        acc_created_at: Dict[str, pd.Timestamp] = {}
        for _, row in ctx.dataset.accounts.iterrows():
            a_id = row["account_id"]
            dt_str = row["created_at"]
            try:
                parsed_dt = pd.to_datetime(dt_str)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.tz_localize("UTC")
                else:
                    parsed_dt = parsed_dt.tz_convert("UTC")
                acc_created_at[a_id] = parsed_dt
            except Exception:
                continue

        # Extract activity day (YYYY-MM-DD) for each successful transaction
        # An active account on a day participates as sender or receiver
        # Compute daily transaction counts per active account in the dataset to find the baseline median
        succ_with_day = succ.copy()
        succ_with_day["date_str"] = succ_with_day["timestamp"].dt.strftime("%Y-%m-%d")

        # Combine sender and receiver daily counts
        sender_counts = (
            succ_with_day.groupby(["sender_account_id", "date_str"])
            .size()
            .reset_index(name="count")
            .rename(columns={"sender_account_id": "account_id"})
        )
        receiver_counts = (
            succ_with_day.groupby(["receiver_account_id", "date_str"])
            .size()
            .reset_index(name="count")
            .rename(columns={"receiver_account_id": "account_id"})
        )
        daily_counts = (
            pd.concat([sender_counts, receiver_counts])
            .groupby(["account_id", "date_str"])["count"]
            .sum()
            .reset_index()
        )

        if daily_counts.empty:
            return []

        # Baseline median daily count across active accounts in the dataset
        median_daily = float(daily_counts["count"].median())
        # Avoid zero or degenerate median
        effective_median = max(1.0, median_daily)

        # Check each account's active days
        for acc_id, group in daily_counts.groupby("account_id"):
            if acc_id not in acc_created_at:
                continue

            created_dt = acc_created_at[acc_id]

            # Get all transaction dates for dormancy check
            all_active_dates = sorted(pd.to_datetime(group["date_str"]).dt.tz_localize("UTC"))

            for _, row in group.iterrows():
                day_str = row["date_str"]
                day_cnt = int(row["count"])

                day_dt = pd.to_datetime(day_str).tz_localize("UTC")
                age_days = (day_dt - created_dt).days

                # Account age check
                if 0 <= age_days <= cfg.max_account_age_days:
                    # Burst checks:
                    # 1. day_cnt >= min_txns_in_day
                    # 2. day_cnt >= burst_multiplier_vs_median * effective_median
                    threshold_mult = cfg.burst_multiplier_vs_median * effective_median
                    if day_cnt >= cfg.min_txns_in_day and day_cnt >= threshold_mult:
                        # Dormancy check: days of inactivity between creation (or previous active day) and this burst
                        prior_active = [d for d in all_active_dates if d < day_dt]
                        if prior_active:
                            last_active = max(prior_active)
                            dormant_days = (day_dt - last_active).days
                        else:
                            dormant_days = (day_dt - created_dt).days

                        is_dormant = dormant_days >= cfg.dormant_days

                        # Compute suspicion from sliders:
                        spike_multiple = day_cnt / effective_median
                        cfg_s = self.config.sliders.new_account_burst
                        s_spike = scale_up(spike_multiple, cfg_s.spike_multiple.low, cfg_s.spike_multiple.high)
                        dormant_bonus = cfg_s.dormant_bonus if is_dormant else 0.0
                        suspicion = clamp(s_spike + dormant_bonus)

                        # Collect supporting txn_ids for this account on this date
                        day_txns = succ_with_day[
                            (succ_with_day["date_str"] == day_str)
                            & (
                                (succ_with_day["sender_account_id"] == acc_id)
                                | (succ_with_day["receiver_account_id"] == acc_id)
                            )
                        ]

                        evidence = {
                            "account_age_days": age_days,
                            "transactions_in_day": day_cnt,
                            "typical_daily_transactions": round(effective_median, 2),
                            "spike_multiple": round(spike_multiple, 2),
                            "day": day_str,
                            "dormant_days_before": dormant_days if is_dormant else 0,
                            "_sliders": {
                                "spike_multiple": round(s_spike, 4),
                            },
                            "_suspicion": suspicion,
                        }

                        findings.append(
                            RawFinding(
                                rule_id=self.rule_id,
                                account_ids=[acc_id],
                                vpas=[ctx.dataset.account_to_vpa.get(acc_id, "")],
                                txn_ids=list(day_txns["txn_id"]),
                                evidence=evidence,
                                strength=suspicion,
                                complaint_ids=[],
                                focal_account_ids=[acc_id],
                                informational_only=False,
                            )
                        )

        return findings
