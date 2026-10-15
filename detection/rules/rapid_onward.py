"""Rule 8.1: Rapid Onward Transfer detection."""

import logging
from datetime import timedelta
from typing import List, Set
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_down, scale_up

logger = logging.getLogger(__name__)


class RapidOnwardTransferRule(BaseRule):
    """Detects accounts that receive funds and forward the majority of them within minutes."""

    rule_id = "RAPID_ONWARD_TRANSFER"
    title = "Rapid onward transfer"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.rapid_onward_transfer
        if not cfg.enabled:
            return []

        findings: List[RawFinding] = []
        # Examine each account with inbound transactions
        succ = ctx.dataset.successful_txns
        if succ.empty:
            return []

        # Find all accounts that received inbound SUCCESS txns >= min_inbound_inr
        inbound_cands = succ[succ["amount_inr"] >= cfg.min_inbound_inr]
        recipient_accounts = sorted(inbound_cands["receiver_account_id"].unique())

        for acc in recipient_accounts:
            inbounds = ctx.features.get_inbound(acc)
            eligible_inbounds = inbounds[inbounds["amount_inr"] >= cfg.min_inbound_inr]
            outbounds = ctx.features.get_outbound(acc)

            if eligible_inbounds.empty or outbounds.empty:
                continue

            used_outbound_txn_ids: Set[str] = set()

            for _, in_row in eligible_inbounds.iterrows():
                in_txn_id = in_row["txn_id"]
                in_time = in_row["timestamp"]
                in_amt = float(in_row["amount_inr"])
                in_sender_acc = in_row["sender_account_id"]

                window_end = in_time + timedelta(minutes=cfg.max_gap_minutes)

                # Look for outbound transactions in (in_time, window_end]
                cand_out = outbounds[
                    (outbounds["timestamp"] > in_time)
                    & (outbounds["timestamp"] <= window_end)
                    & (~outbounds["txn_id"].isin(used_outbound_txn_ids))
                ]

                if cand_out.empty:
                    continue

                matched_out_ids: List[str] = []
                matched_receivers: List[str] = []
                matched_out_total = 0.0
                last_matched_time = in_time

                for _, out_row in cand_out.iterrows():
                    out_txn_id = out_row["txn_id"]
                    out_receiver_acc = out_row["receiver_account_id"]
                    out_amt = float(out_row["amount_inr"])
                    out_time = out_row["timestamp"]

                    # Guard 1: exclude return to sender (refund)
                    if cfg.exclude_return_to_sender and out_receiver_acc == in_sender_acc:
                        continue

                    # Guard 2: recurring counterparty check
                    prior_count = ctx.features.count_prior_outbound(acc, out_receiver_acc, in_time)
                    if prior_count >= cfg.recurring_counterparty_min_prior_txns:
                        continue

                    # Match this outbound
                    matched_out_ids.append(out_txn_id)
                    matched_receivers.append(out_receiver_acc)
                    matched_out_total += out_amt
                    last_matched_time = out_time

                if not matched_out_ids:
                    continue

                forwarded_pct = min(100.0, (matched_out_total / in_amt) * 100.0)
                if forwarded_pct >= cfg.min_forwarded_pct:
                    # Mark outbounds as matched so they aren't attributed to another inbound
                    used_outbound_txn_ids.update(matched_out_ids)

                    gap_minutes = (last_matched_time - in_time).total_seconds() / 60.0

                    # Compute suspicion from sliders:
                    cfg_s = self.config.sliders.rapid_onward_transfer
                    s_pct = scale_up(forwarded_pct, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
                    s_gap = scale_down(gap_minutes, cfg_s.gap_minutes.cutoff, cfg_s.gap_minutes.best)
                    suspicion = (s_pct + s_gap) / 2.0

                    # Gather involved account IDs and VPAs
                    all_involved_accs = [acc] + sorted(list(set(matched_receivers)))
                    all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in all_involved_accs]

                    evidence = {
                        "received_inr": round(in_amt, 2),
                        "forwarded_inr": round(matched_out_total, 2),
                        "forwarded_pct": round(forwarded_pct, 2),
                        "gap_minutes": round(gap_minutes, 2),
                        "inbound_txn_id": in_txn_id,
                        "outbound_txn_ids": matched_out_ids,
                        "outbound_receivers": sorted(list(set(matched_receivers))),
                        "_sliders": {
                            "forwarded_pct": round(s_pct, 4),
                            "gap_minutes": round(s_gap, 4),
                        },
                        "_suspicion": suspicion,
                    }

                    # Collect supporting txns in time order
                    all_txn_ids = [in_txn_id] + matched_out_ids

                    findings.append(
                        RawFinding(
                            rule_id=self.rule_id,
                            account_ids=all_involved_accs,
                            vpas=all_vpas,
                            txn_ids=all_txn_ids,
                            evidence=evidence,
                            strength=suspicion,
                            complaint_ids=[],
                            focal_account_ids=[acc],
                            informational_only=False,
                        )
                    )

        return findings
