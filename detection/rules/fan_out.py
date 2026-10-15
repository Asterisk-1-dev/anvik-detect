"""Rule 8.3: Fan-Out Splitting detection."""

import logging
from datetime import timedelta
from typing import List, Set
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext
from detection.sliders import clamp, scale_down, scale_up

logger = logging.getLogger(__name__)


class FanOutSplittingRule(BaseRule):
    """Detects accounts receiving inbound funds split quickly into multiple outbound transfers of similar amounts."""

    rule_id = "FAN_OUT_SPLITTING"
    title = "Fan-out splitting"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.fan_out_splitting
        if not cfg.enabled:
            return []

        findings: List[RawFinding] = []
        succ = ctx.dataset.successful_txns
        if succ.empty:
            return []

        # Find all accounts receiving inbound transactions >= min_inbound_inr
        inbound_cands = succ[succ["amount_inr"] >= cfg.min_inbound_inr]
        recipient_accounts = sorted(inbound_cands["receiver_account_id"].unique())
        window_delta = timedelta(minutes=cfg.window_minutes)

        for acc in recipient_accounts:
            inbounds = ctx.features.get_inbound(acc)
            eligible_inbounds = inbounds[inbounds["amount_inr"] >= cfg.min_inbound_inr]
            outbounds = ctx.features.get_outbound(acc)

            if eligible_inbounds.empty or outbounds.empty:
                continue

            for _, in_row in eligible_inbounds.iterrows():
                in_time = in_row["timestamp"]
                in_amt = float(in_row["amount_inr"])
                in_txn_id = in_row["txn_id"]

                w_end = in_time + window_delta
                cand_out = outbounds[
                    (outbounds["timestamp"] > in_time) & (outbounds["timestamp"] <= w_end)
                ]

                if len(cand_out) < cfg.min_outgoing_count:
                    continue

                distinct_receivers = cand_out["receiver_account_id"].unique()
                if len(distinct_receivers) < cfg.min_distinct_receivers:
                    continue

                out_total = float(cand_out["amount_inr"].sum())
                forwarded_pct = (out_total / in_amt) * 100.0

                if forwarded_pct < cfg.min_forwarded_pct:
                    continue

                # Calculate amount spread: (max - min) / mean
                amounts = cand_out["amount_inr"].values
                amt_max = amounts.max()
                amt_min = amounts.min()
                amt_mean = amounts.mean()

                if amt_mean <= 0:
                    continue

                spread_pct = ((amt_max - amt_min) / amt_mean) * 100.0

                if spread_pct <= cfg.max_amount_spread_pct:
                    # Sliders calculation:
                    cfg_s = self.config.sliders.fan_out_splitting
                    s_pct = scale_up(forwarded_pct, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
                    s_spread = scale_down(spread_pct, cfg_s.amount_spread_pct.cutoff, cfg_s.amount_spread_pct.best)
                    s_cnt = scale_up(len(cand_out), cfg_s.outgoing_count.low, cfg_s.outgoing_count.high)
                    suspicion = (s_pct + s_spread + s_cnt) / 3.0

                    involved_accs = [acc] + sorted(list(distinct_receivers))
                    all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

                    evidence = {
                        "received_inr": round(in_amt, 2),
                        "outgoing_count": int(len(cand_out)),
                        "outgoing_total_inr": round(out_total, 2),
                        "distinct_receivers": int(len(distinct_receivers)),
                        "window_minutes": float(cfg.window_minutes),
                        "amount_spread_pct": round(spread_pct, 2),
                        "_sliders": {
                            "forwarded_pct": round(s_pct, 4),
                            "amount_spread_pct": round(s_spread, 4),
                            "outgoing_count": round(s_cnt, 4),
                        },
                        "_suspicion": suspicion,
                    }

                    all_txns = [in_txn_id] + list(cand_out["txn_id"])

                    findings.append(
                        RawFinding(
                            rule_id=self.rule_id,
                            account_ids=involved_accs,
                            vpas=all_vpas,
                            txn_ids=all_txns,
                            evidence=evidence,
                            strength=suspicion,
                            complaint_ids=[],
                            focal_account_ids=[acc],
                            informational_only=False,
                        )
                    )

        return findings
