"""Comprehensive tests for scoring v2.0 math, sliders, escalation, and rules."""

import json
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from detection.config import Config, load_config
from detection.engine import run_detection
from detection.rules.base import RawFinding
from detection.scoring import Scorer
from detection.sliders import clamp, scale_down, scale_up
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


# ---------------- 1. Helper tests for clamp, scale_up, scale_down ----------------

def test_clamp_helper():
    assert clamp(0.5) == 0.5
    assert clamp(-0.2) == 0.0
    assert clamp(1.5) == 1.0
    assert clamp(0.0) == 0.0
    assert clamp(1.0) == 1.0
    assert clamp(5, lo=2, hi=8) == 5.0
    assert clamp(1, lo=2, hi=8) == 2.0
    assert clamp(10, lo=2, hi=8) == 8.0


def test_scale_up_helper():
    # 0.0 at low, 1.0 at high, linear between
    assert scale_up(80, 80, 100) == 0.0
    assert scale_up(100, 80, 100) == 1.0
    assert scale_up(90, 80, 100) == 0.5
    # Below low
    assert scale_up(70, 80, 100) == 0.0
    # Above high
    assert scale_up(110, 80, 100) == 1.0
    # Equal bounds raise ValueError
    with pytest.raises(ValueError, match="cannot equal high"):
        scale_up(50, 50, 50)


def test_scale_down_helper():
    # 0.0 at cutoff, 1.0 at best (best < cutoff), linear between
    assert scale_down(15, 15, 0) == 0.0
    assert scale_down(0, 15, 0) == 1.0
    assert scale_down(7.5, 15, 0) == 0.5
    # Above cutoff (worse than cutoff)
    assert scale_down(20, 15, 0) == 0.0
    # Below best (better than best)
    assert scale_down(-5, 15, 0) == 1.0
    # Equal bounds raise ValueError
    with pytest.raises(ValueError, match="cannot equal best"):
        scale_down(10, 10, 10)


# ---------------- 2. Section 11 Worked Examples (all 17 rows) ----------------

def test_worked_example_rapid_min_boundary(default_config: Config):
    # Rapid: forwarded 80%, gap 15 min -> 0.0, 0.0 -> suspicion 0.00 -> score 0.40 -> low
    cfg_s = default_config.sliders.rapid_onward_transfer
    s_pct = scale_up(80, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
    s_gap = scale_down(15, cfg_s.gap_minutes.cutoff, cfg_s.gap_minutes.best)
    suspicion = (s_pct + s_gap) / 2.0
    assert round(s_pct, 2) == 0.00
    assert round(s_gap, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN1"],
        {"_sliders": {"forwarded_pct": s_pct, "gap_minutes": s_gap}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.40
    assert res.evidence["calculated_priority"] == "low"


def test_worked_example_rapid_high(default_config: Config):
    # Rapid: forwarded 98%, gap 7 min -> 0.90, 0.533 -> suspicion 0.717 -> score 0.83 -> high
    cfg_s = default_config.sliders.rapid_onward_transfer
    s_pct = scale_up(98, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
    s_gap = scale_down(7, cfg_s.gap_minutes.cutoff, cfg_s.gap_minutes.best)
    suspicion = (s_pct + s_gap) / 2.0
    assert round(s_pct, 2) == 0.90
    assert round(s_gap, 3) == 0.533
    assert round(suspicion, 3) == 0.717

    f = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN1"],
        {"_sliders": {"forwarded_pct": s_pct, "gap_minutes": s_gap}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.83
    assert res.evidence["calculated_priority"] == "high"


def test_worked_example_rapid_mid(default_config: Config):
    # Rapid: forwarded 90%, gap 7.5 min -> 0.50, 0.50 -> suspicion 0.50 -> score 0.70 -> medium
    cfg_s = default_config.sliders.rapid_onward_transfer
    s_pct = scale_up(90, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
    s_gap = scale_down(7.5, cfg_s.gap_minutes.cutoff, cfg_s.gap_minutes.best)
    suspicion = (s_pct + s_gap) / 2.0
    assert round(s_pct, 2) == 0.50
    assert round(s_gap, 2) == 0.50
    assert round(suspicion, 2) == 0.50

    f = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN1"],
        {"_sliders": {"forwarded_pct": s_pct, "gap_minutes": s_gap}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.70
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_cycle_min(default_config: Config):
    # Cycle: similarity 0.80, span 6 h -> 0.0, 0.0 -> suspicion 0.00 -> score 0.32 -> low
    cfg_s = default_config.sliders.transaction_cycle
    s_sim = scale_up(0.80, cfg_s.amount_similarity.low, cfg_s.amount_similarity.high)
    s_span = scale_down(6.0, cfg_s.span_hours.cutoff, cfg_s.span_hours.best)
    suspicion = (s_sim + s_span) / 2.0
    assert round(s_sim, 2) == 0.00
    assert round(s_span, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "TRANSACTION_CYCLE", ["ACC1", "ACC2", "ACC3"], ["vpa1"], ["TXN1"],
        {"_sliders": {"amount_similarity": s_sim, "span_hours": s_span}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1", "ACC2", "ACC3"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.32
    assert res.evidence["calculated_priority"] == "low"


def test_worked_example_cycle_mid(default_config: Config):
    # Cycle: similarity 0.90, span 3 h -> 0.50, 0.50 -> suspicion 0.50 -> score 0.56 -> medium
    cfg_s = default_config.sliders.transaction_cycle
    s_sim = scale_up(0.90, cfg_s.amount_similarity.low, cfg_s.amount_similarity.high)
    s_span = scale_down(3.0, cfg_s.span_hours.cutoff, cfg_s.span_hours.best)
    suspicion = (s_sim + s_span) / 2.0
    assert round(s_sim, 2) == 0.50
    assert round(s_span, 2) == 0.50
    assert round(suspicion, 2) == 0.50

    f = RawFinding(
        "TRANSACTION_CYCLE", ["ACC1", "ACC2", "ACC3"], ["vpa1"], ["TXN1"],
        {"_sliders": {"amount_similarity": s_sim, "span_hours": s_span}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1", "ACC2", "ACC3"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.56
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_cycle_max(default_config: Config):
    # Cycle: similarity 1.00, span 0 -> 1.0, 1.0 -> suspicion 1.00 -> score 0.80 -> high
    cfg_s = default_config.sliders.transaction_cycle
    s_sim = scale_up(1.00, cfg_s.amount_similarity.low, cfg_s.amount_similarity.high)
    s_span = scale_down(0.0, cfg_s.span_hours.cutoff, cfg_s.span_hours.best)
    suspicion = (s_sim + s_span) / 2.0
    assert round(s_sim, 2) == 1.00
    assert round(s_span, 2) == 1.00
    assert round(suspicion, 2) == 1.00

    f = RawFinding(
        "TRANSACTION_CYCLE", ["ACC1", "ACC2", "ACC3"], ["vpa1"], ["TXN1"],
        {"_sliders": {"amount_similarity": s_sim, "span_hours": s_span}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1", "ACC2", "ACC3"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.80
    assert res.evidence["calculated_priority"] == "high"


def test_worked_example_fan_in_min(default_config: Config):
    # Fan-in: 8 senders, 100% first-time -> 0.0, 1.0 -> suspicion 0.30 -> score 0.58 -> medium
    cfg_s = default_config.sliders.multi_source_fan_in
    s_senders = scale_up(8, cfg_s.distinct_senders.low, cfg_s.distinct_senders.high)
    s_first_time = scale_up(1.0, cfg_s.first_time_share.low, cfg_s.first_time_share.high)
    suspicion = cfg_s.mix.count * s_senders + cfg_s.mix.strangers * s_first_time
    assert round(s_senders, 2) == 0.00
    assert round(s_first_time, 2) == 1.00
    assert round(suspicion, 2) == 0.30

    f = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC_TARGET"], ["vpa1"], ["TXN1"],
        {"_sliders": {"distinct_senders": s_senders, "first_time_share": s_first_time}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_TARGET"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.58
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_fan_in_mid(default_config: Config):
    # Fan-in: 14 senders, 85% first-time -> 0.5, 0.5 -> suspicion 0.50 -> score 0.70 -> medium
    cfg_s = default_config.sliders.multi_source_fan_in
    s_senders = scale_up(14, cfg_s.distinct_senders.low, cfg_s.distinct_senders.high)
    s_first_time = scale_up(0.85, cfg_s.first_time_share.low, cfg_s.first_time_share.high)
    suspicion = cfg_s.mix.count * s_senders + cfg_s.mix.strangers * s_first_time
    assert round(s_senders, 2) == 0.50
    assert round(s_first_time, 2) == 0.50
    assert round(suspicion, 2) == 0.50

    f = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC_TARGET"], ["vpa1"], ["TXN1"],
        {"_sliders": {"distinct_senders": s_senders, "first_time_share": s_first_time}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_TARGET"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.70
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_fan_in_max(default_config: Config):
    # Fan-in: 20 senders, 100% first-time -> 1.0, 1.0 -> suspicion 1.00 -> score 1.00 -> high
    cfg_s = default_config.sliders.multi_source_fan_in
    s_senders = scale_up(20, cfg_s.distinct_senders.low, cfg_s.distinct_senders.high)
    s_first_time = scale_up(1.00, cfg_s.first_time_share.low, cfg_s.first_time_share.high)
    suspicion = cfg_s.mix.count * s_senders + cfg_s.mix.strangers * s_first_time
    assert round(s_senders, 2) == 1.00
    assert round(s_first_time, 2) == 1.00
    assert round(suspicion, 2) == 1.00

    f = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC_TARGET"], ["vpa1"], ["TXN1"],
        {"_sliders": {"distinct_senders": s_senders, "first_time_share": s_first_time}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_TARGET"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 1.00
    assert res.evidence["calculated_priority"] == "high"


def test_worked_example_fan_out_min(default_config: Config):
    # Fan-out: 3 pieces, spread 25%, forwarded 80% -> 0, 0, 0 -> suspicion 0.00 -> score 0.32 -> low
    cfg_s = default_config.sliders.fan_out_splitting
    s_pct = scale_up(80, cfg_s.forwarded_pct.low, cfg_s.forwarded_pct.high)
    s_spread = scale_down(25, cfg_s.amount_spread_pct.cutoff, cfg_s.amount_spread_pct.best)
    s_cnt = scale_up(3, cfg_s.outgoing_count.low, cfg_s.outgoing_count.high)
    suspicion = (s_pct + s_spread + s_cnt) / 3.0
    assert round(s_pct, 2) == 0.00
    assert round(s_spread, 2) == 0.00
    assert round(s_cnt, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "FAN_OUT_SPLITTING", ["ACC1"], ["vpa1"], ["TXN1"],
        {"_sliders": {"forwarded_pct": s_pct, "amount_spread_pct": s_spread, "outgoing_count": s_cnt}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.32
    assert res.evidence["calculated_priority"] == "low"


def test_worked_example_complaints_floor(default_config: Config):
    # Complaints: 2 complaints, ₹500, avg 3 hops -> 0, 0, 0 -> suspicion 0.00 -> score 0.50 (floor) -> medium
    cfg_s = default_config.sliders.complaint_convergence
    s_comp = scale_up(2, cfg_s.complaints.low, cfg_s.complaints.high)
    s_amt = scale_up(500, cfg_s.traced_inr.low, cfg_s.traced_inr.high)
    s_hops = scale_down(3.0, cfg_s.avg_hops.cutoff, cfg_s.avg_hops.best)
    suspicion = (s_comp + s_amt + s_hops) / 3.0
    assert round(s_comp, 2) == 0.00
    assert round(s_amt, 2) == 0.00
    assert round(s_hops, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "COMPLAINT_CONVERGENCE", ["ACC_MULE"], ["vpa1"], ["TXN1"],
        {"_sliders": {"complaints": s_comp, "traced_inr": s_amt, "avg_hops": s_hops}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_MULE"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.50
    assert res.evidence["score_breakdown"]["floor_applied"] is True
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_complaints_high(default_config: Config):
    # Complaints: 5 complaints, ₹50,000, avg 1 hop -> 1, 1, 1 -> suspicion 1.00 -> score 1.00 -> high
    cfg_s = default_config.sliders.complaint_convergence
    s_comp = scale_up(5, cfg_s.complaints.low, cfg_s.complaints.high)
    s_amt = scale_up(50000, cfg_s.traced_inr.low, cfg_s.traced_inr.high)
    s_hops = scale_down(1.0, cfg_s.avg_hops.cutoff, cfg_s.avg_hops.best)
    suspicion = (s_comp + s_amt + s_hops) / 3.0
    assert round(s_comp, 2) == 1.00
    assert round(s_amt, 2) == 1.00
    assert round(s_hops, 2) == 1.00
    assert round(suspicion, 2) == 1.00

    f = RawFinding(
        "COMPLAINT_CONVERGENCE", ["ACC_MULE"], ["vpa1"], ["TXN1"],
        {"_sliders": {"complaints": s_comp, "traced_inr": s_amt, "avg_hops": s_hops}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_MULE"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 1.00
    assert res.evidence["score_breakdown"]["floor_applied"] is False
    assert res.evidence["calculated_priority"] == "high"


def test_worked_example_new_account_burst_min(default_config: Config):
    # New account: 4x median, not dormant -> 0.0 -> suspicion 0.00 -> score 0.24 -> low
    cfg_s = default_config.sliders.new_account_burst
    s_spike = scale_up(4.0, cfg_s.spike_multiple.low, cfg_s.spike_multiple.high)
    suspicion = clamp(s_spike + 0.0)
    assert round(s_spike, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "NEW_ACCOUNT_BURST", ["ACC_BURST"], ["vpa1"], ["TXN1"],
        {"_sliders": {"spike_multiple": s_spike}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_BURST"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.24
    assert res.evidence["calculated_priority"] == "low"


def test_worked_example_new_account_burst_max(default_config: Config):
    # New account: 20x median, dormant -> clamp(1.0 + 0.2) -> suspicion 1.00 -> score 0.60 -> medium (never high alone)
    cfg_s = default_config.sliders.new_account_burst
    s_spike = scale_up(20.0, cfg_s.spike_multiple.low, cfg_s.spike_multiple.high)
    suspicion = clamp(s_spike + cfg_s.dormant_bonus)
    assert round(s_spike, 2) == 1.00
    assert round(suspicion, 2) == 1.00

    f = RawFinding(
        "NEW_ACCOUNT_BURST", ["ACC_BURST"], ["vpa1"], ["TXN1"],
        {"_sliders": {"spike_multiple": s_spike}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_BURST"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.60
    assert res.evidence["calculated_priority"] == "medium"


def test_worked_example_collect_min(default_config: Config):
    # Collect: 5 requests, 4 payers -> 0, 0 -> suspicion 0.00 -> score 0.32 -> low
    cfg_s = default_config.sliders.collect_request_abuse
    s_req = scale_up(5, cfg_s.requests.low, cfg_s.requests.high)
    s_payers = scale_up(4, cfg_s.distinct_payers.low, cfg_s.distinct_payers.high)
    suspicion = (s_req + s_payers) / 2.0
    assert round(s_req, 2) == 0.00
    assert round(s_payers, 2) == 0.00
    assert round(suspicion, 2) == 0.00

    f = RawFinding(
        "COLLECT_REQUEST_ABUSE", ["ACC_INIT"], ["vpa1"], ["TXN1"],
        {"_sliders": {"requests": s_req, "distinct_payers": s_payers}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_INIT"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.32
    assert res.evidence["calculated_priority"] == "low"


def test_worked_example_collect_max(default_config: Config):
    # Collect: 15 requests, 10 payers -> 1, 1 -> suspicion 1.00 -> score 0.80 -> high
    cfg_s = default_config.sliders.collect_request_abuse
    s_req = scale_up(15, cfg_s.requests.low, cfg_s.requests.high)
    s_payers = scale_up(10, cfg_s.distinct_payers.low, cfg_s.distinct_payers.high)
    suspicion = (s_req + s_payers) / 2.0
    assert round(s_req, 2) == 1.00
    assert round(s_payers, 2) == 1.00
    assert round(suspicion, 2) == 1.00

    f = RawFinding(
        "COLLECT_REQUEST_ABUSE", ["ACC_INIT"], ["vpa1"], ["TXN1"],
        {"_sliders": {"requests": s_req, "distinct_payers": s_payers}, "_suspicion": suspicion},
        suspicion, focal_account_ids=["ACC_INIT"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.80
    assert res.evidence["calculated_priority"] == "high"


def test_worked_example_shared_device(default_config: Config):
    # Shared device (any) -> score 0.20 -> low
    f = RawFinding(
        "SHARED_DEVICE", ["ACC1", "ACC2", "ACC3"], ["vpa1"], ["TXN1"],
        {}, 0.5, focal_account_ids=["ACC1", "ACC2", "ACC3"], informational_only=True
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.20
    assert res.evidence["calculated_priority"] == "low"
    assert res.evidence["score_breakdown"]["flat_score_applied"] is True


# ---------------- 3. Escalation worked examples ----------------

def test_escalation_example_two_distinct_families(default_config: Config):
    # One focal account has rapid (base 0.83) and fan-in (base 0.58) -> +0.10 each -> 0.93 (high) and 0.68 (medium)
    f_rapid = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC_FOCAL", "ACC_OUT"], ["vpa1"], ["TXN1"],
        {"_suspicion": 0.71666666}, 0.71666666, focal_account_ids=["ACC_FOCAL"]
    )
    f_fanin = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC_FOCAL", "ACC_IN1"], ["vpa1"], ["TXN2"],
        {"_suspicion": 0.30}, 0.30, focal_account_ids=["ACC_FOCAL"]
    )
    scorer = Scorer(default_config)
    results = scorer.score_findings([f_rapid, f_fanin])

    assert results[0].evidence["calculated_score"] == 0.93
    assert results[0].evidence["calculated_priority"] == "high"
    assert results[0].evidence["score_breakdown"]["family_bonus"] == 0.10

    assert results[1].evidence["calculated_score"] == 0.68
    assert results[1].evidence["calculated_priority"] == "medium"
    assert results[1].evidence["score_breakdown"]["family_bonus"] == 0.10


def test_escalation_example_same_family_no_bonus(default_config: Config):
    # The same account with rapid-transfer AND splitting alert: one family only (PASS_THROUGH) -> no bonus
    f_rapid = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC_FOCAL"], ["vpa1"], ["TXN1"],
        {"_suspicion": 0.71666666}, 0.71666666, focal_account_ids=["ACC_FOCAL"]
    )
    f_split = RawFinding(
        "FAN_OUT_SPLITTING", ["ACC_FOCAL"], ["vpa1"], ["TXN2"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC_FOCAL"]
    )
    scorer = Scorer(default_config)
    results = scorer.score_findings([f_rapid, f_split])

    # No bonus applied
    assert results[0].evidence["score_breakdown"]["family_bonus"] == 0.00
    assert results[0].evidence["calculated_score"] == 0.83
    assert results[1].evidence["score_breakdown"]["family_bonus"] == 0.00
    assert results[1].evidence["calculated_score"] == 0.32


def test_escalation_example_complaint_link_bonus(default_config: Config):
    # A fan-in alert (base 0.58) whose focal account is on a complaint trail: +0.10 gives 0.68, still medium.
    # The same alert with one more distinct family: 0.78, high.
    f_fanin = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC_FOCAL"], ["vpa1"], ["TXN1"],
        {"_suspicion": 0.30}, 0.30, focal_account_ids=["ACC_FOCAL"]
    )
    # Trail has ACC_FOCAL
    scorer_complaint_only = Scorer(default_config, accounts_on_complaint_trails={"ACC_FOCAL"})
    res1 = scorer_complaint_only.score_findings([f_fanin])[0]
    assert res1.evidence["score_breakdown"]["complaint_bonus"] == 0.10
    assert res1.evidence["score_breakdown"]["family_bonus"] == 0.00
    assert res1.evidence["calculated_score"] == 0.68
    assert res1.evidence["calculated_priority"] == "medium"

    # Now add another family (e.g. RAPID_ONWARD_TRANSFER)
    f_rapid = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC_FOCAL"], ["vpa1"], ["TXN2"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC_FOCAL"]
    )
    scorer_both = Scorer(default_config, accounts_on_complaint_trails={"ACC_FOCAL"})
    res2 = scorer_both.score_findings([f_fanin, f_rapid])[0]
    assert res2.evidence["score_breakdown"]["complaint_bonus"] == 0.10
    assert res2.evidence["score_breakdown"]["family_bonus"] == 0.10
    assert res2.evidence["calculated_score"] == 0.78
    assert res2.evidence["calculated_priority"] == "high"


def test_escalation_example_loop_extra_family(default_config: Config):
    # A barely qualifying loop (0.32) with one extra family: 0.42, still low
    f_loop = RawFinding(
        "TRANSACTION_CYCLE", ["ACC1", "ACC2", "ACC3"], ["vpa1"], ["TXN1"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1", "ACC2", "ACC3"]
    )
    f_inflow = RawFinding(
        "MULTI_SOURCE_FAN_IN", ["ACC1"], ["vpa1"], ["TXN2"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f_loop, f_inflow])[0]
    assert res.evidence["score_breakdown"]["base_score"] == 0.32
    assert res.evidence["score_breakdown"]["family_bonus"] == 0.10
    assert res.evidence["calculated_score"] == 0.42
    assert res.evidence["calculated_priority"] == "low"


def test_complaint_alert_never_gets_own_complaint_bonus(default_config: Config):
    # A COMPLAINT_CONVERGENCE alert never receives the complaint-link bonus from itself
    f_comp = RawFinding(
        "COMPLAINT_CONVERGENCE", ["ACC_MULE"], ["vpa1"], ["TXN1"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC_MULE"]
    )
    scorer = Scorer(default_config, accounts_on_complaint_trails={"ACC_MULE"})
    res = scorer.score_findings([f_comp])[0]
    assert res.evidence["score_breakdown"]["complaint_bonus"] == 0.00
    assert res.evidence["score_breakdown"]["family_bonus"] == 0.00
    assert res.evidence["calculated_score"] == 0.50


# ---------------- 4. Guards & Invariants ----------------

def test_new_account_burst_never_high_alone(default_config: Config):
    # Max suspicion = 1.0 -> score = 0.6 * (0.4 + 0.6 * 1.0) = 0.60 < 0.75 -> cannot reach high alone
    f = RawFinding(
        "NEW_ACCOUNT_BURST", ["ACC1"], ["vpa1"], ["TXN1"],
        {"_suspicion": 1.0}, 1.0, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config)
    res = scorer.score_findings([f])[0]
    assert res.evidence["calculated_score"] == 0.60
    assert res.evidence["calculated_priority"] == "medium"


def test_shared_device_guards(default_config: Config):
    # SHARED_DEVICE is always 0.20, low, never escalated and never counts as a family
    f_sd = RawFinding(
        "SHARED_DEVICE", ["ACC1", "ACC2"], ["vpa1"], ["TXN1"],
        {}, 1.0, focal_account_ids=["ACC1", "ACC2"], informational_only=True
    )
    f_rapid = RawFinding(
        "RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN2"],
        {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]
    )
    scorer = Scorer(default_config, accounts_on_complaint_trails={"ACC1"})
    res_sd, res_rapid = scorer.score_findings([f_sd, f_rapid])

    # SD stays 0.20, low, no bonus
    assert res_sd.evidence["calculated_score"] == 0.20
    assert res_sd.evidence["calculated_priority"] == "low"
    assert res_sd.evidence["score_breakdown"]["flat_score_applied"] is True

    # Rapid does NOT get family bonus from SD! (Only complaint bonus from trail)
    assert res_rapid.evidence["score_breakdown"]["family_bonus"] == 0.00
    assert res_rapid.evidence["score_breakdown"]["complaint_bonus"] == 0.10


def test_family_bonus_cap_and_no_cascade(default_config: Config):
    # Even with 5 distinct families on ACC1, bonus is capped at 0.30
    findings = [
        RawFinding("RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["T1"], {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]), # PASS_THROUGH
        RawFinding("MULTI_SOURCE_FAN_IN", ["ACC1"], ["vpa1"], ["T2"], {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]),   # INFLOW
        RawFinding("TRANSACTION_CYCLE", ["ACC1"], ["vpa1"], ["T3"], {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]),     # LOOP
        RawFinding("COMPLAINT_CONVERGENCE", ["ACC1"], ["vpa1"], ["T4"], {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]), # COMPLAINT
        RawFinding("NEW_ACCOUNT_BURST", ["ACC1"], ["vpa1"], ["T5"], {"_suspicion": 0.0}, 0.0, focal_account_ids=["ACC1"]),     # ACCOUNT_BEHAVIOR
    ]
    scorer = Scorer(default_config)
    results = scorer.score_findings(findings)
    for res in results:
        assert res.evidence["score_breakdown"]["family_bonus"] <= 0.30


# ---------------- 5. Fan-in baseline & warmup guards ----------------

def test_fan_in_baseline_guard(default_config: Config):
    # ACC_REC has 3 prior active days with 10 distinct senders each.
    # Today, receiving from 8 senders < 2.0 * 10 is suppressed.
    # Receiving from 25 senders >= 2.0 * 10 is reported!
    accs = [make_account("ACC_REC")]
    txns = []
    # 3 prior active days: 2026-02-10, 2026-02-11, 2026-02-12
    for day in [10, 11, 12]:
        for s_idx in range(10):
            s_acc = f"ACC_HIST_{day}_{s_idx}"
            accs.append(make_account(s_acc))
            txns.append(make_txn(f"TXN_H_{day}_{s_idx}", f"2026-02-{day:02d} 10:{s_idx*5:02d}:00", f"{s_acc.lower()}@synaxis", "acc_rec@synaxis", 100.0))

    # Case A: 8 senders today on 2026-03-01 -> suppressed!
    txns_case_a = list(txns)
    for s_idx in range(8):
        s_acc = f"ACC_NEW_{s_idx}"
        accs.append(make_account(s_acc))
        txns_case_a.append(make_txn(f"TXN_A_{s_idx}", f"2026-03-01 10:{s_idx*2:02d}:00", f"{s_acc.lower()}@synaxis", "acc_rec@synaxis", 500.0))

    ds_a = build_dataset_from_dicts(accs, [], txns_case_a)
    out_a = run_detection(ds_a, default_config)
    fan_in_alerts_a = [a for a in out_a.alerts if a.rule_id == "MULTI_SOURCE_FAN_IN"]
    assert len(fan_in_alerts_a) == 0

    # Case B: 25 senders today on 2026-03-01 -> burst >= 2.0 * 10 = 20 -> reported!
    txns_case_b = list(txns)
    for s_idx in range(25):
        s_acc = f"ACC_BURST_{s_idx}"
        accs.append(make_account(s_acc))
        txns_case_b.append(make_txn(f"TXN_B_{s_idx}", f"2026-03-01 10:{s_idx*2:02d}:00", f"{s_acc.lower()}@synaxis", "acc_rec@synaxis", 500.0))

    ds_b = build_dataset_from_dicts(accs, [], txns_case_b)
    out_b = run_detection(ds_b, default_config)
    fan_in_alerts_b = [a for a in out_b.alerts if a.rule_id == "MULTI_SOURCE_FAN_IN"]
    assert len(fan_in_alerts_b) == 1


def test_fan_in_warmup_guard_noted_in_meta(default_config: Config):
    # Dataset spanning 14 days (2026-03-01 to 2026-03-15).
    # A fan-in window on 2026-03-03 (day 2, inside 7-day warmup) must be skipped and recorded in meta.
    accs = [make_account("ACC_REC")]
    txns = []
    # Seed transaction on 2026-03-01 (first transaction)
    accs.append(make_account("ACC_SEED"))
    txns.append(make_txn("TXN_SEED", "2026-03-01 08:00:00", "acc_seed@synaxis", "acc_rec@synaxis", 100.0))

    # Fan-in pattern on 2026-03-03 (inside warmup)
    for i in range(8):
        s_acc = f"ACC_W_{i}"
        accs.append(make_account(s_acc))
        txns.append(make_txn(f"TXN_W_{i}", f"2026-03-03 10:{i*2:02d}:00", f"{s_acc.lower()}@synaxis", "acc_rec@synaxis", 500.0))

    # Later transaction on 2026-03-15 to make dataset span 14 days
    accs.append(make_account("ACC_LATE"))
    txns.append(make_txn("TXN_LATE", "2026-03-15 10:00:00", "acc_late@synaxis", "acc_rec@synaxis", 100.0))

    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config)

    # Fan-in inside warmup was skipped
    fan_in_alerts = [a for a in out.alerts if a.rule_id == "MULTI_SOURCE_FAN_IN"]
    assert len(fan_in_alerts) == 0

    # Meta records skipped rule due to warmup
    skipped = [s for s in out.meta.rules_skipped if s.rule_id == "MULTI_SOURCE_FAN_IN"]
    assert len(skipped) == 1
    assert "warm-up" in skipped[0].reason


# ---------------- 6. Config Validation Tests ----------------

def test_config_validation_equal_bounds():
    with pytest.raises(ValidationError):
        Config.model_validate({
            "sliders": {
                "rapid_onward_transfer": {
                    "forwarded_pct": {"low": 80, "high": 80}
                }
            }
        })

    with pytest.raises(ValidationError):
        Config.model_validate({
            "sliders": {
                "rapid_onward_transfer": {
                    "gap_minutes": {"cutoff": 15, "best": 15}
                }
            }
        })


def test_config_validation_mix_weights_not_summing_to_1():
    with pytest.raises(ValidationError, match="Mix weights must sum to 1.0"):
        Config.model_validate({
            "sliders": {
                "multi_source_fan_in": {
                    "mix": {"count": 0.7, "strangers": 0.4}
                }
            }
        })


def test_config_validation_unknown_rule_id():
    with pytest.raises(ValidationError, match="Unknown rule ID"):
        Config.model_validate({
            "scoring": {
                "rule_weights": {"NON_EXISTENT_RULE": 1.0}
            }
        })

    with pytest.raises(ValidationError, match="Unknown rule ID"):
        Config.model_validate({
            "scoring": {
                "escalation": {
                    "families": {"MY_FAMILY": ["NON_EXISTENT_RULE"]}
                }
            }
        })


# ---------------- 7. Priority & Score Consistency ----------------

def test_priority_always_agrees_with_final_score(default_config: Config):
    # Run integration detection with multiple patterns
    accs = [make_account("ACC0"), make_account("ACC1"), make_account("ACC2"), make_account("ACC3")]
    devs = [
        {"device_id": "DEV999", "account_id": "ACC1"},
        {"device_id": "DEV999", "account_id": "ACC2"},
        {"device_id": "DEV999", "account_id": "ACC3"},
    ]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0, device_id="DEV999"),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0, device_id="DEV999"),
    ]
    ds = build_dataset_from_dicts(accs, devs, txns)
    out = run_detection(ds, default_config, dataset_id="consistency_test")

    high_thresh = default_config.scoring.priority_thresholds.high
    med_thresh = default_config.scoring.priority_thresholds.medium

    for alr in out.alerts:
        bd = alr.evidence["score_breakdown"]
        assert bd["scoring_version"] == "2.0"
        final_s = bd["final_score"]
        if alr.rule_id == "SHARED_DEVICE":
            assert alr.priority == "low"
        elif final_s >= high_thresh:
            assert alr.priority == "high"
        elif final_s >= med_thresh:
            assert alr.priority == "medium"
        else:
            assert alr.priority == "low"


# ---------------- 8. Wording guard tests ----------------

def test_no_fraud_conclusion_and_no_proven_in_texts(default_config: Config):
    accs = [make_account("ACC0"), make_account("ACC1"), make_account("ACC2")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    complaints = [
        {"complaint_id": "CMP1", "victim_vpa": "acc0@synaxis", "txn_id": "TXN0", "complaint_date": "2026-03-02"}
    ]
    ds = build_dataset_from_dicts(accs, [], txns, complaints)
    out = run_detection(ds, default_config)

    for alr in out.alerts:
        text = f"{alr.explanation} {alr.limitations} {' '.join(alr.alternative_explanations)} {' '.join(alr.would_clear_if)}".lower()
        assert "proven" not in text
        assert "confirmed theft" not in text
        assert "is fraud" not in text
        assert "proves fraud" not in text
        assert "fraudulent account" not in text
