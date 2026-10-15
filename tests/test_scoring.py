"""Tests for scoring, base priority, and escalation rules."""

import pytest
from detection.config import Config
from detection.rules.base import RawFinding
from detection.scoring import Scorer


def test_base_scoring_thresholds(default_config: Config):
    scorer = Scorer(default_config)
    # strength 0.0 -> score = 1.0 * (0.4 + 0.6 * 0.0) = 0.40 -> low (< 0.45)
    f_low = RawFinding("RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN1"], {}, 0.0)
    # strength 0.2 -> score = 1.0 * (0.4 + 0.6 * 0.2) = 0.52 -> medium (>= 0.45)
    f_med = RawFinding("RAPID_ONWARD_TRANSFER", ["ACC2"], ["vpa2"], ["TXN2"], {}, 0.2)
    # strength 0.8 -> score = 1.0 * (0.4 + 0.6 * 0.8) = 0.88 -> high (>= 0.75)
    f_high = RawFinding("RAPID_ONWARD_TRANSFER", ["ACC3"], ["vpa3"], ["TXN3"], {}, 0.8)

    results = scorer.score_findings([f_low, f_med, f_high])
    assert results[0].evidence["calculated_priority"] == "low"
    assert results[1].evidence["calculated_priority"] == "medium"
    assert results[2].evidence["calculated_priority"] == "high"


def test_escalation_multiple_rules(default_config: Config):
    scorer = Scorer(default_config)
    # ACC1 gets both RAPID_ONWARD_TRANSFER and MULTI_SOURCE_FAN_IN
    f1 = RawFinding("RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN1"], {}, 0.0)  # low base
    f2 = RawFinding("MULTI_SOURCE_FAN_IN", ["ACC1"], ["vpa1"], ["TXN2"], {}, 0.0)   # low base

    results = scorer.score_findings([f1, f2])
    # Both should be escalated to medium (base 0.40 + family_bonus 0.10 = 0.50 >= 0.45)
    assert results[0].evidence["calculated_priority"] == "medium"
    assert results[1].evidence["calculated_priority"] == "medium"
    assert results[0].evidence["score_breakdown"]["family_bonus"] > 0
    assert "PASS_THROUGH" in results[0].evidence["score_breakdown"]["families_on_focal_accounts"]


def test_shared_device_never_escalates(default_config: Config):
    scorer = Scorer(default_config)
    # SHARED_DEVICE rule on ACC1 should stay capped at low and never escalate
    f1 = RawFinding("SHARED_DEVICE", ["ACC1"], ["vpa1"], ["TXN1"], {}, 1.0, informational_only=True)
    f2 = RawFinding("RAPID_ONWARD_TRANSFER", ["ACC1"], ["vpa1"], ["TXN2"], {}, 0.0)

    results = scorer.score_findings([f1, f2])
    # f1 is SHARED_DEVICE -> low
    assert results[0].evidence["calculated_priority"] == "low"
    # f2 is RAPID_ONWARD_TRANSFER, but since SHARED_DEVICE is context-only, it doesn't count toward multiple rules escalation
    assert results[1].evidence["calculated_priority"] == "low"
