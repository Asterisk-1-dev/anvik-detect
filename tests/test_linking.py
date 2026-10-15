"""Tests for linking, rings creation, and account summaries."""

import pytest
from detection.linking import link_alerts_and_rings
from detection.models import Alert


def make_test_alert(
    alert_id: str,
    account_ids: list[str],
    txn_ids: list[str],
    priority: str = "high",
    rule_id: str = "RAPID_ONWARD_TRANSFER",
    informational: bool = False,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title=rule_id.replace("_", " ").title(),
        priority=priority,  # type: ignore
        score=0.8,
        created_at="2026-10-15T12:00:00Z",
        account_ids=account_ids,
        vpas=[f"{a.lower()}@upi" for a in account_ids],
        txn_ids=txn_ids,
        evidence={},
        explanation="Testing explanation.",
        limitations="Testing limitations.",
        alternative_explanations=["Alt 1", "Alt 2"],
        would_clear_if=["Clear 1", "Clear 2"],
        complaint_ids=[],
        related_alert_ids=[],
        ring_id=None,
        informational_only=informational,
    )


def test_related_alert_ids_symmetric():
    # ALR-1 and ALR-2 share TXN-A. ALR-2 and ALR-3 share ACC-Z.
    a1 = make_test_alert("ALR-0001", ["ACC1"], ["TXN-A"])
    a2 = make_test_alert("ALR-0002", ["ACC-Z"], ["TXN-A", "TXN-B"])
    a3 = make_test_alert("ALR-0003", ["ACC-Z", "ACC3"], ["TXN-C"])

    alerts, rings, summaries = link_alerts_and_rings([a1, a2, a3])
    # a1 should link to a2
    assert a1.related_alert_ids == ["ALR-0002"]
    # a2 should link to a1 and a3
    assert a2.related_alert_ids == ["ALR-0001", "ALR-0003"]
    # a3 should link to a2
    assert a3.related_alert_ids == ["ALR-0002"]


def test_ring_creation_and_context_alert_attachment():
    # Ring 1 has ACC1, ACC2 from non-context alert ALR-1
    # Ring 2 has ACC3, ACC4 from non-context alert ALR-2
    # ALR-3 is a SHARED_DEVICE alert touching ACC1 and ACC5.
    # It should attach to Ring 1 because ACC1 is already in it, but not merge Ring 1 and Ring 2.
    a1 = make_test_alert("ALR-0001", ["ACC1", "ACC2"], ["TXN1"], priority="high")
    a2 = make_test_alert("ALR-0002", ["ACC3", "ACC4"], ["TXN2"], priority="medium")
    a3 = make_test_alert("ALR-0003", ["ACC1", "ACC5"], ["TXN3"], priority="low", rule_id="SHARED_DEVICE", informational=True)

    alerts, rings, summaries = link_alerts_and_rings([a1, a2, a3])
    assert len(rings) == 2
    # First ring should be RING-01 with highest priority high
    assert rings[0].ring_id == "RING-01"
    assert rings[0].highest_priority == "high"
    assert "ACC1" in rings[0].account_ids
    assert "ALR-0001" in rings[0].alert_ids
    assert "ALR-0003" in rings[0].alert_ids  # attached
