"""Tests for Rule 8.5 COMPLAINT_CONVERGENCE."""

import pytest
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.rules.base import RuleContext
from detection.rules.complaint_convergence import ComplaintConvergenceRule
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_complaint_convergence_true_positive(default_config: Config):
    # Two victims complain about TXN_C1 and TXN_C2
    # TXN_C1 goes from VIC1 to MULE1 (10,000 INR). MULE1 sends 10,000 to HUB (TXN_M1).
    # TXN_C2 goes from VIC2 to MULE2 (8,000 INR). MULE2 sends 8,000 to HUB (TXN_M2).
    # HUB receives funds traced from 2 complaints -> fires COMPLAINT_CONVERGENCE!
    accs = [
        make_account("VIC1"),
        make_account("VIC2"),
        make_account("MULE1"),
        make_account("MULE2"),
        make_account("HUB"),
    ]
    txns = [
        make_txn("TXN_C1", "2026-03-01 10:00:00", "vic1@synaxis", "mule1@synaxis", 10000.0),
        make_txn("TXN_M1", "2026-03-01 10:30:00", "mule1@synaxis", "hub@synaxis", 10000.0),
        make_txn("TXN_C2", "2026-03-01 11:00:00", "vic2@synaxis", "mule2@synaxis", 8000.0),
        make_txn("TXN_M2", "2026-03-01 11:30:00", "mule2@synaxis", "hub@synaxis", 8000.0),
    ]
    complaints = [
        {"complaint_id": "CMP001", "victim_vpa": "vic1@synaxis", "txn_id": "TXN_C1", "complaint_date": "2026-03-02"},
        {"complaint_id": "CMP002", "victim_vpa": "vic2@synaxis", "txn_id": "TXN_C2", "complaint_date": "2026-03-02"},
    ]
    ds = build_dataset_from_dicts(accs, [], txns, complaints)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    rule = ComplaintConvergenceRule(default_config)
    findings = rule.run(ctx)
    hub_findings = [f for f in findings if f.account_ids[0] == "HUB"]
    assert len(hub_findings) == 1
    f = hub_findings[0]
    assert f.evidence["complaints_converging"] == 2
    assert "CMP001" in f.evidence["complaint_ids"]
    assert "CMP002" in f.evidence["complaint_ids"]
    assert len(f.evidence["trails"]) >= 2


def test_complaint_convergence_true_negative_single_complaint(default_config: Config):
    # Only 1 complaint -> should stay quiet (min_converging_complaints = 2)
    accs = [make_account("VIC1"), make_account("MULE1"), make_account("HUB")]
    txns = [
        make_txn("TXN_C1", "2026-03-01 10:00:00", "vic1@synaxis", "mule1@synaxis", 10000.0),
        make_txn("TXN_M1", "2026-03-01 10:30:00", "mule1@synaxis", "hub@synaxis", 10000.0),
    ]
    complaints = [
        {"complaint_id": "CMP001", "victim_vpa": "vic1@synaxis", "txn_id": "TXN_C1", "complaint_date": "2026-03-02"},
    ]
    ds = build_dataset_from_dicts(accs, [], txns, complaints)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = ComplaintConvergenceRule(default_config).run(ctx)
    assert len(findings) == 0


def test_complaint_convergence_clean_skip_no_complaints(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2")]
    txns = [make_txn("TXN1", "2026-03-01 10:00:00", "acc1@synaxis", "acc2@synaxis", 5000.0)]
    ds = build_dataset_from_dicts(accs, [], txns, complaints_rows=None)
    ctx = RuleContext(ds, default_config, TransactionGraph(ds), FeatureStore(ds))

    findings = ComplaintConvergenceRule(default_config).run(ctx)
    assert len(findings) == 0
