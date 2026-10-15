"""Tests for role assignment per rule and precedence order."""

import pytest
from detection.config import Config
from detection.engine import run_detection
from detection.graph_output import assign_role_by_precedence
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_role_precedence():
    # potential_mule > origin_account > receiving_account > destination_account > linked_account
    assert assign_role_by_precedence("origin_account", "potential_mule") == "potential_mule"
    assert assign_role_by_precedence("potential_mule", "origin_account") == "potential_mule"
    assert assign_role_by_precedence("receiving_account", "origin_account") == "origin_account"
    assert assign_role_by_precedence("destination_account", "receiving_account") == "receiving_account"
    assert assign_role_by_precedence("linked_account", "destination_account") == "destination_account"


def test_roles_rapid_onward(default_config: Config):
    # ACC0 (origin_account) -> ACC1 (potential_mule) -> ACC2 (destination_account)
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC0") == "origin_account"
    assert node_roles.get("ACC1") == "potential_mule"
    assert node_roles.get("ACC2") == "destination_account"


def test_roles_multi_source_fan_in(default_config: Config):
    # 8 senders (origin_account) -> ACC_REC (potential_mule)
    accs = [make_account(f"ACC_S_{i}") for i in range(8)] + [make_account("ACC_REC")]
    txns = [
        make_txn(f"TXN_{i}", f"2026-03-01 10:{i*3:02d}:00", f"acc_s_{i}@synaxis", "acc_rec@synaxis", 500.0)
        for i in range(8)
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC_REC") == "potential_mule"
    for i in range(8):
        assert node_roles.get(f"ACC_S_{i}") == "origin_account"


def test_roles_fan_out_splitting(default_config: Config):
    # SENDER (origin_account) -> ACC_IN (potential_mule) -> ACC_OUT_1, 2, 3 (destination_account)
    accs = [make_account("ACC_IN"), make_account("ACC_OUT_1"), make_account("ACC_OUT_2"), make_account("ACC_OUT_3"), make_account("SENDER")]
    txns = [
        make_txn("IN0", "2026-03-01 10:00:00", "sender@synaxis", "acc_in@synaxis", 10000.0),
        make_txn("OUT1", "2026-03-01 10:05:00", "acc_in@synaxis", "acc_out_1@synaxis", 3000.0),
        make_txn("OUT2", "2026-03-01 10:08:00", "acc_in@synaxis", "acc_out_2@synaxis", 3000.0),
        make_txn("OUT3", "2026-03-01 10:12:00", "acc_in@synaxis", "acc_out_3@synaxis", 3000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("SENDER") == "origin_account"
    assert node_roles.get("ACC_IN") == "potential_mule"
    assert node_roles.get("ACC_OUT_1") == "destination_account"
    assert node_roles.get("ACC_OUT_2") == "destination_account"
    assert node_roles.get("ACC_OUT_3") == "destination_account"


def test_roles_transaction_cycle(default_config: Config):
    # ACC_A -> ACC_B -> ACC_C -> ACC_A
    accs = [make_account("ACC_A"), make_account("ACC_B"), make_account("ACC_C")]
    txns = [
        make_txn("TXN_1", "2026-03-01 10:00:00", "acc_a@synaxis", "acc_b@synaxis", 1000.0),
        make_txn("TXN_2", "2026-03-01 10:20:00", "acc_b@synaxis", "acc_c@synaxis", 1000.0),
        make_txn("TXN_3", "2026-03-01 10:40:00", "acc_c@synaxis", "acc_a@synaxis", 1000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC_A") == "origin_account"
    assert node_roles.get("ACC_B") == "linked_account"
    assert node_roles.get("ACC_C") == "linked_account"


def test_roles_complaint_convergence(default_config: Config):
    # VIC1 -> MULE1 -> HUB
    # VIC2 -> MULE2 -> HUB
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
    out = run_detection(ds, default_config, graph_mode="alert")

    hub_alert = next(a for a in out.alerts if a.rule_id == "COMPLAINT_CONVERGENCE")
    g = hub_alert.graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("HUB") == "potential_mule"


def test_roles_new_account_burst(default_config: Config):
    accs = [make_account("ACC_BURST", created_at="2026-03-01")]
    txns = []
    for i in range(12):
        other = f"ACC_OTHER_{i}"
        accs.append(make_account(other, created_at="2025-01-01"))
        txns.append(
            make_txn(f"TXN_{i}", f"2026-03-10 10:{i*2:02d}:00", "acc_burst@synaxis", f"{other.lower()}@synaxis", 100.0)
        )
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC_BURST") == "potential_mule"


def test_roles_collect_abuse(default_config: Config):
    accs = [make_account("ACC_INIT")]
    txns = []
    for i in range(5):
        payer = f"ACC_P_{i}"
        accs.append(make_account(payer))
        txns.append(
            make_txn(f"TXN_C_{i}", f"2026-03-10 10:{i*5:02d}:00", f"{payer.lower()}@synaxis", "acc_init@synaxis", 1000.0, txn_type="COLLECT")
        )
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC_INIT") == "potential_mule"
    for i in range(5):
        assert node_roles.get(f"ACC_P_{i}") == "origin_account"


def test_roles_shared_device(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC3")]
    devs = [
        {"device_id": "DEV_999", "account_id": "ACC1"},
        {"device_id": "DEV_999", "account_id": "ACC2"},
        {"device_id": "DEV_999", "account_id": "ACC3"},
    ]
    ds = build_dataset_from_dicts(accs, devs, [])
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_roles = {n.id: n.role for n in g.nodes if n.type == "account"}
    assert node_roles.get("ACC1") == "linked_account"
    assert node_roles.get("ACC2") == "linked_account"
    assert node_roles.get("ACC3") == "linked_account"
