"""Tests for graph generation, schema integrity, roles, and ring graphs."""

from datetime import datetime, timezone
import pytest
from detection.config import Config, load_config
from detection.engine import run_detection
from tests.conftest import make_account, make_txn, build_dataset_from_dicts


def test_graph_schema_and_consistency(default_config: Config):
    # Setup rapid onward scenario
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, dataset_id="graph_test", graph_mode="both")

    assert out.count == 1
    alr = out.alerts[0]
    assert alr.graph is not None

    g = alr.graph
    node_ids = {n.id for n in g.nodes}
    edge_ids = {e.id for e in g.edges}

    # Node IDs and Edge IDs must be unique
    assert len(node_ids) == len(g.nodes)
    assert len(edge_ids) == len(g.edges)

    # Every edge source and target must exist in node_ids
    for e in g.edges:
        assert e.source in node_ids
        assert e.target in node_ids

    # Supporting transactions in alert.txn_ids must appear as is_supporting=True payment edges
    for t_id in alr.txn_ids:
        matching = [e for e in g.edges if e.id == t_id]
        assert len(matching) == 1
        assert matching[0].is_supporting is True
        assert matching[0].direction == "supporting"

    # linked_txn_ids must be disjoint from txn_ids and equal to non-supporting payment edges
    non_supp_payment_ids = [e.id for e in g.edges if e.kind == "payment" and not e.is_supporting]
    assert alr.linked_txn_ids == non_supp_payment_ids
    assert set(alr.linked_txn_ids).isdisjoint(set(alr.txn_ids))

    # All payment edges must have status SUCCESS
    for e in g.edges:
        if e.kind == "payment":
            assert e.status == "SUCCESS"
            assert e.amount_inr is not None
            assert e.sequence is not None


def test_graph_direction_and_time_windows(default_config: Config):
    # ACC1 gets supporting inbound at 10:00, supporting outbound at 10:05
    # Upstream txn: ACC_UP -> ACC1 at 08:00 (inside 48h context window)
    # Too-early txn: ACC_OLD -> ACC1 at 2026-02-20 10:00 (outside 48h window)
    # Downstream txn: ACC2 -> ACC_DOWN at 12:00 (inside 48h context window)
    accs = [
        make_account("ACC1", created_at="2024-01-01"),
        make_account("ACC2", created_at="2024-01-01"),
        make_account("ACC0", created_at="2024-01-01"),
        make_account("ACC_UP", created_at="2024-01-01"),
        make_account("ACC_OLD", created_at="2024-01-01"),
        make_account("ACC_DOWN", created_at="2024-01-01"),
    ]
    txns = [
        make_txn("TXN_OLD", "2026-02-20 10:00:00", "acc_old@synaxis", "acc1@synaxis", 500.0, device_id="DEV_OLD"),
        make_txn("TXN_UP", "2026-03-01 08:00:00", "acc_up@synaxis", "acc1@synaxis", 500.0, device_id="DEV_UP"),
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0, device_id="DEV0"),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0, device_id="DEV1"),
        make_txn("TXN_DOWN", "2026-03-01 12:00:00", "acc2@synaxis", "acc_down@synaxis", 500.0, device_id="DEV2"),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    assert out.count == 1
    g = out.alerts[0].graph
    edge_map = {e.id: e for e in g.edges}

    assert "TXN0" in edge_map
    assert "TXN1" in edge_map
    assert "TXN_UP" in edge_map
    assert edge_map["TXN_UP"].direction == "upstream"
    assert "TXN_DOWN" in edge_map
    assert edge_map["TXN_DOWN"].direction == "downstream"
    # TXN_OLD is outside 48 hours and must not be present
    assert "TXN_OLD" not in edge_map


def test_device_nodes_shared_and_origin(default_config: Config):
    # ACC1, ACC2 share DEV_SHARED (linked in devices.csv)
    # Earliest txn TXN0 uses DEV_ORIGIN
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    devs = [
        {"device_id": "DEV_SHARED", "account_id": "ACC1"},
        {"device_id": "DEV_SHARED", "account_id": "ACC2"},
    ]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0, device_id="DEV_ORIGIN"),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0, device_id="DEV_SHARED"),
    ]
    ds = build_dataset_from_dicts(accs, devs, txns)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    node_map = {n.id: n for n in g.nodes}

    assert "DEV_SHARED" in node_map
    assert node_map["DEV_SHARED"].type == "device"
    assert node_map["DEV_SHARED"].role == "shared_device"

    assert "DEV_ORIGIN" in node_map
    assert node_map["DEV_ORIGIN"].type == "device"
    assert node_map["DEV_ORIGIN"].role == "origin_device"

    # Test include_devices: false
    cfg_no_dev = default_config.model_copy(deep=True)
    cfg_no_dev.graph.include_devices = False
    out_no_dev = run_detection(ds, cfg_no_dev, graph_mode="alert")
    g_no_dev = out_no_dev.alerts[0].graph
    assert not any(n.type == "device" for n in g_no_dev.nodes)


def test_collect_request_as_node(default_config: Config):
    # COLLECT txn with collect_request_as_node enabled
    accs = [make_account("ACC_INIT")]
    txns = []
    for i in range(5):
        payer = f"ACC_P_{i}"
        accs.append(make_account(payer))
        txns.append(
            make_txn(f"TXN_C_{i}", f"2026-03-10 10:{i*5:02d}:00", f"{payer.lower()}@synaxis", "acc_init@synaxis", 1000.0, txn_type="COLLECT")
        )
    ds = build_dataset_from_dicts(accs, [], txns)

    # 1. With collect_request_as_node: false (default)
    out_def = run_detection(ds, default_config, graph_mode="alert")
    g_def = out_def.alerts[0].graph
    assert not any(n.type == "collect_request" for n in g_def.nodes)

    # 2. With collect_request_as_node: true
    cfg_cr = default_config.model_copy(deep=True)
    cfg_cr.graph.collect_request_as_node = True
    out_cr = run_detection(ds, cfg_cr, graph_mode="alert")
    g_cr = out_cr.alerts[0].graph
    req_nodes = [n for n in g_cr.nodes if n.type == "collect_request"]
    assert len(req_nodes) == 5
    assert req_nodes[0].id.startswith("REQ-TXN_C_")
    req_edges = [e for e in g_cr.edges if e.kind == "request_link"]
    assert len(req_edges) == 5


def test_reported_flag_on_payment_edge(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    complaints = [
        {"complaint_id": "CMP999", "victim_vpa": "acc0@synaxis", "txn_id": "TXN0", "complaint_date": "2026-03-02"}
    ]
    ds = build_dataset_from_dicts(accs, [], txns, complaints)
    out = run_detection(ds, default_config, graph_mode="alert")

    g = out.alerts[0].graph
    txn0_edge = next(e for e in g.edges if e.id == "TXN0")
    assert txn0_edge.reported is True
    assert txn0_edge.complaint_ids == ["CMP999"]

    txn1_edge = next(e for e in g.edges if e.id == "TXN1")
    assert txn1_edge.reported is False
    assert txn1_edge.complaint_ids == []


def test_graph_truncation_limits(default_config: Config):
    # Set max_context_edges to 1
    cfg = default_config.model_copy(deep=True)
    cfg.graph.max_context_edges = 1

    accs = [
        make_account("ACC1"),
        make_account("ACC2"),
        make_account("ACC0"),
        make_account("ACC_UP1"),
        make_account("ACC_UP2"),
    ]
    txns = [
        make_txn("TXN_UP1", "2026-03-01 08:00:00", "acc_up1@synaxis", "acc1@synaxis", 1000.0),
        make_txn("TXN_UP2", "2026-03-01 08:30:00", "acc_up2@synaxis", "acc1@synaxis", 1000.0),
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, cfg, graph_mode="alert")

    g = out.alerts[0].graph
    assert g.truncated is True
    assert g.omitted_edges == 1
    # Both supporting edges TXN0 and TXN1 must NEVER be dropped
    edge_ids = {e.id for e in g.edges}
    assert "TXN0" in edge_ids
    assert "TXN1" in edge_ids


def test_ring_graph_union_and_deduplication(default_config: Config):
    # Two alerts in the same ring
    accs = [
        make_account("ACC0"),
        make_account("ACC1"),
        make_account("ACC2"),
        make_account("ACC3"),
    ]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
        make_txn("TXN2", "2026-03-01 10:10:00", "acc2@synaxis", "acc3@synaxis", 8000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="both")

    assert len(out.rings) >= 1
    ring = out.rings[0]
    assert ring.graph is not None
    rg = ring.graph

    # Node IDs and edge IDs in ring graph must be unique
    node_ids = [n.id for n in rg.nodes]
    edge_ids = [e.id for e in rg.edges]
    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))

    # Payment sequence in ring must be strictly 1..N
    payment_edges = [e for e in rg.edges if e.kind == "payment"]
    sequences = [e.sequence for e in payment_edges]
    assert sequences == list(range(1, len(payment_edges) + 1))


def test_graph_mode_none_backward_compatible(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="none")

    assert out.alerts[0].graph is None
    assert out.alerts[0].linked_txn_ids == []
    assert out.rings[0].graph is None
    assert out.meta.graph_mode == "none"
    assert out.meta.total_graph_nodes == 0
    assert out.meta.total_graph_edges == 0


def test_wording_no_fraud_in_graph_labels_and_disclaimer(default_config: Config):
    accs = [make_account("ACC1"), make_account("ACC2"), make_account("ACC0")]
    txns = [
        make_txn("TXN0", "2026-03-01 10:00:00", "acc0@synaxis", "acc1@synaxis", 10000.0),
        make_txn("TXN1", "2026-03-01 10:05:00", "acc1@synaxis", "acc2@synaxis", 9000.0),
    ]
    ds = build_dataset_from_dicts(accs, [], txns)
    out = run_detection(ds, default_config, graph_mode="both")

    g = out.alerts[0].graph
    assert "fraud" not in g.disclaimer.lower()
    for n in g.nodes:
        assert "fraud" not in n.role.lower()
        assert "fraud" not in n.label.lower()
