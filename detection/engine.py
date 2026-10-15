"""Detection engine orchestrator and run_detection entry point."""

import logging
import time
from datetime import datetime, timezone
from typing import List, Literal, Optional, Set, Tuple
from detection.config import Config
from detection.explain import generate_explanation
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.graph_output import GraphBuilder
from detection.linking import link_alerts_and_rings
from detection.loader import Dataset
from detection.models import Alert, Meta, Output, PriorityLevel, SkippedRule
from detection.rules import ALL_RULES
from detection.rules.base import RawFinding, RuleContext
from detection.scoring import Scorer

logger = logging.getLogger(__name__)

PRIORITY_SORT_WEIGHT = {"high": 3, "medium": 2, "low": 1}
GraphMode = Literal["none", "alert", "ring", "both"]


def run_detection(
    dataset: Dataset,
    config: Config,
    dataset_id: str = "anvik_demo_v1",
    generated_at: datetime | None = None,
    graph_mode: GraphMode = "both",
) -> Output:
    """Run the deterministic rule-based fraud-pattern detection engine.

    Args:
        dataset: Typed and validated Dataset containing accounts, devices, transactions, complaints.
        config: Typed engine and rule configuration.
        dataset_id: Identifier for the current dataset batch.
        generated_at: Output generation timestamp (defaults to current UTC time).
        graph_mode: Graph building mode ('none' | 'alert' | 'ring' | 'both').

    Returns:
        Output schema complying with Pydantic models.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    elif generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    else:
        generated_at = generated_at.astimezone(timezone.utc)

    iso_generated_at = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build Graph and FeatureStore
    t_start = time.perf_counter()
    graph = TransactionGraph(dataset)
    features = FeatureStore(dataset)
    ctx = RuleContext(dataset=dataset, config=config, graph=graph, features=features)

    rules_run: List[str] = []
    rules_skipped: List[SkippedRule] = []
    raw_findings: List[RawFinding] = []

    # Execute rules
    for rule_cls in ALL_RULES:
        rule_instance = rule_cls(config)
        r_id = rule_instance.rule_id

        # Check complaints condition for COMPLAINT_CONVERGENCE
        if r_id == "COMPLAINT_CONVERGENCE" and (
            dataset.complaints.empty or len(dataset.complaints) == 0
        ):
            logger.info("Skipping COMPLAINT_CONVERGENCE rule: no complaints present in dataset")
            rules_skipped.append(SkippedRule(rule_id=r_id, reason="no complaints"))
            continue

        r_start = time.perf_counter()
        try:
            findings = rule_instance.run(ctx)
            raw_findings.extend(findings)
            rules_run.append(r_id)
            if getattr(rule_instance, "warmup_skipped_occurred", False):
                rules_skipped.append(
                    SkippedRule(
                        rule_id=r_id,
                        reason=f"windows inside {config.multi_source_fan_in.warmup_days}d warm-up period skipped",
                    )
                )
            r_elapsed = time.perf_counter() - r_start
            logger.info(
                f"Rule {r_id} completed: {len(findings)} findings in {r_elapsed:.3f}s"
            )
        except Exception as e:
            logger.error(f"Error executing rule {r_id}: {e}", exc_info=True)
            rules_skipped.append(SkippedRule(rule_id=r_id, reason=f"error: {str(e)}"))

    # Determine complaint trail accounts if any
    accounts_on_complaint_trails: Set[str] = set()
    for f in raw_findings:
        if f.rule_id == "COMPLAINT_CONVERGENCE":
            accounts_on_complaint_trails.update(f.account_ids)

    # Score and escalate findings
    scorer = Scorer(config, accounts_on_complaint_trails)
    scored_findings = scorer.score_findings(raw_findings)

    # Deterministic sorting before assigning alert IDs:
    # 1. priority desc (high first)
    # 2. score desc (unrounded)
    # 3. rule_id asc
    # 4. first account_id asc
    scored_findings.sort(
        key=lambda f: (
            -PRIORITY_SORT_WEIGHT.get(f.evidence.get("calculated_priority", "low"), 1),
            -f.evidence.get("_unrounded_score", f.evidence.get("calculated_score", 0.0)),
            f.rule_id,
            f.account_ids[0] if f.account_ids else "",
        )
    )

    # Clean unrounded score before generating alerts
    for f in scored_findings:
        f.evidence.pop("_unrounded_score", None)

    # Generate Alerts
    alerts: List[Alert] = []
    for idx, f in enumerate(scored_findings, start=1):
        alert_id = f"ALR-{idx:04d}"
        expl, limit, alts, clear = generate_explanation(f)

        # Sort txn_ids deterministically by timestamp
        # Build mapping of txn_id to timestamp from dataset.transactions
        txn_ts_map = {}
        if not dataset.transactions.empty:
            for _, r in dataset.transactions[dataset.transactions["txn_id"].isin(f.txn_ids)].iterrows():
                txn_ts_map[r["txn_id"]] = r["timestamp"]

        sorted_txns = sorted(
            f.txn_ids,
            key=lambda t: (txn_ts_map.get(t, datetime.min.replace(tzinfo=timezone.utc)), t),
        )

        alert = Alert(
            alert_id=alert_id,
            rule_id=f.rule_id,
            title=f.evidence.get("rule_title", f.rule_id.replace("_", " ").title()),
            priority=f.evidence["calculated_priority"],
            score=f.evidence["calculated_score"],
            created_at=iso_generated_at,
            account_ids=sorted(f.account_ids),
            vpas=sorted(list(set(f.vpas))),
            txn_ids=sorted_txns,
            linked_txn_ids=[],
            evidence=f.evidence,
            explanation=expl,
            limitations=limit,
            alternative_explanations=alts,
            would_clear_if=clear,
            complaint_ids=sorted(list(set(f.complaint_ids))),
            related_alert_ids=[],
            ring_id=None,
            informational_only=f.informational_only,
            graph=None,
        )
        alerts.append(alert)

    # Find direct transaction edges between all flagged accounts
    all_flagged_accounts = set()
    for alr in alerts:
        all_flagged_accounts.update(alr.account_ids)

    direct_edges: Set[Tuple[str, str]] = set()
    for _, r in dataset.successful_txns.iterrows():
        s = r["sender_account_id"]
        rc = r["receiver_account_id"]
        if s in all_flagged_accounts and rc in all_flagged_accounts:
            direct_edges.add((s, rc))

    # Link alerts, rings, and build account summaries
    linked_alerts, rings, account_summaries = link_alerts_and_rings(
        alerts, direct_edges_between_flagged=direct_edges
    )

    # Build graphs if enabled
    graph_builder = GraphBuilder(dataset, config)
    total_nodes_count = 0
    total_edges_count = 0

    build_alert_graphs = graph_mode in ("alert", "both") and config.graph.enabled
    build_ring_graphs = graph_mode in ("ring", "both") and config.graph.enabled

    # 1. Build alert graphs
    alert_map = {a.alert_id: a for a in linked_alerts}
    for alr in linked_alerts:
        if build_alert_graphs:
            a_graph, linked_txns = graph_builder.build_alert_graph(alr)
            alr.graph = a_graph
            alr.linked_txn_ids = linked_txns
            total_nodes_count += len(a_graph.nodes)
            total_edges_count += len(a_graph.edges)
        else:
            alr.graph = None
            alr.linked_txn_ids = []

    # 2. Build ring graphs
    for r in rings:
        if build_ring_graphs:
            ring_alrs = [alert_map[a_id] for a_id in r.alert_ids if a_id in alert_map]
            # Ensure alert graphs exist for ring union
            if not build_alert_graphs:
                # If only ring graphs are requested, build temporary alert graphs
                for alr in ring_alrs:
                    if alr.graph is None:
                        a_g, _ = graph_builder.build_alert_graph(alr)
                        alr.graph = a_g
            r_graph = graph_builder.build_ring_graph(r, ring_alrs)
            r.graph = r_graph
            total_nodes_count += len(r_graph.nodes)
            total_edges_count += len(r_graph.edges)
        else:
            r.graph = None

    meta = Meta(
        engine_version="1.0.0",
        scoring_version=config.scoring.version,
        config_hash=config.config_hash,
        rules_run=rules_run,
        rules_skipped=rules_skipped,
        validation_warnings=dataset.validation_warnings,
        dropped_rows=dataset.dropped_rows,
        graph_schema_version="1.0",
        graph_mode=graph_mode,
        total_graph_nodes=total_nodes_count,
        total_graph_edges=total_edges_count,
    )

    output = Output(
        dataset_id=dataset_id,
        generated_at=iso_generated_at,
        amount_unit="inr",
        count=len(linked_alerts),
        meta=meta,
        alerts=linked_alerts,
        rings=rings,
        account_summaries=account_summaries,
    )

    total_elapsed = time.perf_counter() - t_start
    logger.info(
        f"Detection engine run complete: {len(linked_alerts)} alerts, {len(rings)} rings in {total_elapsed:.3f}s"
    )

    return output
