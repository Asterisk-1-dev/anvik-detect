"""Evaluation tool for comparing alerts.json against expected scenario results.

Standalone script: NEVER imported by the detection engine.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("evaluate")


# Canonical scenario field names - easily modifiable here if expected schema differs
SCENARIO_RULE_KEY = "expected_pattern"
SCENARIO_TRIGGER_KEY = "should_trigger"
SCENARIO_ACCOUNTS_KEY = "expected_account_ids"
SCENARIO_TXNS_KEY = "expected_transaction_ids"
SCENARIO_PRIORITY_KEY = "expected_priority"


def evaluate(alerts_data: Dict[str, Any], ground_truth_data: Dict[str, Any]) -> Dict[str, Any]:
    """Compare generated alerts with expected ground truth scenarios."""
    alerts: List[Dict[str, Any]] = alerts_data.get("alerts", [])
    scenarios: List[Dict[str, Any]] = ground_truth_data.get("scenarios", [])

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    priority_mismatches = 0

    matched_alert_ids: Set[str] = set()
    scenario_reports = []

    for idx, sc in enumerate(scenarios, start=1):
        expected_rule = sc.get(SCENARIO_RULE_KEY)
        should_trigger = sc.get(SCENARIO_TRIGGER_KEY, True)
        exp_txns = set(sc.get(SCENARIO_TXNS_KEY, []))
        exp_prio = sc.get(SCENARIO_PRIORITY_KEY)

        # Match alert to scenario: rule_id matches and transaction IDs overlap
        matched_alert = None
        for alr in alerts:
            if alr.get("rule_id") == expected_rule:
                alr_txns = set(alr.get("txn_ids", []))
                if exp_txns & alr_txns or (not exp_txns and set(sc.get(SCENARIO_ACCOUNTS_KEY, [])) & set(alr.get("account_ids", []))):
                    matched_alert = alr
                    break

        if should_trigger:
            if matched_alert:
                true_positives += 1
                matched_alert_ids.add(matched_alert["alert_id"])
                prio_match = True
                if exp_prio and matched_alert.get("priority") != exp_prio:
                    priority_mismatches += 1
                    prio_match = False
                scenario_reports.append(
                    {
                        "scenario_index": idx,
                        "rule": expected_rule,
                        "status": "TP",
                        "alert_id": matched_alert["alert_id"],
                        "priority_match": prio_match,
                    }
                )
            else:
                false_negatives += 1
                scenario_reports.append(
                    {
                        "scenario_index": idx,
                        "rule": expected_rule,
                        "status": "FN",
                        "alert_id": None,
                        "priority_match": False,
                    }
                )
        else:
            # Should not trigger (negative test case)
            if matched_alert:
                false_positives += 1
                matched_alert_ids.add(matched_alert["alert_id"])
                scenario_reports.append(
                    {
                        "scenario_index": idx,
                        "rule": expected_rule,
                        "status": "FP",
                        "alert_id": matched_alert["alert_id"],
                        "priority_match": False,
                    }
                )
            else:
                scenario_reports.append(
                    {
                        "scenario_index": idx,
                        "rule": expected_rule,
                        "status": "TN",
                        "alert_id": None,
                        "priority_match": True,
                    }
                )

    # Extra alerts not matching any scenario are counted as additional FPs if ground truth was exhaustive
    unmatched_alerts = [a["alert_id"] for a in alerts if a["alert_id"] not in matched_alert_ids]

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "priority_mismatches": priority_mismatches,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "total_alerts": len(alerts),
        "unmatched_alerts_count": len(unmatched_alerts),
        "scenarios": scenario_reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate RingScope alerts against expected ground truth")
    parser.add_argument("--alerts", required=True, type=Path, help="Path to alerts.json")
    parser.add_argument("--ground-truth", required=True, type=Path, help="Path to expected results JSON")
    parser.add_argument("--out-report", default=None, type=Path, help="Path to write evaluation report JSON")

    args = parser.parse_args()

    with open(args.alerts, "r", encoding="utf-8") as f:
        alerts_data = json.load(f)

    with open(args.ground_truth, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    results = evaluate(alerts_data, gt_data)

    print("\n" + "=" * 50)
    print(" RingScope Detection Evaluation Report")
    print("=" * 50)
    print(f"True Positives:      {results['true_positives']}")
    print(f"False Positives:     {results['false_positives']}")
    print(f"False Negatives:     {results['false_negatives']}")
    print(f"Priority Mismatches: {results['priority_mismatches']}")
    print(f"Precision:           {results['precision']:.2%}")
    print(f"Recall:              {results['recall']:.2%}")
    print(f"F1 Score:            {results['f1_score']:.4f}")
    print("=" * 50 + "\n")

    if args.out_report:
        with open(args.out_report, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Detailed report saved to {args.out_report}")


if __name__ == "__main__":
    main()
