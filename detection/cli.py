"""Command line interface for RingScope detection engine."""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from detection.config import load_config
from detection.engine import run_detection
from detection.loader import load_dataset

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ringscope")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RingScope: Deterministic fraud-pattern detection engine for UPI graphs"
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Directory containing accounts.csv, devices.csv, transactions.csv, complaints.csv",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        type=Path,
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Path to output alerts.json file",
    )
    parser.add_argument(
        "--dataset-id",
        default="anvik_demo_v1",
        help="Identifier for the dataset batch (default: anvik_demo_v1)",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Fixed ISO timestamp for deterministic output generation (e.g. 2026-10-15T12:00:00Z)",
    )
    parser.add_argument(
        "--graph-mode",
        choices=["none", "alert", "ring", "both"],
        default="both",
        help="Graph building mode: none, alert, ring, or both (default: both)",
    )

    args = parser.parse_args()

    # Load config
    cfg = load_config(args.config if args.config.is_file() else None)

    # Parse fixed generated_at if supplied
    gen_dt = None
    if args.generated_at:
        try:
            gen_dt = datetime.fromisoformat(args.generated_at.replace("Z", "+00:00"))
        except Exception as e:
            logger.error(f"Invalid timestamp provided for --generated-at: {e}")
            sys.exit(1)

    # Load dataset
    try:
        dataset = load_dataset(args.input_dir, assume_timezone=cfg.general.assume_timezone)
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        sys.exit(1)

    # Run detection
    output = run_detection(
        dataset=dataset,
        config=cfg,
        dataset_id=args.dataset_id,
        generated_at=gen_dt,
        graph_mode=args.graph_mode,
    )

    # Summary counts
    rule_counts = {}
    prio_counts = {"high": 0, "medium": 0, "low": 0}
    for alr in output.alerts:
        rule_counts[alr.rule_id] = rule_counts.get(alr.rule_id, 0) + 1
        prio_counts[alr.priority] = prio_counts.get(alr.priority, 0) + 1

    print("\n" + "=" * 50)
    print(" RingScope Rulebook Detection Run Summary")
    print("=" * 50)
    print(f"Total alerts: {output.count}")
    print(f"Rings identified: {len(output.rings)}")
    print(f"Flagged accounts: {len(output.account_summaries)}")
    print(f"Graph Mode: {args.graph_mode} (Nodes: {output.meta.total_graph_nodes}, Edges: {output.meta.total_graph_edges})")
    print("\nAlerts per rule:")
    if rule_counts:
        for r, c in sorted(rule_counts.items()):
            print(f"  - {r}: {c}")
    else:
        print("  (None)")

    print("\nAlerts per priority:")
    for p, c in prio_counts.items():
        print(f"  - {p.upper()}: {c}")
    print("=" * 50 + "\n")

    # Serialize output with ensure_ascii=False and write file
    output_dict = output.model_dump(mode="json")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output_dict, f, indent=2, ensure_ascii=False)

    logger.info(f"Results successfully written to {out_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
