"""Rule 8.8: Shared Device detection (informational context)."""

import logging
from collections import defaultdict
from typing import Dict, List, Set
from detection.config import Config
from detection.rules.base import BaseRule, RawFinding, RuleContext

logger = logging.getLogger(__name__)


class SharedDeviceRule(BaseRule):
    """Detects devices linked to multiple accounts across devices.csv and transaction records.

    Emitted as informational context only (priority low, informational_only=True).
    Never proof of fraud and never elevates other rules.
    """

    rule_id = "SHARED_DEVICE"
    title = "Shared device"

    def run(self, ctx: RuleContext) -> List[RawFinding]:
        cfg = self.config.shared_device
        if not cfg.enabled:
            return []

        findings: List[RawFinding] = []

        # Map device_id to set of associated accounts
        # 1. From devices.csv
        device_to_accounts: Dict[str, Set[str]] = defaultdict(set)
        if not ctx.dataset.devices.empty:
            for _, row in ctx.dataset.devices.iterrows():
                dev_id = row["device_id"]
                acc_id = row["account_id"]
                if dev_id and acc_id:
                    device_to_accounts[dev_id].add(acc_id)

        # 2. From transactions observed
        # txn.device_id links to sender_account_id
        device_txn_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        device_supporting_txns: Dict[str, List[str]] = defaultdict(list)

        if not ctx.dataset.transactions.empty:
            for _, row in ctx.dataset.transactions.iterrows():
                dev_id = row.get("device_id")
                sender_acc = row.get("sender_account_id")
                txn_id = row.get("txn_id")
                if dev_id and sender_acc and str(dev_id).strip():
                    dev_id = str(dev_id).strip()
                    device_to_accounts[dev_id].add(sender_acc)
                    device_txn_counts[dev_id][sender_acc] += 1
                    device_supporting_txns[dev_id].append(txn_id)

        # Find devices linked to >= min_accounts accounts
        for dev_id, acc_set in sorted(device_to_accounts.items()):
            if len(acc_set) >= cfg.min_accounts:
                involved_accs = sorted(list(acc_set))
                all_vpas = [ctx.dataset.account_to_vpa.get(a, "") for a in involved_accs]

                # Transaction counts per account
                observed_counts = {acc: device_txn_counts[dev_id].get(acc, 0) for acc in involved_accs}

                evidence = {
                    "device_id": dev_id,
                    "accounts_on_device": involved_accs,
                    "observed_transaction_count_per_account": observed_counts,
                }

                # Context-only rules have low fixed strength
                strength = 0.2

                findings.append(
                    RawFinding(
                        rule_id=self.rule_id,
                        account_ids=involved_accs,
                        vpas=all_vpas,
                        txn_ids=device_supporting_txns.get(dev_id, []),
                        evidence=evidence,
                        strength=strength,
                        complaint_ids=[],
                        focal_account_ids=involved_accs,
                        informational_only=True,
                    )
                )

        return findings
