"""Scoring, suspicion scaling, priority derivation, and rule family escalation logic (scoring v2.0)."""

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Set
from detection.config import Config, PriorityStr
from detection.models import PriorityLevel
from detection.rules.base import RawFinding
from detection.sliders import clamp

logger = logging.getLogger(__name__)


class Scorer:
    """Computes final score, assigns priority, and handles rule-family escalation."""

    def __init__(self, config: Config, accounts_on_complaint_trails: Optional[Set[str]] = None):
        self.config = config
        self.accounts_on_complaint_trails = accounts_on_complaint_trails or set()

    def score_findings(self, findings: List[RawFinding]) -> List[RawFinding]:
        """Compute score, priority, and score_breakdown for each finding according to scoring v2.0."""
        scoring_cfg = self.config.scoring
        esc_cfg = scoring_cfg.escalation

        # Build rule -> family mapping
        rule_to_family: Dict[str, str] = {}
        for fam_name, r_ids in esc_cfg.families.items():
            for r_id in r_ids:
                rule_to_family[r_id] = fam_name

        # 1. First pass: compute base score for each finding and index families on focal accounts
        # SHARED_DEVICE and any CONTEXT-family rule is excluded from family indexing and escalation
        account_to_non_context_families: Dict[str, Set[str]] = defaultdict(set)

        for f in findings:
            fam = rule_to_family.get(f.rule_id, "UNKNOWN")
            if fam != "CONTEXT" and not f.informational_only and f.rule_id != "SHARED_DEVICE":
                focal_accs = f.focal_account_ids if f.focal_account_ids else f.account_ids
                for acc in focal_accs:
                    account_to_non_context_families[acc].add(fam)

        # 2. Second pass: compute base score, bonuses, final score, and priority
        for f in findings:
            fam = rule_to_family.get(f.rule_id, "UNKNOWN")
            weight = scoring_cfg.rule_weights.get(f.rule_id, 1.0)
            focal_accs = f.focal_account_ids if f.focal_account_ids else f.account_ids

            # Sliders and suspicion
            sliders_dict = f.evidence.get("_sliders", {})
            suspicion = f.evidence.get("_suspicion", f.strength)

            # Check if flat score applies (e.g. SHARED_DEVICE)
            if f.rule_id == "SHARED_DEVICE" or f.informational_only or fam == "CONTEXT":
                base_score = scoring_cfg.shared_device_flat_score
                floor_applied = False
                flat_score_applied = True
                family_bonus = 0.0
                complaint_bonus = 0.0
                families_on_focal = []
                final_score = base_score
                priority: PriorityLevel = "low"
            else:
                flat_score_applied = False
                formula_score = weight * (
                    scoring_cfg.base_offset + (1.0 - scoring_cfg.base_offset) * suspicion
                )

                if f.rule_id == "COMPLAINT_CONVERGENCE":
                    if formula_score < scoring_cfg.complaint_score_floor:
                        base_score = scoring_cfg.complaint_score_floor
                        floor_applied = True
                    else:
                        base_score = formula_score
                        floor_applied = False
                else:
                    base_score = formula_score
                    floor_applied = False

                # Escalation calculations
                if esc_cfg.enabled:
                    # Collect distinct families across all focal accounts of this finding
                    focal_families: Set[str] = set()
                    for acc in focal_accs:
                        focal_families.update(account_to_non_context_families.get(acc, set()))
                    families_on_focal = sorted(list(focal_families))

                    num_distinct = len(focal_families)
                    if num_distinct > 1:
                        family_bonus = min(
                            esc_cfg.family_bonus_cap,
                            esc_cfg.family_bonus_each * (num_distinct - 1),
                        )
                    else:
                        family_bonus = 0.0

                    # Complaint bonus: applied if any focal account lies on complaint trail
                    # and this alert is not itself in the COMPLAINT family
                    touches_complaint = (
                        any(acc in self.accounts_on_complaint_trails for acc in focal_accs)
                        or bool(f.complaint_ids)
                    )
                    if touches_complaint and fam != "COMPLAINT":
                        complaint_bonus = esc_cfg.complaint_link_bonus
                    else:
                        complaint_bonus = 0.0
                else:
                    family_bonus = 0.0
                    complaint_bonus = 0.0
                    families_on_focal = [fam] if fam != "UNKNOWN" else []

                final_score = clamp(base_score + family_bonus + complaint_bonus, 0.0, 1.0)

                # Derive priority strictly from final score
                if final_score >= scoring_cfg.priority_thresholds.high:
                    priority = "high"
                elif final_score >= scoring_cfg.priority_thresholds.medium:
                    priority = "medium"
                else:
                    priority = "low"

            # Clean temporary private keys from evidence
            f.evidence.pop("_sliders", None)
            f.evidence.pop("_suspicion", None)

            # Store score breakdown in evidence
            breakdown: Dict[str, any] = {
                "scoring_version": scoring_cfg.version,
                "sliders": {k: round(v, 2) for k, v in sliders_dict.items()},
                "suspicion": round(suspicion, 2),
                "rule_weight": weight,
                "base_score": round(base_score, 2),
                "family": fam,
                "families_on_focal_accounts": families_on_focal,
                "family_bonus": round(family_bonus, 2),
                "complaint_bonus": round(complaint_bonus, 2),
                "floor_applied": floor_applied,
                "final_score": round(final_score, 2),
                "priority": priority,
            }
            if flat_score_applied:
                breakdown["flat_score_applied"] = True

            f.evidence["score_breakdown"] = breakdown
            f.evidence["calculated_score"] = round(final_score, 2)
            f.evidence["calculated_priority"] = priority
            f.evidence["_unrounded_score"] = final_score

        return findings
