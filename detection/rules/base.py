"""Base classes, data types, and interfaces for RingScope detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from detection.config import Config
from detection.features import FeatureStore
from detection.graph import TransactionGraph
from detection.loader import Dataset


@dataclass
class RuleContext:
    """Context object passed to every rule execution."""
    dataset: Dataset
    config: Config
    graph: TransactionGraph
    features: FeatureStore


@dataclass
class RawFinding:
    """Internal representation of a finding emitted by a rule before scoring and explanation."""
    rule_id: str
    account_ids: List[str]
    vpas: List[str]
    txn_ids: List[str]
    evidence: Dict[str, Any]
    strength: float  # [0.0, 1.0]
    complaint_ids: List[str] = field(default_factory=list)
    focal_account_ids: List[str] = field(default_factory=list)
    informational_only: bool = False


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    rule_id: str
    title: str

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def run(self, ctx: RuleContext) -> List[RawFinding]:
        """Execute the rule and return a list of RawFinding objects."""
        pass
