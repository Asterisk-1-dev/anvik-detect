"""Configuration loading, validation, and typed dataclass definitions."""

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
import yaml

logger = logging.getLogger(__name__)

PriorityStr = Literal["high", "medium", "low"]

KNOWN_RULE_IDS: Set[str] = {
    "RAPID_ONWARD_TRANSFER",
    "MULTI_SOURCE_FAN_IN",
    "FAN_OUT_SPLITTING",
    "TRANSACTION_CYCLE",
    "COMPLAINT_CONVERGENCE",
    "NEW_ACCOUNT_BURST",
    "COLLECT_REQUEST_ABUSE",
    "SHARED_DEVICE",
}


class GeneralConfig(BaseModel):
    assume_timezone: str = "UTC"
    include_statuses: List[str] = Field(default_factory=lambda: ["SUCCESS"])
    collect_initiator: Literal["receiver", "sender"] = "receiver"


class RapidOnwardConfig(BaseModel):
    enabled: bool = True
    min_inbound_inr: float = 1000.0
    max_gap_minutes: float = 15.0
    min_forwarded_pct: float = 80.0
    exclude_return_to_sender: bool = True
    recurring_counterparty_min_prior_txns: int = 2


class MultiSourceFanInConfig(BaseModel):
    enabled: bool = True
    window_minutes: float = 60.0
    min_distinct_senders: int = 8
    min_first_time_sender_share: float = 0.7
    warmup_days: int = 7
    baseline_min_prior_active_days: int = 3
    baseline_multiplier: float = 2.0


class FanOutSplittingConfig(BaseModel):
    enabled: bool = True
    window_minutes: float = 30.0
    min_inbound_inr: float = 2000.0
    min_outgoing_count: int = 3
    min_distinct_receivers: int = 3
    min_forwarded_pct: float = 80.0
    max_amount_spread_pct: float = 25.0


class TransactionCycleConfig(BaseModel):
    enabled: bool = True
    min_length: int = 3
    max_length: int = 5
    max_span_hours: float = 6.0
    min_amount_similarity: float = 0.8
    min_amount_inr: float = 500.0
    max_cycles_reported: int = 200


class ComplaintConvergenceConfig(BaseModel):
    enabled: bool = True
    max_hops: int = 3
    trace_window_hours: float = 24.0
    min_converging_complaints: int = 2
    min_traced_amount_inr: float = 500.0
    trace_method: Literal["proportional"] = "proportional"


class NewAccountBurstConfig(BaseModel):
    enabled: bool = True
    max_account_age_days: int = 45
    min_txns_in_day: int = 10
    burst_multiplier_vs_median: float = 4.0
    dormant_days: int = 14


class CollectRequestAbuseConfig(BaseModel):
    enabled: bool = True
    window_minutes: float = 120.0
    min_collect_txns: int = 5
    min_distinct_payers: int = 4
    min_collect_share_of_inbound: float = 0.6
    include_failed_in_attempts: bool = True


class SharedDeviceConfig(BaseModel):
    enabled: bool = True
    min_accounts: int = 3
    informational_only: bool = True


class GraphConfig(BaseModel):
    enabled: bool = True
    include_devices: bool = True
    collect_request_as_node: bool = False
    context_hops: int = 1
    context_window_hours: float = 48.0
    max_context_edges: int = 25
    max_nodes: int = 40
    max_ring_edges: int = 80
    max_ring_nodes: int = 80

    @field_validator("context_hops", "max_context_edges", "max_nodes", "max_ring_edges", "max_ring_nodes")
    @classmethod
    def validate_non_negative_ints(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Must be non-negative integer")
        return v

    @field_validator("context_window_hours")
    @classmethod
    def validate_non_negative_float(cls, v: float) -> float:
        if v < 0.0:
            raise ValueError("Must be non-negative float")
        return v


# ---------------- Slider bounds definitions ----------------

class BoundLowHigh(BaseModel):
    low: float
    high: float

    @model_validator(mode="after")
    def validate_bounds(self) -> "BoundLowHigh":
        if self.low == self.high:
            raise ValueError(f"Invalid slider bounds: low ({self.low}) cannot equal high ({self.high})")
        return self


class BoundCutoffBest(BaseModel):
    cutoff: float
    best: float

    @model_validator(mode="after")
    def validate_bounds(self) -> "BoundCutoffBest":
        if self.cutoff == self.best:
            raise ValueError(f"Invalid slider bounds: cutoff ({self.cutoff}) cannot equal best ({self.best})")
        return self


class FanInMix(BaseModel):
    count: float = 0.7
    strangers: float = 0.3

    @model_validator(mode="after")
    def validate_sum(self) -> "FanInMix":
        if abs((self.count + self.strangers) - 1.0) > 1e-4:
            raise ValueError(f"Mix weights must sum to 1.0, got count={self.count}, strangers={self.strangers}")
        return self


class SlidersRapidOnward(BaseModel):
    forwarded_pct: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=80.0, high=100.0))
    gap_minutes: BoundCutoffBest = Field(default_factory=lambda: BoundCutoffBest(cutoff=15.0, best=0.0))


class SlidersMultiSourceFanIn(BaseModel):
    distinct_senders: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=8.0, high=20.0))
    first_time_share: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=0.70, high=1.00))
    mix: FanInMix = Field(default_factory=FanInMix)


class SlidersFanOutSplitting(BaseModel):
    forwarded_pct: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=80.0, high=100.0))
    amount_spread_pct: BoundCutoffBest = Field(default_factory=lambda: BoundCutoffBest(cutoff=25.0, best=0.0))
    outgoing_count: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=3.0, high=8.0))


class SlidersTransactionCycle(BaseModel):
    amount_similarity: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=0.80, high=1.00))
    span_hours: BoundCutoffBest = Field(default_factory=lambda: BoundCutoffBest(cutoff=6.0, best=0.0))


class SlidersComplaintConvergence(BaseModel):
    complaints: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=2.0, high=5.0))
    traced_inr: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=500.0, high=50000.0))
    avg_hops: BoundCutoffBest = Field(default_factory=lambda: BoundCutoffBest(cutoff=3.0, best=1.0))


class SlidersNewAccountBurst(BaseModel):
    spike_multiple: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=4.0, high=20.0))
    dormant_bonus: float = 0.20


class SlidersCollectRequestAbuse(BaseModel):
    requests: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=5.0, high=15.0))
    distinct_payers: BoundLowHigh = Field(default_factory=lambda: BoundLowHigh(low=4.0, high=10.0))


class SlidersConfig(BaseModel):
    rapid_onward_transfer: SlidersRapidOnward = Field(default_factory=SlidersRapidOnward)
    multi_source_fan_in: SlidersMultiSourceFanIn = Field(default_factory=SlidersMultiSourceFanIn)
    fan_out_splitting: SlidersFanOutSplitting = Field(default_factory=SlidersFanOutSplitting)
    transaction_cycle: SlidersTransactionCycle = Field(default_factory=SlidersTransactionCycle)
    complaint_convergence: SlidersComplaintConvergence = Field(default_factory=SlidersComplaintConvergence)
    new_account_burst: SlidersNewAccountBurst = Field(default_factory=SlidersNewAccountBurst)
    collect_request_abuse: SlidersCollectRequestAbuse = Field(default_factory=SlidersCollectRequestAbuse)


# ---------------- Scoring and Escalation definitions ----------------

class PriorityThresholds(BaseModel):
    high: float = 0.75
    medium: float = 0.45


class EscalationConfig(BaseModel):
    enabled: bool = True
    family_bonus_each: float = 0.10
    family_bonus_cap: float = 0.30
    complaint_link_bonus: float = 0.10
    families: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "PASS_THROUGH": ["RAPID_ONWARD_TRANSFER", "FAN_OUT_SPLITTING"],
            "INFLOW": ["MULTI_SOURCE_FAN_IN", "COLLECT_REQUEST_ABUSE"],
            "LOOP": ["TRANSACTION_CYCLE"],
            "COMPLAINT": ["COMPLAINT_CONVERGENCE"],
            "ACCOUNT_BEHAVIOR": ["NEW_ACCOUNT_BURST"],
            "CONTEXT": ["SHARED_DEVICE"],
        }
    )

    @field_validator("families")
    @classmethod
    def validate_families(cls, v: Dict[str, List[str]]) -> Dict[str, List[str]]:
        for fam_name, rule_list in v.items():
            for r in rule_list:
                if r not in KNOWN_RULE_IDS:
                    raise ValueError(f"Unknown rule ID '{r}' in escalation family '{fam_name}'")
        return v


class ScoringConfig(BaseModel):
    version: str = "2.0"
    priority_thresholds: PriorityThresholds = Field(default_factory=PriorityThresholds)
    base_offset: float = 0.40
    rule_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "RAPID_ONWARD_TRANSFER": 1.0,
            "MULTI_SOURCE_FAN_IN": 1.0,
            "FAN_OUT_SPLITTING": 0.8,
            "TRANSACTION_CYCLE": 0.8,
            "COMPLAINT_CONVERGENCE": 1.0,
            "NEW_ACCOUNT_BURST": 0.6,
            "COLLECT_REQUEST_ABUSE": 0.8,
        }
    )
    shared_device_flat_score: float = 0.20
    complaint_score_floor: float = 0.50
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)

    @field_validator("rule_weights")
    @classmethod
    def validate_rule_weights(cls, v: Dict[str, float]) -> Dict[str, float]:
        for r in v.keys():
            if r not in KNOWN_RULE_IDS:
                raise ValueError(f"Unknown rule ID '{r}' in rule_weights")
        return v


class Config(BaseModel):
    """Root configuration object containing all rule, engine and scoring parameters."""
    model_config = ConfigDict(extra="ignore")

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    rapid_onward_transfer: RapidOnwardConfig = Field(default_factory=RapidOnwardConfig)
    multi_source_fan_in: MultiSourceFanInConfig = Field(default_factory=MultiSourceFanInConfig)
    fan_out_splitting: FanOutSplittingConfig = Field(default_factory=FanOutSplittingConfig)
    transaction_cycle: TransactionCycleConfig = Field(default_factory=TransactionCycleConfig)
    complaint_convergence: ComplaintConvergenceConfig = Field(default_factory=ComplaintConvergenceConfig)
    new_account_burst: NewAccountBurstConfig = Field(default_factory=NewAccountBurstConfig)
    collect_request_abuse: CollectRequestAbuseConfig = Field(default_factory=CollectRequestAbuseConfig)
    shared_device: SharedDeviceConfig = Field(default_factory=SharedDeviceConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    sliders: SlidersConfig = Field(default_factory=SlidersConfig)

    _raw_yaml_bytes: bytes = b""

    @property
    def config_hash(self) -> str:
        """Computes sha256 checksum of raw yaml or canonical dumped string."""
        if self._raw_yaml_bytes:
            return f"sha256:{hashlib.sha256(self._raw_yaml_bytes).hexdigest()}"
        canonical = self.model_dump_json()
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from a YAML file or return defaults if path is None."""
    if config_path is None:
        return Config()

    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found at: {path}")

    raw_bytes = path.read_bytes()
    try:
        data = yaml.safe_load(raw_bytes) or {}
    except Exception as e:
        raise ValueError(f"Failed to parse YAML file {path}: {e}") from e

    known_top_level = {
        "general",
        "rapid_onward_transfer",
        "multi_source_fan_in",
        "fan_out_splitting",
        "transaction_cycle",
        "complaint_convergence",
        "new_account_burst",
        "collect_request_abuse",
        "shared_device",
        "graph",
        "scoring",
        "sliders",
    }
    unknown = set(data.keys()) - known_top_level
    if unknown:
        logger.warning(f"Unknown keys in configuration file: {unknown}")

    cfg = Config.model_validate(data)
    cfg._raw_yaml_bytes = raw_bytes
    return cfg
