"""Pydantic models for RingScope detection engine output and internal data structures."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


PriorityLevel = Literal["high", "medium", "low"]
NodeType = Literal["account", "device", "collect_request"]
NodeRole = Literal[
    "origin_account",
    "receiving_account",
    "potential_mule",
    "destination_account",
    "linked_account",
    "shared_device",
    "origin_device",
    "collect_request",
]
EdgeKind = Literal["payment", "device_link", "request_link"]
EdgeDirection = Literal["supporting", "upstream", "downstream", "context"]


class GraphNode(BaseModel):
    """A node in the directed transaction-network graph."""
    model_config = ConfigDict(extra="forbid")

    id: str
    type: NodeType
    role: NodeRole
    label: str
    vpa: Optional[str] = None
    bank: Optional[str] = None
    accounts_on_device: Optional[int] = None
    flagged: bool = False
    alert_ids: List[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A directed edge in the transaction-network graph."""
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: EdgeKind
    source: str
    target: str
    txn_type: Optional[str] = None
    status: Optional[str] = None
    amount_inr: Optional[float] = None
    timestamp: Optional[str] = None
    sequence: Optional[int] = None
    is_supporting: bool = False
    direction: EdgeDirection
    reported: Optional[bool] = None
    complaint_ids: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)


class Graph(BaseModel):
    """Directed transaction-network graph representation."""
    model_config = ConfigDict(extra="forbid")

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    truncated: bool = False
    omitted_edges: int = 0
    disclaimer: str = "Roles are investigative hypotheses to support review, not findings of wrongdoing."


class SkippedRule(BaseModel):
    """Details of a skipped detection rule."""
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    reason: str


class Meta(BaseModel):
    """Metadata block for the detection engine run."""
    model_config = ConfigDict(extra="forbid")

    engine_version: str = "1.0.0"
    scoring_version: Optional[str] = "2.0"
    config_hash: str
    rules_run: List[str] = Field(default_factory=list)
    rules_skipped: List[SkippedRule] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)
    dropped_rows: Dict[str, int] = Field(default_factory=dict)
    graph_schema_version: Optional[str] = None
    graph_mode: Optional[str] = None
    total_graph_nodes: Optional[int] = None
    total_graph_edges: Optional[int] = None


class Alert(BaseModel):
    """Model representing an alert emitted by a detection rule."""
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    rule_id: str
    title: str
    priority: PriorityLevel
    score: float
    created_at: str
    account_ids: List[str] = Field(default_factory=list)
    vpas: List[str] = Field(default_factory=list)
    txn_ids: List[str] = Field(default_factory=list)
    linked_txn_ids: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    limitations: str
    alternative_explanations: List[str] = Field(default_factory=list)
    would_clear_if: List[str] = Field(default_factory=list)
    complaint_ids: List[str] = Field(default_factory=list)
    related_alert_ids: List[str] = Field(default_factory=list)
    ring_id: Optional[str] = None
    informational_only: bool = False
    graph: Optional[Graph] = None


class Ring(BaseModel):
    """Model representing a connected ring of flagged accounts."""
    model_config = ConfigDict(extra="forbid")

    ring_id: str
    account_ids: List[str] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)
    highest_priority: PriorityLevel
    highest_score: Optional[float] = None
    graph: Optional[Graph] = None


class AccountSummary(BaseModel):
    """Summary of detection alerts per account."""
    model_config = ConfigDict(extra="forbid")

    account_id: str
    alert_ids: List[str] = Field(default_factory=list)
    highest_priority: PriorityLevel
    highest_score: Optional[float] = None


class Output(BaseModel):
    """Top-level output schema for RingScope detection engine."""
    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    generated_at: str
    amount_unit: str = "inr"
    count: int
    meta: Meta
    alerts: List[Alert] = Field(default_factory=list)
    rings: List[Ring] = Field(default_factory=list)
    account_summaries: List[AccountSummary] = Field(default_factory=list)
