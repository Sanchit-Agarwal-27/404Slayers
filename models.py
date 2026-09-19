"""
ChainGuard Data Models

Pydantic models for request/response validation and type safety.
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class AddressType(str, Enum):
    """Type of blockchain address."""
    EOA = "eoa"  # Externally Owned Account (wallet)
    CONTRACT = "contract"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    VERY_LOW = "very_low"


class SignalType(str, Enum):
    """Type of risk signal."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class Chain(str, Enum):
    """Supported blockchain networks."""
    ETHEREUM_MAINNET = "ethereum_mainnet"
    SEPOLIA = "sepolia"


# ============================================================================
# Request Models
# ============================================================================

class AddressAnalysisRequest(BaseModel):
    """Request to analyze a blockchain address."""

    address: str = Field(..., description="Blockchain address (EVM format)")
    chain: Chain = Field(default=Chain.ETHEREUM_MAINNET, description="Blockchain network")
    include_transactions: bool = Field(default=True, description="Include detailed transaction analysis")
    include_graph: bool = Field(default=True, description="Include interaction graph")

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate EVM address format."""
        v = v.strip()
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid EVM address format. Must be 0x followed by 40 hex characters.")
        if not all(c in "0123456789abcdefABCDEF" for c in v[2:]):
            raise ValueError("Address contains invalid hex characters.")
        return v.lower()


# ============================================================================
# Response Models
# ============================================================================

class Signal(BaseModel):
    """A single risk or positive signal contributing to the reputation score."""

    signal_type: SignalType
    name: str = Field(..., description="Signal name (e.g., 'Flagged Address Interaction')")
    description: str = Field(..., description="Human-readable description, phrased as a signal, not a verdict")
    weight: float = Field(..., description="Deterministic impact on reputation score")
    severity: str = Field(default="info", description="info | low | medium | high | critical")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Supporting evidence for this signal")
    source: str = Field(..., description="Data source / analysis module that produced this signal")
    confidence: float = Field(default=1.0, ge=0, le=1, description="Confidence in this signal (0-1)")


class ActivityMetrics(BaseModel):
    """Activity metrics for an address."""

    transaction_count: int = Field(..., description="Total transaction count")
    unique_counterparties: int = Field(..., description="Number of unique addresses interacted with")
    unique_contracts: int = Field(..., description="Number of counterparties classified as contracts (best-effort)")
    first_seen: Optional[datetime] = Field(None, description="First transaction timestamp")
    last_active: Optional[datetime] = Field(None, description="Last transaction timestamp")
    incoming_value_sum: float = Field(default=0, description="Total incoming native-currency value")
    outgoing_value_sum: float = Field(default=0, description="Total outgoing native-currency value")
    failed_transaction_count: int = Field(default=0, description="Failed transactions")
    token_transfers: int = Field(default=0, description="ERC-20 token transfers")


class ReputationScore(BaseModel):
    """Reputation/risk score result. Always computed deterministically — never by an LLM."""

    score: int = Field(..., ge=0, le=100, description="Reputation score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk classification")
    signals: List[Signal] = Field(..., description="Signals contributing to score, each with evidence")
    positive_signal_count: int = Field(default=0)
    negative_signal_count: int = Field(default=0)
    reasoning: str = Field(..., description="Human-readable explanation of score")
    recommendation: str = Field(..., description="Security recommendation based on the risk level")


class AddressInfo(BaseModel):
    """Basic information about an address."""

    address: str = Field(..., description="The analyzed address")
    address_type: AddressType = Field(..., description="Type of address (EOA/Contract/Unknown)")
    chain: str = Field(..., description="Blockchain network display name")
    chain_id: int = Field(..., description="Chain ID")
    activity_metrics: ActivityMetrics = Field(..., description="Activity statistics")


class ContractInfo(BaseModel):
    """Additional information for contract addresses."""

    is_verified: bool = Field(default=False, description="Is contract source verified on explorer")
    compiler_version: Optional[str] = Field(None, description="Solidity compiler version if verified")
    has_proxy: bool = Field(default=False, description="Is this a proxy contract")
    admin_address: Optional[str] = Field(None, description="Admin/owner if detectable")
    creation_block: Optional[int] = Field(None, description="Block contract was deployed")
    creation_timestamp: Optional[datetime] = Field(None, description="Time contract was deployed")


class TransactionSummary(BaseModel):
    """A single transaction, normalized for display."""

    hash: str
    from_address: str
    to_address: Optional[str]
    value: float
    timestamp: datetime
    block_number: int
    is_failed: bool = False
    direction: str = Field(..., description="in | out")


class InteractionGraphNode(BaseModel):
    """Node in an interaction graph."""

    address: str
    type: AddressType
    is_central: bool = False
    is_flagged: bool = False
    interaction_count: int = 0


class InteractionGraphEdge(BaseModel):
    """Edge in an interaction graph."""

    from_address: str
    to_address: str
    edge_type: str = Field(..., description="transaction, transfer, contract_interaction")
    count: int = 1
    value_sum: Optional[float] = None


class InteractionGraph(BaseModel):
    """Graph of address interactions, generated deterministically from transaction data."""

    nodes: List[InteractionGraphNode]
    edges: List[InteractionGraphEdge]
    truncated: bool = Field(default=False, description="True if graph was capped to the top N counterparties")


class AddressAnalysisResponse(BaseModel):
    """Complete analysis of a blockchain address."""

    address_info: AddressInfo
    reputation_score: ReputationScore
    contract_info: Optional[ContractInfo] = None
    interaction_graph: Optional[InteractionGraph] = None
    recent_transactions: List[TransactionSummary] = Field(default_factory=list)
    is_demo_data: bool = Field(False, description="Is this demo data or real blockchain data?")
    data_source: str = Field(default="demo", description="'demo' or the live provider name")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SearchHistoryEntry(BaseModel):
    """Entry in search history."""

    address: str
    chain: str
    score: int
    risk_level: RiskLevel
    timestamp: datetime
    is_demo: bool


class SearchHistoryResponse(BaseModel):
    """User's search history."""

    entries: List[SearchHistoryEntry]
    total_count: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    demo_mode: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
