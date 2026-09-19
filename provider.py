"""
Blockchain Provider Abstraction

Defines the interface for blockchain data providers.
Implementations: Ethereum (live, via Etherscan), Demo (offline, deterministic).
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Transaction:
    """Normalized transaction representation."""

    hash: str
    from_address: str
    to_address: Optional[str]
    value: float  # In ETH or native currency
    gas_price: float
    gas_used: Optional[float]
    timestamp: datetime
    block_number: int
    is_failed: bool = False
    input_data: str = "0x"
    contract_address: Optional[str] = None
    token_transfers: int = 0
    type: str = "transaction"  # transaction, internal_transaction, token_transfer


@dataclass
class Contract:
    """Smart contract information."""

    address: str
    is_verified: bool
    compiler_version: Optional[str]
    source_code: Optional[str]
    creator_address: Optional[str]
    creation_block: Optional[int]
    creation_timestamp: Optional[datetime] = None
    has_proxy: bool = False
    admin_address: Optional[str] = None


class BlockchainProvider(ABC):
    """Abstract base class for blockchain data providers."""

    def __init__(self, network: str, chain_id: int):
        self.network = network
        self.chain_id = chain_id
        self.name = f"{network} (Chain {chain_id})"

    @abstractmethod
    async def is_contract(self, address: str) -> bool:
        """Check if an address is a smart contract."""
        raise NotImplementedError

    @abstractmethod
    async def get_transactions(self, address: str, limit: int = 10000) -> List[Transaction]:
        """Fetch transactions for an address, most recent first."""
        raise NotImplementedError

    @abstractmethod
    async def get_contract_info(self, address: str) -> Optional[Contract]:
        """Get contract information if address is a contract."""
        raise NotImplementedError

    @abstractmethod
    async def get_balance(self, address: str) -> float:
        """Get current balance of an address."""
        raise NotImplementedError

    @abstractmethod
    async def get_token_transfers(self, address: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get ERC-20 token transfers for an address."""
        raise NotImplementedError

    @abstractmethod
    async def get_first_transaction_timestamp(self, address: str) -> Optional[datetime]:
        """Get timestamp of first transaction."""
        raise NotImplementedError

    @abstractmethod
    async def get_flagged_addresses(self) -> List[str]:
        """Get list of known flagged/suspicious addresses relevant to this network."""
        raise NotImplementedError

    async def classify_counterparties(self, addresses: List[str]) -> Dict[str, bool]:
        """
        Best-effort classification of counterparty addresses as contracts (True)
        or EOAs (False). Default implementation conservatively treats every
        address as an EOA; providers may override with real lookups.
        """
        return {addr.lower(): False for addr in addresses}
