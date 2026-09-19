"""
Demo Blockchain Provider

Provides realistic, fully deterministic sample data so ChainGuard works
completely offline with no API keys and no internet access. Every field
returned here is synthetic scenario data — never presented as live
blockchain data (see the DEMO DATA banner enforced by the frontend and
the `is_demo_data` flag on every API response).
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from blockchain.provider import BlockchainProvider, Transaction, Contract
from threat_intel.database import get_threat_intel

logger = logging.getLogger(__name__)

# Single source of truth for the five demo scenarios. routers/analyze.py and
# the tests import these so an address can never drift out of sync.
LOW_RISK_ADDRESS = "0xabcd000000000000000000000000000000000001"
SUSPICIOUS_CONTRACT_ADDRESS = "0xdead000000000000000000000000000000000002"
ACTIVE_DEFI_ADDRESS = "0xdef1000000000000000000000000000000000003"
HIGH_RISK_ADDRESS = "0xbad0000000000000000000000000000000000004"
REVIEW2_ANOMALY_ADDRESS = "0x4444444444444444444444444444444444444444"

DEMO_SCENARIO_ADDRESSES = {
    "low_risk_wallet": LOW_RISK_ADDRESS,
    "suspicious_contract": SUSPICIOUS_CONTRACT_ADDRESS,
    "active_defi_wallet": ACTIVE_DEFI_ADDRESS,
    "high_risk_wallet": HIGH_RISK_ADDRESS,
    "review2_anomaly_wallet": REVIEW2_ANOMALY_ADDRESS,
}

DRAINER_ADDRESS = "0x6666666666666666666666666666666666666666"
UNI_TOKEN_CONTRACT = "0x1111111111111111111111111111111111111111"
AAVE_TOKEN_CONTRACT = "0x2222222222222222222222222222222222222222"


class DemoProvider(BlockchainProvider):
    """Deterministic offline data provider covering five demo scenarios."""

    # Addresses that should be classified as contracts in demo mode,
    # independent of which address is being analyzed.
    KNOWN_CONTRACTS = {
        "0xdead000000000000000000000000000000000002",
        "0x6666666666666666666666666666666666666666",
        UNI_TOKEN_CONTRACT,
        AAVE_TOKEN_CONTRACT,
    }

    def __init__(self, network: str = "ethereum_mainnet", chain_id: int = 1):
        super().__init__(network, chain_id)
        self.demo_addresses = self._generate_demo_data()

    def _generate_demo_data(self) -> Dict[str, Dict]:
        """Generate the fixed set of demo scenarios."""

        now = datetime.utcnow()
        one_month_ago = now - timedelta(days=30)
        two_years_ago = now - timedelta(days=730)

        # Active DeFi wallet data (most recent first, like a live provider).
        defi_transactions = [
            Transaction(
                hash="0x" + format(i, "064x"),
                from_address=ACTIVE_DEFI_ADDRESS,
                to_address=UNI_TOKEN_CONTRACT if i % 2 == 0 else AAVE_TOKEN_CONTRACT,
                value=round(0.05 * (1 + i % 20), 4),
                gas_price=40.0 + (i % 10) * 3,
                gas_used=68000 + (i % 7) * 1000,
                timestamp=now - timedelta(days=2) - timedelta(days=2.6 * i),
                block_number=19000000 - (i * 190),
                input_data="0xa9059cbb" + "0" * 64,
                type="transaction",
            )
            for i in range(150)
        ]
        defi_token_transfers = [
            {
                "hash": "0x" + format(0x1000 + i, "064x"),
                "from": ACTIVE_DEFI_ADDRESS if i % 2 == 0 else AAVE_TOKEN_CONTRACT,
                "to": UNI_TOKEN_CONTRACT if i % 2 == 0 else ACTIVE_DEFI_ADDRESS,
                "value": float(100 + i),
                "token_name": "Uniswap" if i % 2 == 0 else "Aave",
                "token_symbol": "UNI" if i % 2 == 0 else "AAVE",
                "timestamp": now - timedelta(days=3) - timedelta(days=3 * i),
            }
            for i in range(120)
        ]

        return {
            # ------------------------------------------------------------
            # Scenario 1: low-risk demo wallet — long-time, quiet holder
            # ------------------------------------------------------------
            LOW_RISK_ADDRESS: {
                "type": "eoa",
                "scenario": "Low-risk demo wallet: long-time holder",
                "transactions": [
                    Transaction(
                        hash="0x" + "a" * 64,
                        from_address="0xabcd000000000000000000000000000000000001",
                        to_address="0x1234567890123456789012345678901234567890",
                        value=10.5,
                        gas_price=45.2,
                        gas_used=21000,
                        timestamp=two_years_ago,
                        block_number=14000000,
                        input_data="0x",
                        type="transaction",
                    ),
                    Transaction(
                        hash="0x" + "b" * 64,
                        from_address="0xabcd000000000000000000000000000000000001",
                        to_address="0x7777777777777777777777777777777777777777",
                        value=5.2,
                        gas_price=50.0,
                        gas_used=21000,
                        timestamp=one_month_ago,
                        block_number=17000000,
                        input_data="0x",
                        type="transaction",
                    ),
                ],
                "is_contract": False,
                "balance": 25.5,
                "first_tx": two_years_ago,
                "contract_info": None,
                "token_transfers": [],
            },
            # ------------------------------------------------------------
            # Scenario 2: suspicious demo contract — newly deployed,
            # unverified, flagged by threat intel
            # ------------------------------------------------------------
            SUSPICIOUS_CONTRACT_ADDRESS: {
                "type": "contract",
                "scenario": "Suspicious demo contract: unverified & recently deployed",
                "transactions": [
                    Transaction(
                        hash="0x" + "c" * 64,
                        from_address="0x9999999999999999999999999999999999999999",
                        to_address="0xdead000000000000000000000000000000000002",
                        value=0.0,
                        gas_price=100.0,
                        gas_used=500000,
                        timestamp=now - timedelta(days=5),
                        block_number=18000000,
                        input_data="0x608060405234801561001057600080fd5b50",
                        type="transaction",
                    ),
                    Transaction(
                        hash="0x" + "d" * 64,
                        from_address="0x0000000000000000000000000000000000000001",
                        to_address="0xdead000000000000000000000000000000000002",
                        value=100.0,
                        gas_price=80.0,
                        gas_used=25000,
                        timestamp=now - timedelta(days=4),
                        block_number=18000050,
                        input_data="0x",
                        is_failed=True,
                        type="transaction",
                    ),
                ],
                "is_contract": True,
                "balance": 50.0,
                "first_tx": now - timedelta(days=5),
                "contract_info": Contract(
                    address="0xdead000000000000000000000000000000000002",
                    is_verified=False,
                    compiler_version=None,
                    source_code=None,
                    creator_address="0x9999999999999999999999999999999999999999",
                    creation_block=18000000,
                    creation_timestamp=now - timedelta(days=5),
                    has_proxy=False,
                ),
                "token_transfers": [],
            },
            # ------------------------------------------------------------
            # Scenario 3: active DeFi user — 150 transactions over ~13
            # months, all successful, plus 120 token transfers. Built so it
            # genuinely triggers the three positive signals (moderate
            # transaction volume, long activity history, active token
            # holder) and none of the negative ones.
            # ------------------------------------------------------------
            ACTIVE_DEFI_ADDRESS: {
                "type": "eoa",
                "scenario": "Active DeFi wallet: high-volume, established history",
                "transactions": defi_transactions,
                "is_contract": False,
                "balance": 15.3,
                "first_tx": defi_transactions[-1].timestamp,
                "contract_info": None,
                "token_transfers": defi_token_transfers,
            },
            # ------------------------------------------------------------
            # Scenario 4: high-risk demo wallet — new address, interacts
            # with a threat-intel-flagged drainer, recent failure burst
            # ------------------------------------------------------------
            # ------------------------------------------------------------
            # Scenario 5: Review-2 anomaly showcase — statistical outliers,
            # concentration, approval exposure, rapid pass-through, and a
            # direct round-trip pattern. This is intentionally deterministic
            # so the new reviewer-requested features can be demonstrated offline.
            # ------------------------------------------------------------
            REVIEW2_ANOMALY_ADDRESS: {
                "type": "eoa",
                "scenario": "Review-2 anomaly showcase: statistical + behavioral signals",
                "transactions": [
                    Transaction(hash="0x" + "4" * 64, from_address=REVIEW2_ANOMALY_ADDRESS,
                                to_address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", value=50.0, gas_price=500.0,
                                gas_used=21000, timestamp=now - timedelta(minutes=3), block_number=18600000, input_data="0x"),
                    Transaction(hash="0x" + "5" * 64, from_address="0x9999999999999999999999999999999999999999",
                                to_address=REVIEW2_ANOMALY_ADDRESS, value=55.0, gas_price=20.0,
                                gas_used=21000, timestamp=now - timedelta(minutes=6), block_number=18599990, input_data="0x"),
                    Transaction(hash="0x" + "6" * 64, from_address=REVIEW2_ANOMALY_ADDRESS,
                                to_address="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", value=2.0, gas_price=20.0,
                                gas_used=21000, timestamp=now - timedelta(days=2), block_number=18590000, input_data="0x"),
                    Transaction(hash="0x" + "7" * 64, from_address="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                to_address=REVIEW2_ANOMALY_ADDRESS, value=1.5, gas_price=20.0,
                                gas_used=21000, timestamp=now - timedelta(days=1, hours=23), block_number=18590010, input_data="0x"),
                    Transaction(hash="0x" + "8" * 64, from_address=REVIEW2_ANOMALY_ADDRESS,
                                to_address="0xcccccccccccccccccccccccccccccccccccccccc", value=0.0, gas_price=22.0,
                                gas_used=50000, timestamp=now - timedelta(hours=1), block_number=18595000,
                                input_data="0x095ea7b3" + "dddddddddddddddddddddddddddddddddddddddd".rjust(64, "0") + format(2**256 - 1, "064x")),
                ] + [
                    Transaction(hash="0x" + format(0x9000 + i, "064x"), from_address=REVIEW2_ANOMALY_ADDRESS,
                                to_address="0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", value=1.0, gas_price=20.0,
                                gas_used=21000, timestamp=now - timedelta(days=10 + i), block_number=18500000 - i, input_data="0x")
                    for i in range(5)
                ],
                "is_contract": False,
                "balance": 60.0,
                "first_tx": now - timedelta(days=60),
                "contract_info": None,
                "token_transfers": [],
            },
            HIGH_RISK_ADDRESS: {
                "type": "eoa",
                "scenario": "High-risk demo wallet: flagged interaction + activity burst",
                "transactions": (
                    [
                        Transaction(
                            hash="0x" + "1" * 63 + "0",
                            from_address="0xbad0000000000000000000000000000000000004",
                            to_address=DRAINER_ADDRESS,
                            value=0.2,
                            gas_price=120.0,
                            gas_used=21000,
                            timestamp=now - timedelta(days=2, hours=1),
                            block_number=18500000,
                            input_data="0x",
                            type="transaction",
                        )
                    ]
                    + [
                        Transaction(
                            hash="0x" + "2" * 63 + format(i, "x"),
                            from_address="0xbad0000000000000000000000000000000000004",
                            to_address=f"0x{i:040x}",
                            value=0.01 * i,
                            gas_price=120.0,
                            gas_used=21000,
                            timestamp=now - timedelta(days=1, hours=i),
                            block_number=18500010 + i,
                            input_data="0x",
                            is_failed=(i % 3 != 0),
                            type="transaction",
                        )
                        for i in range(1, 23)
                    ]
                ),
                "is_contract": False,
                "balance": 0.4,
                "first_tx": now - timedelta(days=12),
                "contract_info": None,
                "token_transfers": [],
            },
        }

    async def is_contract(self, address: str) -> bool:
        data = self.demo_addresses.get(address.lower())
        if data:
            return data.get("is_contract", False)
        return False

    async def get_transactions(self, address: str, limit: int = 10000) -> List[Transaction]:
        data = self.demo_addresses.get(address.lower())
        if data:
            # Provider contract: most recent first (matches the live provider).
            ordered = sorted(data.get("transactions", []), key=lambda tx: tx.timestamp, reverse=True)
            return ordered[:limit]
        logger.info(f"No demo data for address {address}; returning empty transaction list.")
        return []

    async def get_contract_info(self, address: str) -> Optional[Contract]:
        data = self.demo_addresses.get(address.lower())
        if data:
            return data.get("contract_info")
        return None

    async def get_balance(self, address: str) -> float:
        data = self.demo_addresses.get(address.lower())
        if data:
            return data.get("balance", 0.0)
        return 0.0

    async def get_token_transfers(self, address: str, limit: int = 1000) -> List[Dict[str, Any]]:
        data = self.demo_addresses.get(address.lower())
        if data:
            return data.get("token_transfers", [])[:limit]
        return []

    async def get_first_transaction_timestamp(self, address: str) -> Optional[datetime]:
        data = self.demo_addresses.get(address.lower())
        if data:
            return data.get("first_tx")
        return None

    async def get_flagged_addresses(self) -> List[str]:
        """Flagged addresses come from the shared curated threat-intel dataset."""
        return get_threat_intel().get_flagged_addresses(self.network)

    async def classify_counterparties(self, addresses: List[str]) -> Dict[str, bool]:
        """Demo mode has ground truth for its own known contract addresses."""
        return {addr.lower(): addr.lower() in self.KNOWN_CONTRACTS for addr in addresses}
