"""
Ethereum Blockchain Provider (LIVE MODE)

Fetches real blockchain data from Ethereum networks via the Etherscan API.
Supports Ethereum Mainnet and Sepolia Testnet. Requires an Etherscan API
key; see core.config / .env.example.
"""

import aiohttp
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import logging

from blockchain.provider import BlockchainProvider, Transaction, Contract
from threat_intel.database import get_threat_intel

logger = logging.getLogger(__name__)


def _utc_naive(timestamp: Any) -> datetime:
    """Unix seconds -> naive UTC datetime (the risk engine compares against utcnow())."""
    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).replace(tzinfo=None)


class EthereumProvider(BlockchainProvider):
    """Ethereum/EVM live blockchain data provider (Etherscan-backed)."""

    def __init__(
        self,
        network: str,
        chain_id: int,
        etherscan_api_key: str,
        etherscan_url: str,
        timeout_seconds: int = 15,
        max_classification_calls: int = 12,
    ):
        super().__init__(network, chain_id)
        self.etherscan_api_key = etherscan_api_key
        self.etherscan_url = etherscan_url
        self.timeout_seconds = timeout_seconds
        self.max_classification_calls = max_classification_calls

    async def _etherscan_request(self, params: Dict[str, str]) -> Dict[str, Any]:
        """
        Make a single request to the Etherscan API V2 with a fresh session.

        Raises ConnectionError on transport failures AND on Etherscan-reported
        errors (status "0" / message "NOTOK": invalid key, rate limit,
        deprecated endpoint, ...). Errors are never treated as "no data" —
        that would silently produce an empty, misleading analysis.
        """
        params = dict(params)
        params["apikey"] = self.etherscan_api_key
        params["chainid"] = str(self.chain_id)

        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.etherscan_url, params=params) as resp:
                    if resp.status != 200:
                        logger.error(f"Etherscan API error: HTTP {resp.status}")
                        raise ConnectionError(f"Etherscan API returned HTTP {resp.status}")
                    payload = await resp.json(content_type=None)
                    if payload.get("status") == "0" and payload.get("message") == "NOTOK":
                        detail = payload.get("result")
                        logger.error(f"Etherscan API error: {detail}")
                        raise ConnectionError(f"Etherscan API error: {detail}")
                    if payload.get("error"):
                        raise ConnectionError(f"Etherscan API error: {payload['error']}")
                    return payload
        except asyncio.TimeoutError:
            logger.error("Etherscan API timeout")
            raise ConnectionError("Etherscan API request timed out")
        except aiohttp.ClientError as e:
            logger.error(f"Etherscan request failed: {e}")
            raise ConnectionError(f"Etherscan API request failed: {e}")

    async def get_code(self, address: str) -> str:
        """
        Get the deployed bytecode via eth_getCode ("0x" means no code, i.e. an EOA).

        eth_getCode is used deliberately rather than getsourcecode: an
        *unverified* contract has an empty SourceCode field and would
        otherwise be misclassified as a wallet — exactly the case that matters.
        """
        params = {"module": "proxy", "action": "eth_getCode", "address": address, "tag": "latest"}
        result = await self._etherscan_request(params)
        code = result.get("result")
        return code if isinstance(code, str) and code else "0x"

    async def is_contract(self, address: str) -> bool:
        try:
            code = await self.get_code(address)
            return code != "0x"
        except ConnectionError:
            raise
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False

    async def get_transactions(self, address: str, limit: int = 10000) -> List[Transaction]:
        """Fetch transactions for an address (most recent first)."""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": "0",
            "endblock": "99999999",
            "sort": "desc",
        }

        result = await self._etherscan_request(params)

        if result.get("status") != "1":
            logger.info(f"No transactions found for {address}: {result.get('message')}")
            return []

        transactions = []
        for tx in result.get("result", [])[:limit]:
            try:
                transactions.append(
                    Transaction(
                        hash=tx.get("hash", ""),
                        from_address=(tx.get("from") or "").lower(),
                        to_address=(tx.get("to") or "").lower() or None,
                        value=float(tx.get("value", 0)) / 1e18,
                        gas_price=float(tx.get("gasPrice", 0)) / 1e9,
                        gas_used=float(tx.get("gasUsed", 0)) if tx.get("gasUsed") else None,
                        timestamp=_utc_naive(tx.get("timeStamp", 0)),
                        block_number=int(tx.get("blockNumber", 0)),
                        is_failed=(tx.get("isError", "0") == "1"),
                        input_data=tx.get("input", "0x"),
                        type="transaction",
                    )
                )
            except (ValueError, KeyError) as e:
                logger.warning(f"Skipping unparseable transaction: {e}")
                continue

        return transactions

    async def get_contract_info(self, address: str) -> Optional[Contract]:
        params = {"module": "contract", "action": "getsourcecode", "address": address}
        result = await self._etherscan_request(params)

        if result.get("status") != "1" or not result.get("result"):
            return None

        contract_data = result["result"][0]
        source = contract_data.get("SourceCode", "") or ""
        has_proxy = "proxy" in source.lower() or "delegatecall" in source.lower()

        creation_block = None
        try:
            if contract_data.get("CreationBlockNumber"):
                creation_block = int(contract_data["CreationBlockNumber"])
        except (ValueError, TypeError):
            creation_block = None

        return Contract(
            address=address,
            is_verified=(source != ""),
            compiler_version=contract_data.get("CompilerVersion") or None,
            source_code=source or None,
            creator_address=contract_data.get("Creator") or contract_data.get("ContractCreator") or None,
            creation_block=creation_block,
            creation_timestamp=None,  # Etherscan's free getsourcecode endpoint doesn't return this
            has_proxy=has_proxy,
            admin_address=None,
        )

    async def get_balance(self, address: str) -> float:
        params = {"module": "account", "action": "balance", "address": address, "tag": "latest"}
        result = await self._etherscan_request(params)
        if result.get("status") == "1":
            return int(result.get("result", 0)) / 1e18
        return 0.0

    async def get_token_transfers(self, address: str, limit: int = 1000) -> List[Dict[str, Any]]:
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": "0",
            "endblock": "99999999",
            "sort": "desc",
        }
        result = await self._etherscan_request(params)
        if result.get("status") != "1":
            return []

        transfers = []
        for tx in result.get("result", [])[:limit]:
            try:
                decimals = int(tx.get("tokenDecimal", 18) or 18)
                transfers.append(
                    {
                        "hash": tx.get("hash"),
                        "from": (tx.get("from") or "").lower(),
                        "to": (tx.get("to") or "").lower(),
                        "value": float(tx.get("value", 0)) / (10 ** decimals),
                        "token_name": tx.get("tokenName"),
                        "token_symbol": tx.get("tokenSymbol"),
                        "timestamp": _utc_naive(tx.get("timeStamp", 0)),
                    }
                )
            except (ValueError, KeyError):
                continue
        return transfers

    async def get_first_transaction_timestamp(self, address: str) -> Optional[datetime]:
        transactions = await self.get_transactions(address)
        if transactions:
            # Results are sorted descending, so the oldest is last.
            return transactions[-1].timestamp
        return None

    async def get_flagged_addresses(self) -> List[str]:
        """
        Known-flagged addresses for LIVE mode currently come from the same
        curated demo/reference threat-intel dataset used by demo mode (see
        threat_intel/flagged_addresses.json). This is a clearly-labelled
        placeholder for a real threat-intelligence integration (Chainalysis,
        OpenChain, TRM, etc.) — see README.md, "Limitations".
        """
        return get_threat_intel().get_flagged_addresses(self.network)

    async def classify_counterparties(self, addresses: List[str]) -> Dict[str, bool]:
        """
        Best-effort contract classification for live mode. Bounded to
        `max_classification_calls` addresses to keep response times
        reasonable; the rest are conservatively reported as unknown/EOA.
        """
        result: Dict[str, bool] = {}
        for addr in addresses[: self.max_classification_calls]:
            try:
                result[addr.lower()] = await self.is_contract(addr)
            except ConnectionError:
                result[addr.lower()] = False
        for addr in addresses[self.max_classification_calls :]:
            result[addr.lower()] = False
        return result
