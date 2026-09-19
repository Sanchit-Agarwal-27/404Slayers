"""
Address Analysis Routes

POST /api/analyze - Main endpoint for analyzing wallet/contract addresses.
GET  /api/analyze/demo/{scenario} - Convenience endpoints for the 4 demo scenarios.
"""

import logging
from fastapi import APIRouter, HTTPException
from datetime import datetime

from core.config import get_settings, NETWORKS
from core.models import (
    AddressAnalysisRequest,
    AddressAnalysisResponse,
    AddressInfo,
    AddressType,
    ActivityMetrics,
    ContractInfo,
    TransactionSummary,
    Chain,
    MultiChainAnalysisRequest,
    MultiChainAnalysisResponse,
)
from blockchain.eth_provider import EthereumProvider
from blockchain.demo_provider import DemoProvider, DEMO_SCENARIO_ADDRESSES
from blockchain.provider import BlockchainProvider
from risk_engine.scoring import get_scorer
from risk_engine.graph import build_interaction_graph
from threat_intel.database import get_threat_intel
from storage.database import save_analysis, add_to_search_history

logger = logging.getLogger(__name__)

router = APIRouter()

# The four fixed demo scenarios (defined once, in blockchain/demo_provider.py).
DEMO_SCENARIOS = DEMO_SCENARIO_ADDRESSES


async def get_provider(chain: str) -> BlockchainProvider:
    """
    Select the blockchain provider for this request.

    USE_DEMO_MODE is the single source of truth. ChainGuard never silently
    substitutes demo data for a live request — if live mode is selected but
    no API key is configured for the requested chain, this raises a clear
    error instead.
    """
    settings = get_settings()
    network_info = NETWORKS.get(chain)
    if not network_info:
        raise HTTPException(status_code=400, detail=f"Unsupported chain: {chain}")

    if settings.use_demo_mode:
        return DemoProvider(network=chain, chain_id=network_info["chain_id"])

    api_key = settings.etherscan_api_key or getattr(settings, network_info["etherscan_key"], "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Live mode is enabled (USE_DEMO_MODE=false) but no Etherscan API key is configured "
                f"for {network_info['name']} ({network_info['etherscan_key'].upper()}). "
                f"Set that variable in .env, or set USE_DEMO_MODE=true to use offline demo data."
            ),
        )

    return EthereumProvider(
        network=chain,
        chain_id=network_info["chain_id"],
        etherscan_api_key=api_key,
        etherscan_url=network_info["etherscan_url"],
        timeout_seconds=settings.provider_timeout_seconds,
        max_classification_calls=settings.max_counterparty_classification_calls,
    )


async def _run_analysis(
    request: AddressAnalysisRequest,
    provider: BlockchainProvider,
    chain_override: str = None,
) -> AddressAnalysisResponse:
    """Shared analysis pipeline used by both /analyze and the demo-scenario shortcuts."""
    address = request.address.lower()
    chain = chain_override or request.chain.value
    is_demo_data = isinstance(provider, DemoProvider)

    logger.info(f"Analyzing address {address} on {chain} (demo={is_demo_data})")

    try:
        transactions = await provider.get_transactions(address)
        is_contract = await provider.is_contract(address)
        contract_info_data = await provider.get_contract_info(address) if is_contract else None
        balance = await provider.get_balance(address)
        token_transfers = await provider.get_token_transfers(address)
        first_tx_timestamp = await provider.get_first_transaction_timestamp(address)
        flagged_addresses = await provider.get_flagged_addresses()
    except ConnectionError as e:
        logger.error(f"Provider fetch failed for {address} on {chain}: {e}")
        raise HTTPException(
            status_code=502,
            detail=(
                f"Failed to fetch live blockchain data from the upstream provider: {e}. "
                f"Try again shortly, or set USE_DEMO_MODE=true to use offline demo data."
            ),
        )

    # Counterparty classification (for graph node types + unique_contracts metric)
    counterparty_addresses = sorted(
        {
            (tx.to_address if tx.from_address.lower() == address else tx.from_address).lower()
            for tx in transactions
            if (tx.to_address if tx.from_address.lower() == address else tx.from_address)
        }
    )
    classification = (
        await provider.classify_counterparties(counterparty_addresses) if counterparty_addresses else {}
    )
    unique_contract_counterparties = sum(1 for v in classification.values() if v)

    # Deterministic risk scoring
    threat_intel_lookup = get_threat_intel().lookup_for_chain(chain)
    scorer = get_scorer()
    reputation = scorer.calculate_full_reputation(
        address=address,
        transactions=transactions,
        is_contract=is_contract,
        contract_info=contract_info_data.__dict__ if contract_info_data else None,
        balance=balance,
        token_transfers=token_transfers,
        first_tx_timestamp=first_tx_timestamp,
        threat_intel_lookup=threat_intel_lookup,
    )

    # Address info
    network_info = NETWORKS.get(chain, {})
    last_active = transactions[0].timestamp if transactions else None
    address_info = AddressInfo(
        address=address,
        address_type=AddressType.CONTRACT if is_contract else AddressType.EOA,
        chain=network_info.get("name", chain),
        chain_id=network_info.get("chain_id", 1),
        activity_metrics=ActivityMetrics(
            transaction_count=len(transactions),
            unique_counterparties=len(counterparty_addresses),
            unique_contracts=unique_contract_counterparties,
            first_seen=first_tx_timestamp,
            last_active=last_active,
            incoming_value_sum=sum(
                tx.value for tx in transactions if tx.to_address and tx.to_address.lower() == address
            ),
            outgoing_value_sum=sum(tx.value for tx in transactions if tx.from_address.lower() == address),
            failed_transaction_count=sum(1 for tx in transactions if tx.is_failed),
            token_transfers=len(token_transfers),
        ),
    )

    contract_info = None
    if is_contract and contract_info_data:
        contract_info = ContractInfo(
            is_verified=contract_info_data.is_verified,
            compiler_version=contract_info_data.compiler_version,
            has_proxy=contract_info_data.has_proxy,
            admin_address=contract_info_data.admin_address,
            creation_block=contract_info_data.creation_block,
            creation_timestamp=contract_info_data.creation_timestamp,
        )

    interaction_graph = None
    if request.include_graph:
        interaction_graph = build_interaction_graph(
            address=address,
            transactions=transactions,
            is_contract=is_contract,
            flagged_addresses=flagged_addresses,
            contract_classification=classification,
        )

    recent_transactions = []
    if request.include_transactions:
        recent_transactions = [
            TransactionSummary(
                hash=tx.hash,
                from_address=tx.from_address,
                to_address=tx.to_address,
                value=tx.value,
                timestamp=tx.timestamp,
                block_number=tx.block_number,
                is_failed=tx.is_failed,
                direction="out" if tx.from_address.lower() == address else "in",
            )
            for tx in transactions[:50]
        ]

    response = AddressAnalysisResponse(
        address_info=address_info,
        reputation_score=reputation,
        contract_info=contract_info,
        interaction_graph=interaction_graph,
        recent_transactions=recent_transactions,
        is_demo_data=is_demo_data,
        data_source="demo" if is_demo_data else provider.name,
        timestamp=datetime.utcnow(),
    )

    try:
        await save_analysis(address, chain, response.model_dump(mode="json"))
        await add_to_search_history(
            address=address,
            chain=chain,
            score=reputation.score,
            risk_level=reputation.risk_level.value,
            is_demo=is_demo_data,
        )
    except Exception as e:
        # Storage is best-effort; never fail the request because caching failed.
        logger.error(f"Failed to persist analysis/history for {address}: {e}")

    logger.info(f"Analysis complete for {address}: score={reputation.score}, risk={reputation.risk_level}")

    return response


@router.post("/analyze", response_model=AddressAnalysisResponse)
async def analyze_address(request: AddressAnalysisRequest) -> AddressAnalysisResponse:
    """
    Analyze a blockchain address and return an explainable reputation report.

    Fetches on-chain activity (live or demo, per USE_DEMO_MODE), extracts
    deterministic risk signals, computes a 0-100 reputation score, and
    builds an interaction graph — all without any LLM involvement in the
    scoring itself.
    """
    provider = await get_provider(request.chain.value)
    return await _run_analysis(request, provider)


@router.post("/analyze/multichain", response_model=MultiChainAnalysisResponse)
async def analyze_multichain(request: MultiChainAnalysisRequest) -> MultiChainAnalysisResponse:
    """Analyze one EVM address across multiple configured chains concurrently.

    Live multi-chain extraction uses the same normalized provider interface and
    Etherscan V2 chain IDs. Demo mode intentionally refuses this endpoint so
    synthetic Ethereum demo data is never presented as real cross-chain data.
    """
    settings = get_settings()
    if settings.use_demo_mode:
        raise HTTPException(
            status_code=400,
            detail="Cross-chain live extraction requires USE_DEMO_MODE=false. Demo mode is single-chain synthetic data and is not presented as real cross-chain activity.",
        )

    from blockchain.multichain import MultiChainAggregator

    async def factory(chain: str):
        return await get_provider(chain)

    aggregator = MultiChainAggregator(factory, _run_analysis)
    results = await aggregator.analyze(request)
    successful = {k: v for k, v in results.items() if not isinstance(v, Exception)}
    failures = {k: str(v) for k, v in results.items() if isinstance(v, Exception)}
    # Keep the response schema intentionally simple: successful chain results are
    # returned; failures are represented by a failed-chain count and logged.
    for chain, error in failures.items():
        logger.error("Cross-chain analysis failed for %s: %s", chain, error)

    return MultiChainAnalysisResponse(
        address=request.address.lower(),
        results=successful,
        chains_analyzed=list(results.keys()),
        successful_chains=len(successful),
        failed_chains=len(failures),
    )


@router.get("/analyze/demo/{scenario}", response_model=AddressAnalysisResponse)
async def demo_scenario(scenario: str) -> AddressAnalysisResponse:
    """
    Run analysis against one of ChainGuard's fixed offline demo scenarios,
    regardless of the server's current USE_DEMO_MODE setting.
    """
    if scenario not in DEMO_SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown demo scenario '{scenario}'. Available: {list(DEMO_SCENARIOS.keys())}",
        )
    request = AddressAnalysisRequest(address=DEMO_SCENARIOS[scenario], chain=Chain.ETHEREUM_MAINNET)
    provider = DemoProvider(network="ethereum_mainnet", chain_id=1)
    return await _run_analysis(request, provider)
