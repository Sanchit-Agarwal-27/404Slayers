"""Cross-chain orchestration for the normalized BlockchainProvider interface."""

import asyncio
from typing import Awaitable, Callable, Dict, List, Any

from blockchain.provider import BlockchainProvider


class MultiChainAggregator:
    """Run the same address analysis across multiple EVM provider instances."""

    def __init__(self, provider_factory: Callable[[str], Awaitable[BlockchainProvider]], analysis_runner: Callable[..., Awaitable[Any]]):
        self.provider_factory = provider_factory
        self.analysis_runner = analysis_runner

    async def analyze(self, request: Any) -> Dict[str, Any]:
        """Analyze all requested chains concurrently and return per-chain results/errors."""
        chain_values = list(dict.fromkeys(chain.value for chain in request.chains))

        async def one(chain: str):
            try:
                provider = await self.provider_factory(chain)
                # Reuse the existing single-chain pipeline; this keeps scoring and
                # evidence identical regardless of the number of chains requested.
                chain_request = request.model_copy(update={"chains": [chain]})
                # MultiChainAnalysisRequest uses enum values, while model_copy may
                # carry strings after serialization. The analysis runner only needs
                # .address/include_* and a chain value is supplied by the provider.
                return chain, await self.analysis_runner(chain_request, provider, chain_override=chain)
            except Exception as exc:  # one failed chain must not hide successful chains
                return chain, exc

        pairs = await asyncio.gather(*(one(chain) for chain in chain_values))
        return dict(pairs)
