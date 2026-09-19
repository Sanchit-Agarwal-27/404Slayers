"""
Address Detail Routes

GET /api/address/{address} - Get the cached analysis for an address.
"""

import logging
from fastapi import APIRouter, HTTPException

from core.models import AddressAnalysisResponse, Chain
from storage.database import get_analysis

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/address/{address}", response_model=AddressAnalysisResponse)
async def get_address_analysis(address: str, chain: str = "ethereum_mainnet"):
    """
    Get the most recently cached analysis for an address.

    Returns 404 if the address hasn't been analyzed yet — call
    POST /api/analyze first.
    """
    address = address.lower()

    try:
        Chain(chain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid chain: {chain}")

    cached = await get_analysis(address, chain)

    if not cached:
        raise HTTPException(
            status_code=404,
            detail=f"No cached analysis for {address} on {chain}. Run POST /api/analyze first.",
        )

    return AddressAnalysisResponse(**cached.get("data", {}))
