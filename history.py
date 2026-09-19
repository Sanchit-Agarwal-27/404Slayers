"""
Search History Routes

GET /api/history - Get the user's recent analysis history.
"""

import logging
from fastapi import APIRouter
from datetime import datetime

from core.models import SearchHistoryResponse, SearchHistoryEntry
from storage.database import get_search_history

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/history", response_model=SearchHistoryResponse)
async def get_history():
    """Get the user's search history, most recent last."""
    entries_data = await get_search_history()

    entries = []
    for entry_data in entries_data:
        try:
            entries.append(
                SearchHistoryEntry(
                    address=entry_data.get("address"),
                    chain=entry_data.get("chain"),
                    score=entry_data.get("score"),
                    risk_level=entry_data.get("risk_level"),
                    timestamp=datetime.fromisoformat(entry_data.get("timestamp", datetime.utcnow().isoformat())),
                    is_demo=entry_data.get("is_demo", False),
                )
            )
        except Exception as e:
            logger.warning(f"Skipping unparseable history entry: {e}")
            continue

    return SearchHistoryResponse(entries=list(reversed(entries)), total_count=len(entries))
