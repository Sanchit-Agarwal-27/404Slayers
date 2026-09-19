"""
Async JSON-based Storage

Simple file-based storage for ChainGuard analysis results and search
history. Good enough for a hackathon demo; swap for a real database
(e.g. PostgreSQL/SQLite) for production use — see README.md, "Limitations".

Callers must pass already-JSON-safe data (e.g. via Pydantic's
`model.model_dump(mode="json")`), since this module does a plain
`json.dump` with no custom encoder.
"""

import json
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# A global lock to prevent race conditions during concurrent JSON reads/writes
db_lock = asyncio.Lock()

from core.config import get_settings

BASE_DIR = Path(__file__).parent.parent
# DB_PATH from .env / settings; a relative value resolves against the project root.
DATA_DIR = BASE_DIR / get_settings().db_path
DATA_DIR.mkdir(parents=True, exist_ok=True)

ANALYSES_FILE = DATA_DIR / "analyses.json"
SEARCH_HISTORY_FILE = DATA_DIR / "search_history.json"


def _load_json_sync(path: Path) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def _save_json_sync(path: Path, data: Dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


async def load_json(path: Path) -> Dict:
    return _load_json_sync(path)


async def save_json(path: Path, data: Dict):
    _save_json_sync(path, data)


# ============================================================================
# Analysis Cache
# ============================================================================

async def save_analysis(address: str, chain: str, analysis_data: Dict[str, Any]):
    """Save a JSON-safe analysis result to cache."""
    async with db_lock:
        analyses = await load_json(ANALYSES_FILE)
        key = f"{chain}:{address.lower()}"
        analyses[key] = {
            "address": address,
            "chain": chain,
            "timestamp": datetime.utcnow().isoformat(),
            "data": analysis_data,
        }
        await save_json(ANALYSES_FILE, analyses)


async def get_analysis(address: str, chain: str) -> Optional[Dict]:
    """Get cached analysis for an address/chain pair, if any."""
    async with db_lock:
        analyses = await load_json(ANALYSES_FILE)
        key = f"{chain}:{address.lower()}"
        return analyses.get(key)


# ============================================================================
# Search History
# ============================================================================

async def add_to_search_history(
    address: str,
    chain: str,
    score: int,
    risk_level: str,
    is_demo: bool = False,
):
    """Append an entry to search history (JSON-safe scalars only)."""
    async with db_lock:
        history = await load_json(SEARCH_HISTORY_FILE)

        if "entries" not in history:
            history["entries"] = []

        history["entries"].append(
            {
                "address": address,
                "chain": chain,
                "score": score,
                "risk_level": risk_level,
                "timestamp": datetime.utcnow().isoformat(),
                "is_demo": is_demo,
            }
        )

        # Keep only the most recent 100 entries
        history["entries"] = history["entries"][-100:]

        await save_json(SEARCH_HISTORY_FILE, history)


async def get_search_history() -> List[Dict]:
    """Get search history, most recent last."""
    async with db_lock:
        history = await load_json(SEARCH_HISTORY_FILE)
        return history.get("entries", [])
