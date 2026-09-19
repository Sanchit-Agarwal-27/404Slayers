"""
Threat Intelligence Database

Loads a curated, clearly-labelled DEMO/reference dataset of flagged
addresses from flagged_addresses.json. This stands in for a real
threat-intelligence API integration (e.g. Chainalysis, OpenChain,
Etherscan's own labels), which is out of scope for this hackathon build.

IMPORTANT: entries here are demo/curated evidence, not a claim of
universal ground truth. See threat_intel/flagged_addresses.json's
"_disclaimer" field and README.md, "Limitations".
"""

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

DATA_FILE = Path(__file__).parent / "flagged_addresses.json"


class ThreatIntelDatabase:
    """In-memory lookup over the curated flagged-address dataset."""

    def __init__(self, path: Path = DATA_FILE):
        self.path = path
        self._entries: List[Dict[str, Any]] = []
        self._by_address: Dict[str, Dict[str, Any]] = {}
        self.disclaimer: str = ""
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.disclaimer = data.get("_disclaimer", "")
            self._entries = data.get("entries", [])
            self._by_address = {
                entry["address"].lower(): entry for entry in self._entries if entry.get("address")
            }
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load threat intel dataset from {self.path}: {e}")
            self._entries = []
            self._by_address = {}

    def get_entries_for_chain(self, chain: str) -> List[Dict[str, Any]]:
        """Return entries applicable to the given chain (or chain-agnostic 'all' entries)."""
        return [e for e in self._entries if e.get("chain") in (chain, "all")]

    def get_flagged_addresses(self, chain: str) -> List[str]:
        """Return the lowercase addresses flagged for a given chain."""
        return [e["address"].lower() for e in self.get_entries_for_chain(chain)]

    def get_entry(self, address: str) -> Optional[Dict[str, Any]]:
        """Look up the threat-intel entry for a single address, if any."""
        return self._by_address.get(address.lower())

    def lookup_for_chain(self, chain: str) -> Dict[str, Dict[str, Any]]:
        """Return an address -> entry lookup scoped to a chain, for signal evidence."""
        return {e["address"].lower(): e for e in self.get_entries_for_chain(chain)}


@lru_cache()
def get_threat_intel() -> ThreatIntelDatabase:
    """Get the cached threat intelligence database singleton."""
    return ThreatIntelDatabase()
