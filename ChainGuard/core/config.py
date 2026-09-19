"""
ChainGuard Configuration

Loads environment variables with validation via pydantic-settings.
Governs demo/live mode selection, supported networks, and risk thresholds.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables (.env)."""

    # extra="ignore": unknown keys in .env (e.g. from an older template) are
    # ignored instead of crashing startup.
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Application
    app_name: str = "ChainGuard"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 5000

    # Blockchain Configuration (live mode uses the Etherscan API V2).
    # A single Etherscan key works for every chain under V2; the two
    # *_etherscan settings exist so a key can be supplied per network.
    # The *_rpc settings are RESERVED and currently unused — no code reads them.
    # A single Etherscan V2 key can be reused across supported EVM chains.
    etherscan_api_key: str = ""

    # Legacy per-network keys remain supported for backwards compatibility.
    eth_mainnet_rpc: str = ""
    eth_mainnet_etherscan: str = ""
    eth_sepolia_rpc: str = ""
    eth_sepolia_etherscan: str = ""

    # Mode selection.
    # USE_DEMO_MODE is the single source of truth for demo vs. live.
    # ChainGuard NEVER silently falls back from live to demo: if this is
    # False and a chain's API key is missing, the analyze endpoint returns
    # a clear error rather than quietly substituting demo data.
    use_demo_mode: bool = True

    # HTTP client
    provider_timeout_seconds: int = 15
    max_counterparty_classification_calls: int = 12

    # Risk Engine
    risk_engine_version: str = "1.0"
    reputation_score_min: int = 0
    reputation_score_max: int = 100

    # RESERVED — not implemented. No LLM/AI explainer exists in this build and
    # nothing reads these two settings. If one is ever added, it may only
    # explain existing deterministic evidence; it must never compute the score.
    groq_api_key: str = ""
    enable_ai_explainer: bool = False

    # Storage directory for cached analyses and search history
    # (relative paths resolve against the project root).
    db_path: str = "data"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Etherscan API V2 (unified multichain endpoint; the chain is selected with a
# `chainid` query parameter). The legacy V1 endpoints were shut down on
# 2025-08-15 and no longer work.
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

# Supported network configurations
NETWORKS = {
    "ethereum_mainnet": {
        "name": "Ethereum Mainnet",
        "chain_id": 1,
        "currency": "ETH",
        "explorer": "https://etherscan.io",
        "rpc_key": "eth_mainnet_rpc",
        "etherscan_key": "eth_mainnet_etherscan",
        "etherscan_url": ETHERSCAN_V2_URL,
    },
    "sepolia": {
        "name": "Sepolia Testnet",
        "chain_id": 11155111,
        "currency": "ETH",
        "explorer": "https://sepolia.etherscan.io",
        "rpc_key": "eth_sepolia_rpc",
        "etherscan_key": "eth_sepolia_etherscan",
        "etherscan_url": ETHERSCAN_V2_URL,
    },
    "polygon": {
        "name": "Polygon", "chain_id": 137, "currency": "POL",
        "explorer": "https://polygonscan.com", "rpc_key": "",
        "etherscan_key": "eth_mainnet_etherscan", "etherscan_url": ETHERSCAN_V2_URL,
    },
    "arbitrum": {
        "name": "Arbitrum One", "chain_id": 42161, "currency": "ETH",
        "explorer": "https://arbiscan.io", "rpc_key": "",
        "etherscan_key": "eth_mainnet_etherscan", "etherscan_url": ETHERSCAN_V2_URL,
    },
    "optimism": {
        "name": "Optimism", "chain_id": 10, "currency": "ETH",
        "explorer": "https://optimistic.etherscan.io", "rpc_key": "",
        "etherscan_key": "eth_mainnet_etherscan", "etherscan_url": ETHERSCAN_V2_URL,
    },
    "base": {
        "name": "Base", "chain_id": 8453, "currency": "ETH",
        "explorer": "https://basescan.org", "rpc_key": "",
        "etherscan_key": "eth_mainnet_etherscan", "etherscan_url": ETHERSCAN_V2_URL,
    },
    "bsc": {
        "name": "BNB Smart Chain", "chain_id": 56, "currency": "BNB",
        "explorer": "https://bscscan.com", "rpc_key": "",
        "etherscan_key": "eth_mainnet_etherscan", "etherscan_url": ETHERSCAN_V2_URL,
    },
}

# Risk score -> risk level thresholds (inclusive upper bounds)
RISK_LEVELS = {
    "critical": (0, 20),
    "high": (21, 40),
    "moderate": (41, 60),
    "low": (61, 80),
    "very_low": (81, 100),
}
