# ChainGuard - Wallet & Contract Reputation

**Explainable Web3 risk analysis.** Paste an Ethereum wallet or smart-contract
address and ChainGuard returns a **0-100 reputation score**, a risk level, the
**evidence behind every signal**, threat-intelligence context, recent
transactions, counterparties, and an **interaction graph** - never a bare
"safe / malicious" label.

## The problem

> **Wallet & Contract Reputation.** Users routinely interact with unknown
> wallets and contracts without any way to judge whether they can be trusted.

ChainGuard analyzes an address's on-chain activity and interactions, extracts
risk signals (flagged-address interactions, unverified or newly deployed
contracts, failure bursts, address age, ...) and positive signals (long history,
sustained activity), and turns them into a score you can audit line by line.

## What makes it explainable

- **Deterministic scoring.** `score = clamp(50 + ? signal weights, 0, 100)`. Fixed rules, fixed weights (`risk_engine/signals.py`). Same input -> same score. **No LLM or ML computes or influences the score.**
- **Evidence on every signal.** Each signal shows its weight, severity, source module, confidence, and the concrete data that triggered it (counts, percentages, matched addresses, transaction hashes, dataset entries with references).
- **Signals, not verdicts.** Wording is "observed signal / associated with flagged activity"; the UI and API always say the score is heuristic.
- **Honest about missing data.** No history -> "insufficient evidence", score stays at the neutral 50.

> **No AI explainer is implemented.** `GROQ_API_KEY` / `ENABLE_AI_EXPLAINER` in the config are reserved placeholders that nothing reads.

## Features

- Wallet (EOA) vs. contract detection; contract verification / proxy / age signals
- Threat-intel checks on both the **analyzed address itself** and its **counterparties**
- Activity metrics, recent transactions (up to 50), counterparties
- Interaction graph (SVG): central address, counterparties, contracts, flagged nodes
- Search history; demo-mode shortcuts; clearly labelled `DEMO DATA` / `LIVE DATA`
- EVM chain extraction: **Ethereum Mainnet, Sepolia, Polygon, Arbitrum, Optimism, Base, and BNB Smart Chain** through the normalized provider layer; multi-chain aggregation is live-mode only

## Quick start

Requires **Python 3.10+** (developed and tested on 3.12).

```bash
cd ChainGuard
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # Windows: copy .env.example .env
python main.py
```

Open **http://localhost:5000**. The default `USE_DEMO_MODE=true` needs no API
keys and no internet access. Interactive API docs: http://localhost:5000/docs

## Demo mode

Demo mode (`USE_DEMO_MODE=true`, the default) runs fully offline on
deterministic synthetic data. The UI shows a demo banner, five one-click
scenario buttons, and a `DEMO DATA` tag and warning on every result. The
scenario endpoint `GET /api/analyze/demo/{scenario}` always uses demo data,
even if the server is in live mode.

### Demo addresses

| Scenario key | Address | What it shows | Score / level |
|--------------|---------|---------------|---------------|
| `low_risk_wallet` | `0xabcd000000000000000000000000000000000001` | Quiet long-time holder, no red flags | 55 ? moderate |
| `suspicious_contract` | `0xdead000000000000000000000000000000000002` | Unverified, 5-day-old contract that is itself in the threat-intel dataset | 0 ? critical |
| `active_defi_wallet` | `0xdef1000000000000000000000000000000000003` | 150 successful txs over ~13 months, 120 token transfers | 59 ? moderate |
| `high_risk_wallet` | `0xbad0000000000000000000000000000000000004` | Sent funds to a flagged drainer contract, 65% failures, activity burst, 12-day-old address | 12 ? critical |
| `review2_anomaly_wallet` | `0x4444444444444444444444444444444444444444` | Review-2 showcase: value/gas outliers, concentrated counterparty, unlimited approval, rapid pass-through, round-trip | 11 ? critical |

> **About the "good" scores.** The weight table is intentionally conservative
> about upside: the maximum a wallet can reach is **60** (a verified contract:
> 62). A clean, established wallet therefore lands in *moderate*, and the
> `low`/`very_low` tiers are effectively unreachable with the current weights.
> The score discriminates mainly on the downside. See
> [RISK_ENGINE.md](RISK_ENGINE.md#reachable-score-range-important).

Demo scores are computed live from the demo data, so they are stable across runs.

## Live Ethereum mode

```
USE_DEMO_MODE=false
ETHERSCAN_API_KEY=<your Etherscan API V2 key>
# Legacy per-network variables such as ETH_MAINNET_ETHERSCAN are also supported
```

Live mode fetches transactions, balance, token transfers, contract code and
verification status from the **Etherscan API V2**
(`https://api.etherscan.io/v2/api`; the old V1 endpoints were retired in
August 2025). Behavior worth knowing:

- **No silent fallback.** Live mode with a missing key returns a clear `400`; an upstream failure (bad key, rate limit, timeout) returns `502`. It never substitutes demo data or reports "no transactions" for an error.
- The browser lets you select a configured EVM chain. The single-chain endpoint accepts the selected chain; `/api/analyze/multichain` runs live extraction across multiple requested chains concurrently.
- **Verification status of live mode:** it was validated against mocked Etherscan responses only. It has **not** been exercised against the real API (no API key or network access was available when this was built). Expect to shake out issues on first real use; free-tier availability of Sepolia under V2 is unconfirmed.
- Live limitations: analysis uses the most recent transactions Etherscan returns (up to 10,000); contract creation time is not fetched, so the *Recently Deployed Contract* signal cannot fire on live data; proxy detection reads verified source, so it cannot flag *unverified* proxies; only the first 12 counterparties (configurable) are classified as contract/EOA.

## Threat-intelligence limitations

`threat_intel/flagged_addresses.json` is a **tiny hand-curated demo dataset**
(3 entries) with its own disclaimer - not a real threat feed - and it is used
in **both** demo and live mode. A match is evidence to weigh; **no match is not
evidence of safety.** In live mode, real-world scam addresses will almost
never match. The reference URLs in the dataset are placeholders. Integrating a
real feed (Chainalysis, TRM, community lists, Etherscan labels) is the natural
next step. Entries with `low` severity (e.g. the null address) are shown but
never affect the score.

## Interaction graph

Generated deterministically from the address's transactions (no LLM): the
analyzed address is the central node; up to 25 counterparties (ranked by
interaction count) surround it; edge width reflects the number of interactions.
Red nodes are in the threat-intel dataset, yellow nodes are contracts, and a
note appears if the graph was truncated. Hover a node for its full address.

## API

Base URL `http://localhost:5000`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Status, version, `demo_mode` |
| `GET` | `/api/status` | Lightweight API info |
| `POST` | `/api/analyze` | Analyze an address (uses `USE_DEMO_MODE`) |
| `GET` | `/api/analyze/demo/{scenario}` | Run a demo scenario: `low_risk_wallet`, `suspicious_contract`, `active_defi_wallet`, `high_risk_wallet` |
| `GET` | `/api/address/{address}?chain=ethereum_mainnet` | Most recently **cached** analysis (404 until analyzed) |
| `GET` | `/api/history` | Recent analyses, most recent first (max 100) |

```bash
curl http://localhost:5000/health

curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "0xbad0000000000000000000000000000000000004",
       "chain": "ethereum_mainnet",
       "include_transactions": true,
       "include_graph": true}'

curl http://localhost:5000/api/analyze/demo/suspicious_contract
```

`chain` can be any configured EVM network such as `ethereum_mainnet`, `sepolia`, `polygon`, `arbitrum`, `optimism`, `base`, or `bsc`. Response shape (abridged):

```jsonc
{
  "address_info": { "address": "0x...", "address_type": "eoa|contract", "chain": "Ethereum Mainnet",
                    "chain_id": 1, "activity_metrics": { "transaction_count": 23, ... } },
  "reputation_score": {
    "score": 12, "risk_level": "critical",          // critical|high|moderate|low|very_low
    "signals": [ { "signal_type": "negative", "name": "Interaction with Flagged Addresses",
                   "weight": -20, "severity": "critical", "source": "threat_intelligence",
                   "confidence": 0.9, "evidence": { "matches": [ ... ] }, "description": "..." } ],
    "reasoning": "...", "recommendation": "..." },
  "contract_info": null,                             // present for contracts
  "interaction_graph": { "nodes": [ ... ], "edges": [ ... ], "truncated": false },
  "recent_transactions": [ ... ],
  "is_demo_data": true, "data_source": "demo", "timestamp": "..."
}
```

Errors: `400` (live mode without key / invalid chain on `/api/address`), `404`
(unknown demo scenario / not yet analyzed), `422` (invalid input), `502`
(live provider failure).

## Review 2 improvements

The risk engine now expands beyond fixed aggregate thresholds with address-relative statistical and behavioral signals:

- **Transaction-value outliers:** Z-score/IQR detection on the address's own outgoing-value history.
- **Gas-price anomalies:** Z-score/IQR detection against the address's own gas-price history.
- **Counterparty concentration:** Gini-style concentration plus top-counterparty share for outgoing value.
- **Token approval exposure:** decodes ERC-20 `approve` and `increaseAllowance` calldata when available and flags very large/unlimited-style allowances.
- **Rapid pass-through:** detects substantial funds leaving shortly after arriving.
- **Circular interactions:** detects direct A->B->A round-trip patterns in the observed transaction graph.

These are deterministic, explainable signals rather than automatic claims of malicious intent. Statistical methods use minimum-sample and zero-variance safeguards.

### Cross-chain extraction

The `BlockchainProvider` abstraction is now configured for Ethereum Mainnet, Sepolia, Polygon, Arbitrum One, Optimism, Base, and BNB Smart Chain using Etherscan API V2 chain IDs. `MultiChainAggregator` can run requested live chains concurrently and return per-chain results using the same risk engine. Demo mode intentionally remains single-chain synthetic data.

## Scoring at a glance

`score = clamp(50 + ? weights, 0, 100)` - risk levels: 0-20 critical ? 21-40 high ? 41-60 moderate ? 61-80 low ? 81-100 very low.

| Positive | Weight | | Negative | Weight |
|----------|-------:|-|----------|-------:|
| Long activity history (>365 d) | +5 | | Address itself in threat intel | -25 |
| Established history (>180 d) | +3 | | Interaction with flagged address | -20 |
| High volume (>1000 tx) | +3 | | Unverified contract | -10 |
| Moderate volume (>100 tx) | +2 | | Recently deployed contract (<30 d) | -10 |
| Verified contract | +2 | | Unverified proxy contract | -8 |
| Active token holder (>100 transfers) | +2 | | Recent activity burst | -8 |
| | | | New address (<30 d) | -5 |
| | | | High failed-tx rate (>50%) | -5 |
| | | | Elevated failed-tx rate (>20%) | -2 |
| | | | Transaction value outlier | -6 |
| | | | Gas price anomaly | -4 |
| | | | Counterparty concentration | -6 |
| | | | Unusual token approval | -10 |
| | | | Rapid pass-through | -7 |
| | | | Circular transaction pattern | -6 |

Full catalog, evidence fields, and worked examples: [RISK_ENGINE.md](RISK_ENGINE.md).

## Testing

```bash
python -m pytest test_core.py -v
```

98 tests, run against the real FastAPI app (via `TestClient`), covering:
address validation; every signal rule; deterministic scoring and risk-level
boundaries; the five demo scenarios end to end (exact scores, evidence on every
signal, graph, repeatability); all API endpoints and error paths; frontend
asset/DOM/CSS wiring; document-code consistency (demo addresses, weight
tables); and the live Etherscan provider with the **network mocked**. Tests
use a temp directory and never touch `data/`.

## Project structure

```
ChainGuard/
??? main.py                 FastAPI entry point (also serves the frontend)
??? core/                   config.py, models.py
??? blockchain/             provider.py (interface), demo_provider.py, eth_provider.py
??? risk_engine/            signals.py (weights + rules), scoring.py, graph.py
??? threat_intel/           database.py, flagged_addresses.json
??? storage/                database.py (JSON cache + history -> data/)
??? routers/                health.py, analyze.py, address.py, history.py
??? frontend/               index.html, styles.css, js/api.js, js/app.js
??? test_core.py
??? requirements.txt   .env.example
??? README.md   ARCHITECTURE.md   RISK_ENGINE.md
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the request flow and component design.

## Limitations

- **Heuristic, not a guarantee.** False positives (legitimate new addresses/contracts) and false negatives (sophisticated scams with clean history) both occur. It is **not a security audit** and cannot detect contract vulnerabilities.
- **Tiny threat-intel dataset** (see above): the biggest gap between this build and a production tool.
- **Conservative scoring range:** wallets top out at 60; see the note under *Demo addresses*.
- **Cross-chain live extraction.** Etherscan V2 chain IDs are configured for Ethereum Mainnet, Sepolia, Polygon, Arbitrum, Optimism, Base, and BNB Smart Chain. Multi-chain aggregation is disabled in demo mode so synthetic data is never presented as real cross-chain activity.
- **Live mode is unverified against the real Etherscan API** (mock-tested only) and has the limitations listed above.
- **Storage is a simple JSON file cache** (single process, no expiry) - fine for a demo, not for production.
- **No authentication; CORS open to all origins** - run it locally or behind your own access control.
- Requires only public data; ChainGuard never asks for private keys or signs anything.
