# ChainGuard Architecture

ChainGuard is a single FastAPI process that serves both a JSON API and a
static, framework-free web UI. Data flows one way: **provider -> risk engine ->
response**, with results cached to JSON files.

```
 Browser (frontend/)  ??HTTP/JSON???  FastAPI (main.py + routers/)
                                          ?
                        ??????????????????????????????????????????
                        ?                 ?                      ?
                 blockchain/         risk_engine/            storage/
                 (providers)         (signals, scoring,      (JSON cache +
                  ? DemoProvider      graph)                  search history)
                  ? EthereumProvider        ?
                        ?                   ?
                        ???????? threat_intel/ (curated JSON dataset)

Multi-chain live flow: one normalized provider interface can target multiple
EVM chain IDs through Etherscan V2, and `MultiChainAggregator` runs requested
chains concurrently before returning per-chain reputation results.
```

## Directory layout

```
ChainGuard/
??? main.py                      # FastAPI app: routers, CORS, static frontend mount
??? core/
?   ??? config.py                # Settings (env / .env), NETWORKS, ETHERSCAN_V2_URL
?   ??? models.py                # Pydantic request/response models and enums
??? blockchain/
?   ??? provider.py              # BlockchainProvider ABC + normalized Transaction / Contract
?   ??? demo_provider.py         # Deterministic offline provider + demo scenarios
?   ??? eth_provider.py          # Live EVM provider (Etherscan API V2)
?   ??? multichain.py            # Concurrent multi-chain orchestration
??? risk_engine/
?   ??? signals.py               # SIGNAL_WEIGHTS + SignalExtractor (rules + evidence)
?   ??? scoring.py               # ReputationScorer (sum, clamp, classify, explain)
?   ??? graph.py                 # Interaction-graph builder
??? threat_intel/
?   ??? database.py              # Loads/queries the curated dataset
?   ??? flagged_addresses.json   # 3 demo entries + disclaimer
??? storage/
?   ??? database.py              # Async JSON cache + search history (writes to data/)
??? routers/
?   ??? health.py                # GET /health, GET /api/status
?   ??? analyze.py               # single-chain + multi-chain analysis endpoints and demo scenarios
?   ??? address.py               # GET /api/address/{address}
?   ??? history.py               # GET /api/history
??? frontend/
?   ??? index.html
?   ??? styles.css
?   ??? js/{api.js, app.js}
??? test_core.py
??? requirements.txt  .env.example
??? README.md  ARCHITECTURE.md  RISK_ENGINE.md
```

`data/` (analysis cache and history) is created at runtime and is not part of the source tree.

## Request flow: `POST /api/analyze`

1. **Validate** - `AddressAnalysisRequest` (Pydantic) checks `0x` + 40 hex characters, lower-cases the address, and constrains `chain` to a configured EVM network. Failures return **422**.
2. **Select provider** (`routers/analyze.py: get_provider`) - driven by one setting, `USE_DEMO_MODE`:
   - `true` -> `DemoProvider` (offline, deterministic).
   - `false` -> `EthereumProvider` (live). If no Etherscan key is configured for that chain the API returns **400** with a message naming the missing variable. **ChainGuard never silently falls back from live to demo data.**
3. **Fetch** - transactions, `is_contract`, contract info (if a contract), balance, token transfers, first-transaction time, and the flagged-address list. A live-provider failure (`ConnectionError`, including Etherscan-reported errors such as an invalid key or rate limit) becomes a **502**; it is never treated as "no data".
4. **Classify counterparties** - best-effort contract/EOA classification for graph node types and the `unique_contracts` metric (live mode is capped at `MAX_COUNTERPARTY_CLASSIFICATION_CALLS`; the rest are reported as EOA/unknown).
5. **Score** - `ReputationScorer.calculate_full_reputation` runs `SignalExtractor` with the chain-scoped threat-intel lookup, sums the weights, clamps to 0-100, classifies the risk level, and writes the reasoning and recommendation. See `RISK_ENGINE.md`.
6. **Assemble** - `AddressAnalysisResponse`: address info + activity metrics, reputation score with signals, optional contract info, optional interaction graph, up to 50 recent transactions, `is_demo_data`, `data_source`, `timestamp`.
7. **Persist (best-effort)** - the response is cached and a history entry appended. A storage failure is logged and never fails the request.

`GET /api/analyze/demo/{scenario}` runs the same pipeline against `DemoProvider` **regardless of `USE_DEMO_MODE`**, so the demo scenarios always work.

## API surface

| Method & path | Purpose | Notable responses |
|---------------|---------|-------------------|
| `GET /health` | Status, version, `demo_mode` | 200 |
| `GET /api/status` | Lightweight API info | 200 |
| `POST /api/analyze` | Analyze an address on one configured chain | 200; 400 live mode without key; 422 invalid input; 502 upstream failure |
| `POST /api/analyze/multichain` | Analyze one address across requested live EVM chains concurrently | 200; 400 in demo mode / invalid live configuration |
| `GET /api/analyze/demo/{scenario}` | Run a fixed demo scenario | 200; 404 unknown scenario |
| `GET /api/address/{address}?chain=` | Most recently cached analysis for an address | 200; 404 not yet analyzed; 400 invalid chain |
| `GET /api/history` | Last <=100 analyses, most recent first | 200 |
| `GET /docs`, `/openapi.json` | FastAPI's auto-generated docs | - |
| `GET /` | The static frontend | - |

Routers are registered before the static-file mount, so API routes always take priority over the frontend's catch-all `/`.

## Components

**Providers (`blockchain/`).** `BlockchainProvider` defines the interface (`is_contract`, `get_transactions` most-recent-first, `get_contract_info`, `get_balance`, `get_token_transfers`, `get_first_transaction_timestamp`, `get_flagged_addresses`, `classify_counterparties`). Both providers return the same normalized `Transaction` / `Contract` dataclasses, so the risk engine never knows which one it is talking to.

- `DemoProvider` holds five synthetic scenarios (addresses defined once in `demo_provider.py` and imported elsewhere). Unknown addresses return empty data.
- `EthereumProvider` uses the **Etherscan API V2** (`https://api.etherscan.io/v2/api` with a `chainid` parameter). The V1 endpoints were shut down on 2025-08-15. Contract detection uses `eth_getCode` (not `getsourcecode`, which would misclassify *unverified* contracts as wallets). Timestamps are converted to naive UTC to match the risk engine. Etherscan V2 is configured for Ethereum Mainnet (1), Sepolia (11155111), Polygon (137), Arbitrum One (42161), Optimism (10), Base (8453), and BNB Smart Chain (56).

**Risk engine (`risk_engine/`).** Pure functions of provider data plus the threat-intel lookup. See `RISK_ENGINE.md`.

**Threat intelligence (`threat_intel/`).** An in-memory lookup over a small curated JSON dataset (with an explicit disclaimer). It is a placeholder for a real feed and is used in both demo and live mode.

**Storage (`storage/database.py`).** Two JSON files under `data/` (`DB_PATH`): `analyses.json` (keyed `chain:address`, latest wins) and `search_history.json` (last 100). An `asyncio.Lock` serializes access within one process. There is no TTL or invalidation: `/api/address/{address}` returns whatever was last computed. It is suitable for a single-instance demo, not production.

**Frontend (`frontend/`).** Vanilla HTML/CSS/JS, no build step. `api.js` is a thin client for the endpoints above; `app.js` owns page state and rendering. On load it calls `/health`: in demo mode it shows a demo banner and four scenario shortcut buttons; every result also carries a `DEMO DATA`/`LIVE DATA` tag and, for demo data, a warning banner. The interaction graph is rendered as inline SVG in a deterministic circular layout (central node in the middle; counterparties on a ring; flagged nodes red; contracts yellow; edge width by interaction count). A request-sequence guard stops a slow earlier response from overwriting a newer one. All dynamic text is HTML-escaped and only `http(s)` reference links are made clickable.

## Configuration

Settings come from environment variables / `.env` (see `.env.example`); unknown keys are ignored. Relevant to behavior: `USE_DEMO_MODE`, `ETHERSCAN_API_KEY` (preferred shared V2 key), legacy per-network Etherscan variables, `PROVIDER_TIMEOUT_SECONDS`, `MAX_COUNTERPARTY_CLASSIFICATION_CALLS`, `DB_PATH`, `HOST`, `PORT`, `DEBUG`.

Reserved but **not implemented/used**: `GROQ_API_KEY`, `ENABLE_AI_EXPLAINER` (no LLM explainer exists), `ETH_*_RPC` (nothing reads them), and the `RISK_ENGINE_VERSION` / `REPUTATION_SCORE_*` fields (the scorer uses its own constants).

## Security notes

- Read-only: ChainGuard never signs, sends, or requests keys.
- CORS is wide open (`*`) and there is no authentication - acceptable for a local demo, not for a public deployment.
- Etherscan keys live only in server-side environment variables and are never sent to the browser.
- The app logs only addresses and scores.

## Testing

`test_core.py` (pytest) covers validation, every signal rule, scoring and risk-level boundaries, the five demo scenarios through the real HTTP API (FastAPI `TestClient`), the API endpoints and error paths, frontend asset wiring, doc/address consistency, and the live provider with the network **mocked** (V2 URL and `chainid`, error handling, contract detection, UTC parsing). Storage is redirected to a temp directory so tests never touch `data/`. Live Etherscan calls are not exercised by the tests.
