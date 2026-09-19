# ChainGuard Risk Engine

The risk engine turns normalized blockchain data into an explainable 0-100
reputation score. It is **entirely deterministic and rule-based**: the same
input always produces the same signals and the same score. No LLM, machine
learning, or network call is involved anywhere in `risk_engine/` (a test
enforces that the package imports no LLM or HTTP client).

```
provider data ??? SignalExtractor ??? list[Signal] ??? ReputationScorer ??? score + risk level
 (risk_engine/signals.py)                               (risk_engine/scoring.py)
```

| File | Role |
|------|------|
| `risk_engine/signals.py` | `SIGNAL_WEIGHTS` (the **single source of truth for all weights**) and `SignalExtractor`, which applies the rules and attaches evidence |
| `risk_engine/scoring.py` | `ReputationScorer`: sums weights, clamps, classifies, writes the reasoning and recommendation text |
| `risk_engine/graph.py` | Builds the interaction graph from transactions (no scoring impact) |

Weights are **not** in `core/config.py`. To change one, edit `SIGNAL_WEIGHTS` in `risk_engine/signals.py`.

## Scoring formula

```
score = clamp( 50 + ? signal.weight , 0 , 100 )        # rounded to an integer
```

- Every address starts at a neutral **50**.
- Only `weight` is summed. `confidence` and `severity` are **displayed** with each signal but do **not** change the score.
- Neutral signals have weight 0.

### Risk levels

| Score | Level |
|-------|-------|
| 0-20 | `critical` |
| 21-40 | `high` |
| 41-60 | `moderate` |
| 61-80 | `low` |
| 81-100 | `very_low` |

Each level has a fixed recommendation string in `ReputationScorer.RECOMMENDATIONS`.

### Reachable score range (important)

The weights are deliberately asymmetric: the largest positive signal is +5, the
largest negative is -25. The design intent is that no single heuristic can label
an address "safe" - only the *absence of red flags plus history* moves it up, a
little.

The consequence is that the top tiers are essentially unreachable:

- Positive signals are mutually exclusive within a group (volume: +3 *or* +2; history: +5 *or* +3), so the maximum for a **wallet** is 50 + 3 + 5 + 2 = **60** (`moderate`).
- The maximum for a **verified contract** is 50 + 3 + 5 + 2 + 2 = **62** (`low`).
- `very_low` (81+) cannot be produced by the current weight table.

In practice: a clean, established wallet scores 55-60 ("moderate"), and the
score's real discriminating power is on the downside. If you want clean wallets
to reach "low"/"very low", the positive weights need to be raised - that is a
product decision, and it has intentionally **not** been changed.

## Signal catalog

All weights below come from `SIGNAL_WEIGHTS` in `risk_engine/signals.py`.
The `key` column is the dictionary key.

### Positive

| key | Weight | Signal name | Condition | Evidence attached |
|-----|-------:|-------------|-----------|-------------------|
| `high_transaction_volume` | +3 | High Transaction Volume | > 1000 transactions | `transaction_count`, `threshold` |
| `moderate_transaction_volume` | +2 | Moderate Transaction Volume | 101-1000 transactions | `transaction_count`, `threshold` |
| `long_activity_history` | +5 | Long Activity History | first transaction > 365 days ago | `days_active` |
| `established_activity_history` | +3 | Established History | first transaction 181-365 days ago | `days_active` |
| `verified_contract` | +2 | Verified Smart Contract | contract source verified on the explorer | `is_verified`, `compiler_version` |
| `active_token_holder` | +2 | Active Token Holder | > 100 ERC-20 transfers | `token_transfer_count`, `threshold` |

### Negative

| key | Weight | Signal name | Condition | Severity | Evidence attached |
|-----|-------:|-------------|-----------|----------|-------------------|
| `flagged_address_self` | -25 | Address Present in Threat Intelligence | the analyzed address itself is in the threat-intel dataset (entry severity medium/high/critical) | entry's severity | full dataset entry (`risk_type`, `severity`, `description`, `source`, `reference`) |
| `flagged_address_interaction` | -20 | Interaction with Flagged Addresses | a counterparty is in the threat-intel dataset (entry severity medium/high/critical); counted once per signal, not per transaction | highest matching severity | up to 5 matches, each with dataset entry, `interaction_count`, and up to 3 `transaction_hashes` |
| `unverified_contract` | -10 | Unverified Smart Contract | analyzed address is a contract without verified source | medium | `is_verified`, `compiler_version` |
| `recently_deployed_contract` | -10 | Recently Deployed Contract | contract deployed < 30 days ago (needs a creation timestamp - see below) | medium | `days_old` |
| `unverified_proxy_contract` | -8 | Unverified Proxy Contract | proxy-like contract with unverified source | high | `has_proxy`, `is_verified` |
| `recent_activity_burst` | -8 | Recent Activity Burst | > 20 transactions in the last 7 days **and** > 30% of them failed | medium (confidence 0.75) | `recent_transaction_count`, `recent_failed_count`, `window_days` |
| `new_address` | -5 | New Address | first transaction < 30 days ago | low | `days_active` |
| `high_failed_transaction_rate` | -5 | High Failed Transaction Rate | > 50% of transactions failed | medium | `failed_tx_percentage` |
| `elevated_failed_transaction_rate` | -2 | Elevated Failed Transactions | 20-50% of transactions failed | low | `failed_tx_percentage` |
| `transaction_value_outlier` | -6 | Transaction Value Outlier | latest outgoing value is a Z-score >=3 or IQR outlier versus the address's own history (minimum 5 historical values) | medium | current value, mean, stddev, z-score, quartiles/IQR, bounds, sample count |
| `gas_price_anomaly` | -4 | Gas Price Anomaly | latest gas price is a Z-score >=3 or IQR outlier versus the address's own gas-price history (minimum 5 historical values) | low | current gas price, mean, stddev, z-score, IQR bounds, sample count |
| `counterparty_concentration` | -6 | Counterparty Concentration | outgoing value has Gini >=0.70 or one counterparty receives >=80% of outgoing value | medium | Gini coefficient, top counterparty, top share, total outgoing value |
| `unusual_token_approval` | -10 | Unusual Token Approval | ERC-20 `approve`/`increaseAllowance` grants a very large or effectively unlimited allowance | high | function, spender, raw allowance, unlimited-style flag, transaction hash |
| `rapid_pass_through` | -7 | Rapid Pass-Through Pattern | incoming value is followed by 50-110% of that value leaving within 1 hour | medium | incoming/outgoing hashes, values, time difference |
| `circular_transaction_pattern` | -6 | Circular Transaction Pattern | target and a counterparty exchange value in both directions within 24 hours | low | cycle addresses, transaction hashes, time difference |

### Neutral (weight 0, informational)

| Signal name | When |
|-------------|------|
| No Transaction History | the address has no recorded transactions ("insufficient evidence" - not a penalty) |
| Address Listed in Threat Intelligence (Low Severity) | the analyzed address is in the dataset with `low` severity |
| Interaction with Low-Severity Watchlist Address | a counterparty is in the dataset with `low` severity (e.g. the null/burn address) |

Low-severity dataset entries are surfaced but **never scored**: the null/burn
address is in the dataset with the note that interactions are usually benign, so
sending a token to it must not read as a critical red flag.

### Every signal carries evidence

Each `Signal` has `name`, `description`, `weight`, `severity`, `source` (which
analysis module produced it), `confidence`, and an `evidence` object with the
concrete data that triggered it. Descriptions are phrased as observed signals
("Observed risk signal...", "Associated with flagged activity..."), not verdicts.
`test_every_scoring_signal_has_evidence` enforces this for all five demo scenarios.

## Worked examples (the five demo scenarios)

These are the real outputs of the engine on the bundled demo data.

**Low-risk wallet** `0xabcd000000000000000000000000000000000001` -> **55, moderate**
2 transactions over ~2 years, no red flags.
`50 + 5 (Long Activity History) = 55`

**Suspicious contract** `0xdead000000000000000000000000000000000002` -> **0, critical**
Unverified contract, deployed 5 days ago, listed in the threat-intel dataset.
`50 - 25 (self-flagged) - 10 (unverified) - 10 (recently deployed) - 5 (new address) - 2 (elevated failures) = -2 -> clamped to 0`

**Active DeFi wallet** `0xdef1000000000000000000000000000000000003` -> **59, moderate**
150 successful transactions over ~13 months, 120 token transfers, no red flags.
`50 + 5 (Long History) + 2 (Moderate Volume) + 2 (Active Token Holder) = 59`

**High-risk wallet** `0xbad0000000000000000000000000000000000004` -> **12, critical**
23 transactions in ~2 days, 65% failed, one to a flagged drainer contract, 12-day-old address.
`50 - 20 (flagged interaction) - 8 (burst) - 5 (high failure rate) - 5 (new address) = 12`

**Review-2 anomaly showcase** `0x4444444444444444444444444444444444444444` -> **11, critical**
Demonstrates all six reviewer-requested enhancements: a large transaction-value outlier, gas-price anomaly, concentrated outgoing value, an unlimited-style ERC-20 approval, rapid pass-through, and a direct round-trip interaction.
`50 - 6 - 4 - 6 - 10 - 7 - 6 = 11`

## Threat-intelligence dataset

`threat_intel/flagged_addresses.json` is a **small, hand-curated demo dataset**
(three entries: a drainer contract, the suspicious demo contract, and the null
address). It stands in for a real threat-intelligence feed. A match is evidence
to weigh, not proof; **the absence of a match is not evidence of safety.** The
same dataset is used in both demo and live mode. Entries are chain-scoped
(`ethereum_mainnet`, `sepolia`, or `all`).

## Limitations and known false positives / negatives

- **Heuristics, not a verdict.** Thresholds and anomaly cutoffs are reasonable defaults, not calibrated against labelled data. Statistical detectors require at least five historical observations and use Z-score/IQR safeguards; they are risk signals, not proof of maliciousness.
- **New ? malicious.** New addresses and new contracts are penalized because they have little history; many are legitimate.
- **Old ? safe.** History and volume raise the score only slightly, and a long-lived address can still be compromised or malicious.
- **Not a security audit.** A verified contract can still be vulnerable; "verified" only means the source is public.
- **Proxy detection is a heuristic and cannot flag unverified proxies in live mode.** Live mode sets `has_proxy` by looking for the words `proxy`/`delegatecall` in the contract's *verified source*; an unverified contract has no source, so *Unverified Proxy Contract* can only fire on demo data.
- **Recently Deployed Contract is effectively demo-only.** Live mode does not currently obtain a contract creation timestamp (`creation_timestamp` is `None`), so this signal cannot fire on live data.
- **Live history is capped.** Live mode analyzes the most recent transactions returned by Etherscan (up to 10,000); for extremely active addresses `first_seen`/history length can be understated.
- **Cross-chain extraction.** The provider layer now supports Etherscan V2 chain IDs for Ethereum Mainnet, Sepolia, Polygon, Arbitrum, Optimism, Base, and BNB Smart Chain. Live multi-chain aggregation requires `USE_DEMO_MODE=false` and a working Etherscan V2 key; demo mode intentionally remains single-chain synthetic data.

## Adding or changing a signal

1. Add its weight to `SIGNAL_WEIGHTS` in `risk_engine/signals.py`.
2. Implement the rule in `SignalExtractor` (`risk_engine/signals.py`), attaching `evidence`.
3. Add tests in `test_core.py`. A test checks that every key in `SIGNAL_WEIGHTS` appears in the catalog above with the right weight, so update this document too.
