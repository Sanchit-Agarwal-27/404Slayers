"""
Risk Signal Extraction

Analyzes blockchain data and extracts deterministic risk and positive
signals. No LLM is involved anywhere in this module — every signal is
produced by a fixed rule against observed data, and every signal carries
its own evidence and source so the result is explainable rather than a
bare "good"/"bad" verdict.

SIGNAL_WEIGHTS is the single source of truth for how much each signal
moves the reputation score; risk_engine/scoring.py and the documentation
both read from it, so the code and the docs can never drift apart.
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta

from core.models import Signal, SignalType

logger = logging.getLogger(__name__)


# Deterministic weight table. Positive values raise the score, negative
# values lower it. These are intentionally modest per-signal so that no
# single heuristic can, by itself, brand an address "safe" or "malicious" —
# only a preponderance of signals moves the score to the extremes.
SIGNAL_WEIGHTS: Dict[str, float] = {
    # Positive signals
    "high_transaction_volume": 3,
    "moderate_transaction_volume": 2,
    "long_activity_history": 5,
    "established_activity_history": 3,
    "verified_contract": 2,
    "active_token_holder": 2,
    # Negative signals
    "flagged_address_self": -25,  # the analyzed address itself is in the threat-intel dataset
    "flagged_address_interaction": -20,  # a counterparty is in the threat-intel dataset
    "unverified_contract": -10,
    "unverified_proxy_contract": -8,
    "recently_deployed_contract": -10,
    "new_address": -5,
    "high_failed_transaction_rate": -5,
    "elevated_failed_transaction_rate": -2,
    "recent_activity_burst": -8,
}


# Threat-intel entries at or above this severity move the score. "low"
# entries (e.g. the null/burn address, whose interactions are usually
# benign) are surfaced as zero-weight informational signals instead, so a
# benign watchlist entry can never be presented as a scoring red flag.
SCORED_THREAT_SEVERITIES = ("medium", "high", "critical")
_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _is_scored(entry: Dict[str, Any]) -> bool:
    return str(entry.get("severity", "")).lower() in SCORED_THREAT_SEVERITIES


class SignalExtractor:
    """Extracts risk and positive signals from normalized blockchain data."""

    def __init__(self, threat_intel_lookup: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        Args:
            threat_intel_lookup: address(lowercase) -> threat-intel entry dict,
                as produced by threat_intel.database.ThreatIntelDatabase.lookup_for_chain
        """
        self.threat_intel_lookup = threat_intel_lookup or {}

    def extract_signals(
        self,
        address: str,
        transactions: List[Any],
        is_contract: bool,
        contract_info: Optional[Dict] = None,
        balance: float = 0.0,
        token_transfers: List[Dict] = None,
        first_tx_timestamp: Optional[datetime] = None,
    ) -> Tuple[List[Signal], Dict[str, Any]]:
        """
        Extract all signals from address data.

        Returns:
            Tuple of (signals list, metrics dict)
        """
        address = address.lower()
        # Self-flag check runs first and regardless of transaction history:
        # an address can be listed in threat intel even if it has no activity.
        signals: List[Signal] = list(self._self_flag_signals(address))
        metrics = {
            "transaction_count": len(transactions),
            "unique_counterparties": 0,
            "token_transfer_count": len(token_transfers or []),
            "days_active": 0,
            "failed_tx_percentage": 0,
        }

        if not transactions:
            signals.append(
                self._create_signal(
                    SignalType.NEUTRAL,
                    "No Transaction History",
                    "Insufficient evidence: this address has no recorded transactions on this chain.",
                    0,
                    "blockchain_analysis",
                    severity="info",
                    evidence={"transaction_count": 0},
                )
            )
            # Even with no transactions, a contract can still be assessed for verification.
            if is_contract and contract_info:
                signals.extend(self._contract_signals(contract_info))
            return signals, metrics

        metrics = self._calculate_metrics(address, transactions, token_transfers, first_tx_timestamp)

        signals.extend(self._activity_signals(metrics))
        signals.extend(self._behavior_signals(transactions))
        signals.extend(self._counterparty_signals(address, transactions))

        if is_contract and contract_info:
            signals.extend(self._contract_signals(contract_info))

        if token_transfers:
            signals.extend(self._token_transfer_signals(token_transfers))

        if first_tx_timestamp:
            signals.extend(self._time_based_signals(first_tx_timestamp))

        return signals, metrics

    def _calculate_metrics(
        self,
        address: str,
        transactions: List[Any],
        token_transfers: Optional[List[Dict]],
        first_tx_timestamp: Optional[datetime],
    ) -> Dict[str, Any]:
        """Calculate key activity metrics from raw transactions."""

        counterparties = set()
        failed_txs = 0
        value_sent = 0.0
        value_received = 0.0

        for tx in transactions:
            other_addr = tx.to_address if tx.from_address.lower() == address else tx.from_address
            if other_addr:
                counterparties.add(other_addr.lower())

            if tx.is_failed:
                failed_txs += 1

            if tx.from_address.lower() == address:
                value_sent += tx.value
            else:
                value_received += tx.value

        days_active = 0
        if first_tx_timestamp:
            days_active = max(0, (datetime.utcnow() - first_tx_timestamp).days)

        return {
            "transaction_count": len(transactions),
            "unique_counterparties": len(counterparties),
            "token_transfer_count": len(token_transfers or []),
            "days_active": days_active,
            "failed_tx_percentage": (failed_txs / len(transactions) * 100) if transactions else 0,
            "value_sent": value_sent,
            "value_received": value_received,
        }

    def _activity_signals(self, metrics: Dict[str, Any]) -> List[Signal]:
        """Signals about raw transaction volume and failure rate."""
        signals = []
        tx_count = metrics["transaction_count"]

        if tx_count > 1000:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "High Transaction Volume",
                    f"Observed risk signal (positive): {tx_count} transactions indicate sustained, active usage.",
                    SIGNAL_WEIGHTS["high_transaction_volume"],
                    "transaction_volume",
                    severity="info",
                    evidence={"transaction_count": tx_count, "threshold": "more than 1000"},
                )
            )
        elif tx_count > 100:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "Moderate Transaction Volume",
                    f"Observed risk signal (positive): {tx_count} transactions is a moderate, non-trivial history.",
                    SIGNAL_WEIGHTS["moderate_transaction_volume"],
                    "transaction_volume",
                    severity="info",
                    evidence={"transaction_count": tx_count, "threshold": "more than 100"},
                )
            )

        failed_pct = metrics["failed_tx_percentage"]
        if failed_pct > 50:
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "High Failed Transaction Rate",
                    f"Observed risk signal: {failed_pct:.1f}% of transactions failed, higher than typical usage and worth reviewing directly.",
                    SIGNAL_WEIGHTS["high_failed_transaction_rate"],
                    "transaction_analysis",
                    severity="medium",
                    evidence={"failed_tx_percentage": round(failed_pct, 1)},
                )
            )
        elif failed_pct > 20:
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Elevated Failed Transactions",
                    f"Observed risk signal: {failed_pct:.1f}% transaction failure rate is elevated versus typical usage.",
                    SIGNAL_WEIGHTS["elevated_failed_transaction_rate"],
                    "transaction_analysis",
                    severity="low",
                    evidence={"failed_tx_percentage": round(failed_pct, 1)},
                )
            )

        return signals

    def _behavior_signals(self, transactions: List[Any]) -> List[Signal]:
        """Signals about recent behavioral anomalies (bursts of activity)."""
        signals = []

        now = datetime.utcnow()
        recent_txs = [tx for tx in transactions if (now - tx.timestamp).days < 7]
        recent_failed = sum(1 for tx in recent_txs if tx.is_failed)

        if len(recent_txs) > 20 and recent_failed / len(recent_txs) > 0.3:
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Recent Activity Burst",
                    "Observed risk signal: unusual surge in activity (20+ transactions in 7 days) combined with a high failure rate. Requires caution.",
                    SIGNAL_WEIGHTS["recent_activity_burst"],
                    "behavior_analysis",
                    severity="medium",
                    confidence=0.75,
                    evidence={
                        "recent_transaction_count": len(recent_txs),
                        "recent_failed_count": recent_failed,
                        "window_days": 7,
                    },
                )
            )

        return signals

    def _self_flag_signals(self, address: str) -> List[Signal]:
        """Signal for when the analyzed address itself is in the threat-intel dataset."""
        entry = self.threat_intel_lookup.get(address)
        if not entry:
            return []

        evidence = {
            "address": address,
            "risk_type": entry.get("risk_type"),
            "severity": entry.get("severity"),
            "description": entry.get("description"),
            "source": entry.get("source"),
            "reference": entry.get("reference"),
        }

        if _is_scored(entry):
            return [
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Address Present in Threat Intelligence",
                    (
                        "Associated with flagged activity: the analyzed address itself is listed in the "
                        "curated threat-intel dataset. Review the evidence before interacting with it."
                    ),
                    SIGNAL_WEIGHTS["flagged_address_self"],
                    "threat_intelligence",
                    severity=str(entry.get("severity")).lower(),
                    confidence=0.9,
                    evidence=evidence,
                )
            ]

        return [
            self._create_signal(
                SignalType.NEUTRAL,
                "Address Listed in Threat Intelligence (Low Severity)",
                "Informational: the analyzed address appears in the threat-intel dataset with low severity; no score impact.",
                0,
                "threat_intelligence",
                severity="info",
                evidence=evidence,
            )
        ]

    def _counterparty_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        """Signals about interactions with threat-intel-listed counterparties."""
        signals = []

        matches: Dict[str, Dict[str, Any]] = {}
        for tx in transactions:
            counterparty = tx.to_address if tx.from_address.lower() == address else tx.from_address
            if not counterparty:
                continue
            counterparty = counterparty.lower()
            if counterparty == address:
                continue
            entry = self.threat_intel_lookup.get(counterparty)
            if not entry:
                continue
            m = matches.setdefault(counterparty, {"entry": entry, "count": 0, "hashes": []})
            m["count"] += 1
            if len(m["hashes"]) < 3:
                m["hashes"].append(tx.hash)

        def _match_evidence(items):
            return [
                {
                    "address": addr,
                    "risk_type": m["entry"].get("risk_type"),
                    "severity": m["entry"].get("severity"),
                    "description": m["entry"].get("description"),
                    "source": m["entry"].get("source"),
                    "reference": m["entry"].get("reference"),
                    "interaction_count": m["count"],
                    "transaction_hashes": m["hashes"],
                }
                for addr, m in items[:5]
            ]

        scored = [(a, m) for a, m in matches.items() if _is_scored(m["entry"])]
        informational = [(a, m) for a, m in matches.items() if not _is_scored(m["entry"])]

        if scored:
            top_severity = max(
                (str(m["entry"].get("severity")).lower() for _, m in scored),
                key=_SEVERITY_ORDER.index,
            )
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Interaction with Flagged Addresses",
                    (
                        f"Associated with flagged activity: this address transacted with "
                        f"{len(scored)} address(es) present in the curated threat-intel "
                        f"dataset. Review the evidence before interacting further."
                    ),
                    SIGNAL_WEIGHTS["flagged_address_interaction"],
                    "threat_intelligence",
                    severity=top_severity,
                    confidence=0.9,
                    evidence={"flagged_count": len(scored), "matches": _match_evidence(scored)},
                )
            )

        if informational:
            signals.append(
                self._create_signal(
                    SignalType.NEUTRAL,
                    "Interaction with Low-Severity Watchlist Address",
                    (
                        f"Informational: this address transacted with {len(informational)} low-severity "
                        f"watchlist address(es) (for example the null/burn address). No score impact."
                    ),
                    0,
                    "threat_intelligence",
                    severity="info",
                    evidence={"flagged_count": len(informational), "matches": _match_evidence(informational)},
                )
            )

        return signals

    def _contract_signals(self, contract_info: Dict) -> List[Signal]:
        """Signals specific to smart contracts."""
        signals = []

        if not contract_info.get("is_verified"):
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Unverified Smart Contract",
                    "Observed risk signal: source code is not verified on the blockchain explorer, so behavior cannot be independently confirmed. Requires caution.",
                    SIGNAL_WEIGHTS["unverified_contract"],
                    "contract_analysis",
                    severity="medium",
                    evidence={"is_verified": False, "compiler_version": contract_info.get("compiler_version")},
                )
            )
        else:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "Verified Smart Contract",
                    "Observed risk signal (positive): source code is verified and publicly viewable on the explorer.",
                    SIGNAL_WEIGHTS["verified_contract"],
                    "contract_analysis",
                    severity="info",
                    evidence={"is_verified": True, "compiler_version": contract_info.get("compiler_version")},
                )
            )

        if contract_info.get("has_proxy") and not contract_info.get("is_verified"):
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "Unverified Proxy Contract",
                    "Observed risk signal: this is a proxy contract with an unverified implementation, so the logic it delegates to cannot be confirmed. Requires caution.",
                    SIGNAL_WEIGHTS["unverified_proxy_contract"],
                    "contract_analysis",
                    severity="high",
                    evidence={"has_proxy": True, "is_verified": False},
                )
            )

        creation_time = contract_info.get("creation_timestamp")
        if creation_time:
            days_old = (datetime.utcnow() - creation_time).days
            if days_old < 30:
                signals.append(
                    self._create_signal(
                        SignalType.NEGATIVE,
                        "Recently Deployed Contract",
                        f"Observed risk signal: contract was deployed only {days_old} day(s) ago; newly deployed contracts have a short track record.",
                        SIGNAL_WEIGHTS["recently_deployed_contract"],
                        "contract_analysis",
                        severity="medium",
                        evidence={"days_old": days_old},
                    )
                )

        return signals

    def _token_transfer_signals(self, token_transfers: List[Dict]) -> List[Signal]:
        """Signals from ERC-20 token transfer behavior."""
        signals = []

        if len(token_transfers) > 100:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "Active Token Holder",
                    f"Observed risk signal (positive): address has participated in {len(token_transfers)} token transfers.",
                    SIGNAL_WEIGHTS["active_token_holder"],
                    "token_analysis",
                    severity="info",
                    evidence={"token_transfer_count": len(token_transfers), "threshold": "more than 100"},
                )
            )

        return signals

    def _time_based_signals(self, first_tx_timestamp: datetime) -> List[Signal]:
        """Signals based on how long the address has been active."""
        signals = []
        days_active = max(0, (datetime.utcnow() - first_tx_timestamp).days)

        if days_active > 365:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "Long Activity History",
                    f"Observed risk signal (positive): address has been active for over {days_active} days. Long history alone does not prove legitimacy, but it is a data point.",
                    SIGNAL_WEIGHTS["long_activity_history"],
                    "temporal_analysis",
                    severity="info",
                    evidence={"days_active": days_active},
                )
            )
        elif days_active > 180:
            signals.append(
                self._create_signal(
                    SignalType.POSITIVE,
                    "Established History",
                    f"Observed risk signal (positive): address has been active for {days_active} days.",
                    SIGNAL_WEIGHTS["established_activity_history"],
                    "temporal_analysis",
                    severity="info",
                    evidence={"days_active": days_active},
                )
            )
        elif days_active < 30:
            signals.append(
                self._create_signal(
                    SignalType.NEGATIVE,
                    "New Address",
                    f"Observed risk signal: address is only {days_active} day(s) old. New addresses simply have less history to evaluate — this is not proof of malicious intent.",
                    SIGNAL_WEIGHTS["new_address"],
                    "temporal_analysis",
                    severity="low",
                    evidence={"days_active": days_active},
                )
            )

        return signals

    def _create_signal(
        self,
        signal_type: SignalType,
        name: str,
        description: str,
        weight: float,
        source: str,
        severity: str = "info",
        evidence: Optional[Dict] = None,
        confidence: float = 1.0,
    ) -> Signal:
        return Signal(
            signal_type=signal_type,
            name=name,
            description=description,
            weight=weight,
            severity=severity,
            evidence=evidence,
            source=source,
            confidence=confidence,
        )
