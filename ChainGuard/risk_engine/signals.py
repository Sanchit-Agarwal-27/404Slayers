"""
Risk Signal Extraction

Deterministic, explainable risk-signal extraction for ChainGuard.
No LLM is involved in scoring. Statistical detectors are used only to
produce evidence-backed signals; the deterministic scorer applies their
fixed weights.
"""

import logging
import math
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta

from core.models import Signal, SignalType

logger = logging.getLogger(__name__)

SIGNAL_WEIGHTS: Dict[str, float] = {
    # Positive signals
    "high_transaction_volume": 3,
    "moderate_transaction_volume": 2,
    "long_activity_history": 5,
    "established_activity_history": 3,
    "verified_contract": 2,
    "active_token_holder": 2,
    # Existing negative signals
    "flagged_address_self": -25,
    "flagged_address_interaction": -20,
    "unverified_contract": -10,
    "unverified_proxy_contract": -8,
    "recently_deployed_contract": -10,
    "new_address": -5,
    "high_failed_transaction_rate": -5,
    "elevated_failed_transaction_rate": -2,
    "recent_activity_burst": -8,
    # Review-2 behavioral/statistical signals
    "transaction_value_outlier": -6,
    "gas_price_anomaly": -4,
    "counterparty_concentration": -6,
    "unusual_token_approval": -10,
    "rapid_pass_through": -7,
    "circular_transaction_pattern": -6,
}

SCORED_THREAT_SEVERITIES = ("medium", "high", "critical")
_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _is_scored(entry: Dict[str, Any]) -> bool:
    return str(entry.get("severity", "")).lower() in SCORED_THREAT_SEVERITIES


def _numeric(values: List[Any]) -> List[float]:
    """Return finite numeric values only."""
    result = []
    for value in values:
        try:
            number = float(value)
            if math.isfinite(number):
                result.append(number)
        except (TypeError, ValueError):
            continue
    return result


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * fraction


def _iqr_bounds(values: List[float]) -> Tuple[float, float, float, float, float]:
    ordered = sorted(values)
    q1 = _percentile(ordered, 0.25)
    q3 = _percentile(ordered, 0.75)
    iqr = q3 - q1
    return q1, q3, iqr, q1 - 1.5 * iqr, q3 + 1.5 * iqr


def _outlier_stats(history: List[float], current: float, min_samples: int = 5) -> Optional[Dict[str, float]]:
    """Return z/IQR statistics when enough historical values exist."""
    history = _numeric(history)
    try:
        current = float(current)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(current) or len(history) < min_samples:
        return None

    mean = _mean(history)
    std = _stddev(history)
    z = (current - mean) / std if std > 0 else 0.0
    q1, q3, iqr, lower, upper = _iqr_bounds(history)
    iqr_outlier = current < lower or current > upper
    z_outlier = abs(z) >= 3.0 if std > 0 else False
    return {
        "current": current,
        "mean": mean,
        "stddev": std,
        "z_score": z,
        "q1": q1,
        "q3": q3,
        "iqr": iqr,
        "lower_bound": lower,
        "upper_bound": upper,
        "z_outlier": z_outlier,
        "iqr_outlier": iqr_outlier,
    }


class SignalExtractor:
    """Extract deterministic risk and positive signals from normalized data."""

    def __init__(self, threat_intel_lookup: Optional[Dict[str, Dict[str, Any]]] = None):
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
        address = address.lower()
        signals: List[Signal] = list(self._self_flag_signals(address))
        metrics = {
            "transaction_count": len(transactions),
            "unique_counterparties": 0,
            "token_transfer_count": len(token_transfers or []),
            "days_active": 0,
            "failed_tx_percentage": 0,
        }

        if not transactions:
            signals.append(self._create_signal(
                SignalType.NEUTRAL, "No Transaction History",
                "Insufficient evidence: this address has no recorded transactions on this chain.",
                0, "blockchain_analysis", severity="info", evidence={"transaction_count": 0}
            ))
            if is_contract and contract_info:
                signals.extend(self._contract_signals(contract_info))
            return signals, metrics

        metrics = self._calculate_metrics(address, transactions, token_transfers, first_tx_timestamp)
        signals.extend(self._activity_signals(metrics))
        signals.extend(self._behavior_signals(transactions))
        signals.extend(self._statistical_signals(address, transactions))
        signals.extend(self._approval_signals(address, transactions))
        signals.extend(self._counterparty_signals(address, transactions))
        signals.extend(self._concentration_signals(address, transactions))
        signals.extend(self._velocity_signals(address, transactions))
        signals.extend(self._circular_signals(address, transactions))

        if is_contract and contract_info:
            signals.extend(self._contract_signals(contract_info))
        if token_transfers:
            signals.extend(self._token_transfer_signals(token_transfers))
        if first_tx_timestamp:
            signals.extend(self._time_based_signals(first_tx_timestamp))
        return signals, metrics

    def _calculate_metrics(self, address, transactions, token_transfers, first_tx_timestamp):
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
        days_active = max(0, (datetime.utcnow() - first_tx_timestamp).days) if first_tx_timestamp else 0
        return {
            "transaction_count": len(transactions),
            "unique_counterparties": len(counterparties),
            "token_transfer_count": len(token_transfers or []),
            "days_active": days_active,
            "failed_tx_percentage": (failed_txs / len(transactions) * 100) if transactions else 0,
            "value_sent": value_sent,
            "value_received": value_received,
        }

    def _activity_signals(self, metrics):
        signals = []
        tx_count = metrics["transaction_count"]
        if tx_count > 1000:
            signals.append(self._create_signal(SignalType.POSITIVE, "High Transaction Volume",
                f"Observed risk signal (positive): {tx_count} transactions indicate sustained, active usage.",
                SIGNAL_WEIGHTS["high_transaction_volume"], "transaction_volume", evidence={"transaction_count": tx_count, "threshold": "more than 1000"}))
        elif tx_count > 100:
            signals.append(self._create_signal(SignalType.POSITIVE, "Moderate Transaction Volume",
                f"Observed risk signal (positive): {tx_count} transactions is a moderate, non-trivial history.",
                SIGNAL_WEIGHTS["moderate_transaction_volume"], "transaction_volume", evidence={"transaction_count": tx_count, "threshold": "more than 100"}))
        failed_pct = metrics["failed_tx_percentage"]
        if failed_pct > 50:
            signals.append(self._create_signal(SignalType.NEGATIVE, "High Failed Transaction Rate",
                f"Observed risk signal: {failed_pct:.1f}% of transactions failed, higher than typical usage and worth reviewing directly.",
                SIGNAL_WEIGHTS["high_failed_transaction_rate"], "transaction_analysis", severity="medium", evidence={"failed_tx_percentage": round(failed_pct, 1)}))
        elif failed_pct > 20:
            signals.append(self._create_signal(SignalType.NEGATIVE, "Elevated Failed Transactions",
                f"Observed risk signal: {failed_pct:.1f}% transaction failure rate is elevated versus typical usage.",
                SIGNAL_WEIGHTS["elevated_failed_transaction_rate"], "transaction_analysis", severity="low", evidence={"failed_tx_percentage": round(failed_pct, 1)}))
        return signals

    def _behavior_signals(self, transactions):
        signals = []
        now = datetime.utcnow()
        recent_txs = [tx for tx in transactions if (now - tx.timestamp).days < 7]
        recent_failed = sum(1 for tx in recent_txs if tx.is_failed)
        if len(recent_txs) > 20 and recent_failed / len(recent_txs) > 0.3:
            signals.append(self._create_signal(SignalType.NEGATIVE, "Recent Activity Burst",
                "Observed risk signal: unusual surge in activity (20+ transactions in 7 days) combined with a high failure rate. Requires caution.",
                SIGNAL_WEIGHTS["recent_activity_burst"], "behavior_analysis", severity="medium", confidence=0.75,
                evidence={"recent_transaction_count": len(recent_txs), "recent_failed_count": recent_failed, "window_days": 7}))
        return signals

    def _statistical_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        """Detect outliers across the address's own transaction-value/gas history."""
        signals = []

        def detect(items, value_getter):
            values = _numeric([value_getter(tx) for tx in items])
            if len(values) < 6:
                return None
            mean = _mean(values)
            std = _stddev(values)
            ordered = sorted(values)
            q1, q3, iqr, lower, upper = _iqr_bounds(values)
            candidates = []
            for idx, value in enumerate(values):
                z = (value - mean) / std if std > 0 else 0.0
                iqr_outlier = value < lower or value > upper
                z_outlier = abs(z) >= 3.0 if std > 0 else False
                if z_outlier or iqr_outlier:
                    # Prefer the most extreme standardized deviation; when
                    # variance is zero, distance beyond the IQR bound wins.
                    distance = abs(z) if std > 0 else abs(value - (q3 if value > q3 else q1))
                    candidates.append((distance, idx, value, z, iqr_outlier, z_outlier))
            if not candidates:
                return None
            _, idx, value, z, iqr_outlier, z_outlier = max(candidates, key=lambda x: x[0])
            return {
                "index": idx, "current": value, "mean": mean, "stddev": std,
                "z_score": z, "q1": q1, "q3": q3, "iqr": iqr,
                "lower_bound": lower, "upper_bound": upper,
                "iqr_outlier": iqr_outlier, "z_outlier": z_outlier,
                "sample_count": len(values),
            }

        outgoing = [tx for tx in transactions if tx.from_address.lower() == address and tx.value is not None and tx.value > 0]
        stats = detect(outgoing, lambda tx: tx.value)
        if stats:
            tx = outgoing[stats["index"]]
            method = "Z-score and IQR" if stats["z_outlier"] and stats["iqr_outlier"] else ("Z-score" if stats["z_outlier"] else "IQR")
            signals.append(self._create_signal(
                SignalType.NEGATIVE, "Transaction Value Outlier",
                "Observed risk signal: a transaction value is unusually large or small relative to this address's own historical outgoing-value distribution.",
                SIGNAL_WEIGHTS["transaction_value_outlier"], "statistical_analysis", severity="medium", confidence=0.85,
                evidence={"transaction_hash": tx.hash, "current_value": round(stats["current"], 8),
                          "historical_mean": round(stats["mean"], 8), "historical_stddev": round(stats["stddev"], 8),
                          "z_score": round(stats["z_score"], 3), "q1": round(stats["q1"], 8), "q3": round(stats["q3"], 8),
                          "iqr": round(stats["iqr"], 8), "iqr_upper_bound": round(stats["upper_bound"], 8),
                          "method": method, "historical_sample_count": stats["sample_count"] - 1, "direction": "outgoing"}))

        gas_txs = [tx for tx in transactions if tx.gas_price is not None and tx.gas_price > 0]
        stats = detect(gas_txs, lambda tx: tx.gas_price)
        if stats:
            tx = gas_txs[stats["index"]]
            method = "Z-score and IQR" if stats["z_outlier"] and stats["iqr_outlier"] else ("Z-score" if stats["z_outlier"] else "IQR")
            signals.append(self._create_signal(
                SignalType.NEGATIVE, "Gas Price Anomaly",
                "Observed risk signal: a gas price is statistically unusual compared with this address's own gas-price history. Unusual gas is not by itself proof of malicious behavior.",
                SIGNAL_WEIGHTS["gas_price_anomaly"], "statistical_analysis", severity="low", confidence=0.8,
                evidence={"transaction_hash": tx.hash, "current_gas_price_gwei": round(stats["current"], 4),
                          "historical_mean_gwei": round(stats["mean"], 4), "historical_stddev_gwei": round(stats["stddev"], 4),
                          "z_score": round(stats["z_score"], 3), "q1": round(stats["q1"], 4), "q3": round(stats["q3"], 4),
                          "iqr": round(stats["iqr"], 4), "iqr_upper_bound": round(stats["upper_bound"], 4),
                          "method": method, "historical_sample_count": stats["sample_count"] - 1, "unit": "Gwei"}))
        return signals

    def _concentration_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        outgoing = defaultdict(float)
        for tx in transactions:
            if tx.from_address.lower() != address or not tx.to_address or not tx.value or tx.value <= 0:
                continue
            outgoing[tx.to_address.lower()] += float(tx.value)
        if len(outgoing) < 2:
            return []
        values = list(outgoing.values())
        total = sum(values)
        if total <= 0:
            return []
        ordered = sorted(values)
        n = len(ordered)
        gini = sum((2 * (i + 1) - n - 1) * value for i, value in enumerate(ordered)) / (n * total)
        top_addr, top_value = max(outgoing.items(), key=lambda item: item[1])
        top_share = top_value / total
        if gini >= 0.70 or top_share >= 0.80:
            return [self._create_signal(
                SignalType.NEGATIVE, "Counterparty Concentration",
                "Observed risk signal: outgoing value is highly concentrated in one or a small number of counterparties. Concentration alone is not proof of malicious behavior.",
                SIGNAL_WEIGHTS["counterparty_concentration"], "counterparty_analysis", severity="medium", confidence=0.8,
                evidence={"gini_coefficient": round(gini, 4), "top_counterparty": top_addr,
                          "top_counterparty_value": round(top_value, 8), "top_counterparty_share": round(top_share, 4),
                          "total_outgoing_value": round(total, 8), "counterparty_count": n},
            )]
        return []

    def _approval_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        """Decode common ERC-20 approval calldata when present."""
        signals = []
        selectors = {"095ea7b3": "approve", "39509351": "increaseAllowance"}
        for tx in transactions:
            if tx.from_address.lower() != address:
                continue
            data = (tx.input_data or "").lower()
            if not data.startswith("0x") or len(data) < 138:
                continue
            selector = data[2:10]
            function = selectors.get(selector)
            if not function:
                continue
            payload = data[10:]
            try:
                spender = "0x" + payload[:64][-40:]
                amount = int(payload[64:128], 16)
            except (ValueError, IndexError):
                continue
            unlimited = amount >= 2 ** 255
            if unlimited or amount >= 10 ** 30:
                signals.append(self._create_signal(
                    SignalType.NEGATIVE, "Unusual Token Approval",
                    "Observed risk signal: a very large or effectively unlimited ERC-20 token allowance was granted. The approval is an exposure signal, not proof that the spender is malicious.",
                    SIGNAL_WEIGHTS["unusual_token_approval"], "token_approval_analysis", severity="high", confidence=0.9,
                    evidence={"function": function, "spender": spender, "raw_allowance": str(amount),
                              "unlimited_style": unlimited, "transaction_hash": tx.hash}))
                break
        return signals

    def _velocity_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        incoming = sorted([tx for tx in transactions if tx.to_address and tx.to_address.lower() == address and tx.value > 0], key=lambda tx: tx.timestamp)
        outgoing = sorted([tx for tx in transactions if tx.from_address.lower() == address and tx.value > 0], key=lambda tx: tx.timestamp)
        if not incoming or not outgoing:
            return []
        for inc in incoming:
            for out in outgoing:
                delta = (out.timestamp - inc.timestamp).total_seconds()
                if 0 <= delta <= 3600 and out.value >= inc.value * 0.5 and out.value <= inc.value * 1.1:
                    return [self._create_signal(
                        SignalType.NEGATIVE, "Rapid Pass-Through Pattern",
                        "Observed risk signal: funds entered the address and a substantial portion was sent onward within a short time window.",
                        SIGNAL_WEIGHTS["rapid_pass_through"], "velocity_analysis", severity="medium", confidence=0.8,
                        evidence={"incoming_hash": inc.hash, "outgoing_hash": out.hash, "time_difference_seconds": int(delta),
                                  "incoming_value": round(inc.value, 8), "outgoing_value": round(out.value, 8), "window_seconds": 3600})
                    ]
        return []

    def _circular_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
        """Detect direct observed cycles A->B->A in the target's transaction history."""
        outbound = defaultdict(list)
        inbound = defaultdict(list)
        for tx in transactions:
            if tx.from_address.lower() == address and tx.to_address:
                outbound[tx.to_address.lower()].append(tx)
            elif tx.to_address and tx.to_address.lower() == address:
                inbound[tx.from_address.lower()].append(tx)
        for counterparty, outs in outbound.items():
            if counterparty == address or counterparty not in inbound:
                continue
            for out_tx in outs:
                for in_tx in inbound[counterparty]:
                    delta = abs((in_tx.timestamp - out_tx.timestamp).total_seconds())
                    if delta <= 86400:
                        return [self._create_signal(
                            SignalType.NEGATIVE, "Circular Transaction Pattern",
                            "Observed risk signal: the target and a counterparty exchanged value in both directions within a short period, forming a direct round-trip pattern.",
                            SIGNAL_WEIGHTS["circular_transaction_pattern"], "graph_analysis", severity="low", confidence=0.75,
                            evidence={"cycle": [address, counterparty, address], "outgoing_hash": out_tx.hash,
                                      "return_hash": in_tx.hash, "time_difference_seconds": int(delta)})
                    ]
        return []

    def _self_flag_signals(self, address: str) -> List[Signal]:
        entry = self.threat_intel_lookup.get(address)
        if not entry:
            return []
        evidence = {"address": address, "risk_type": entry.get("risk_type"), "severity": entry.get("severity"),
                    "description": entry.get("description"), "source": entry.get("source"), "reference": entry.get("reference")}
        if _is_scored(entry):
            return [self._create_signal(SignalType.NEGATIVE, "Address Present in Threat Intelligence",
                "Associated with flagged activity: the analyzed address itself is listed in the curated threat-intel dataset. Review the evidence before interacting with it.",
                SIGNAL_WEIGHTS["flagged_address_self"], "threat_intelligence", severity=str(entry.get("severity")).lower(), confidence=0.9, evidence=evidence)]
        return [self._create_signal(SignalType.NEUTRAL, "Address Listed in Threat Intelligence (Low Severity)",
            "Informational: the analyzed address appears in the threat-intel dataset with low severity; no score impact.",
            0, "threat_intelligence", severity="info", evidence=evidence)]

    def _counterparty_signals(self, address: str, transactions: List[Any]) -> List[Signal]:
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
            return [{"address": addr, "risk_type": m["entry"].get("risk_type"), "severity": m["entry"].get("severity"),
                     "description": m["entry"].get("description"), "source": m["entry"].get("source"),
                     "reference": m["entry"].get("reference"), "interaction_count": m["count"], "transaction_hashes": m["hashes"]}
                    for addr, m in items[:5]]
        scored = [(a, m) for a, m in matches.items() if _is_scored(m["entry"])]
        informational = [(a, m) for a, m in matches.items() if not _is_scored(m["entry"])]
        if scored:
            top_severity = max((str(m["entry"].get("severity")).lower() for _, m in scored), key=_SEVERITY_ORDER.index)
            signals.append(self._create_signal(SignalType.NEGATIVE, "Interaction with Flagged Addresses",
                f"Associated with flagged activity: this address transacted with {len(scored)} address(es) present in the curated threat-intel dataset. Review the evidence before interacting further.",
                SIGNAL_WEIGHTS["flagged_address_interaction"], "threat_intelligence", severity=top_severity, confidence=0.9,
                evidence={"flagged_count": len(scored), "matches": _match_evidence(scored)}))
        if informational:
            signals.append(self._create_signal(SignalType.NEUTRAL, "Interaction with Low-Severity Watchlist Address",
                f"Informational: this address transacted with {len(informational)} low-severity watchlist address(es) (for example the null/burn address). No score impact.",
                0, "threat_intelligence", severity="info", evidence={"flagged_count": len(informational), "matches": _match_evidence(informational)}))
        return signals

    def _contract_signals(self, contract_info: Dict) -> List[Signal]:
        signals = []
        if not contract_info.get("is_verified"):
            signals.append(self._create_signal(SignalType.NEGATIVE, "Unverified Smart Contract",
                "Observed risk signal: source code is not verified on the blockchain explorer, so behavior cannot be independently confirmed. Requires caution.",
                SIGNAL_WEIGHTS["unverified_contract"], "contract_analysis", severity="medium", evidence={"is_verified": False, "compiler_version": contract_info.get("compiler_version")}))
        else:
            signals.append(self._create_signal(SignalType.POSITIVE, "Verified Smart Contract",
                "Observed risk signal (positive): source code is verified and publicly viewable on the explorer.",
                SIGNAL_WEIGHTS["verified_contract"], "contract_analysis", evidence={"is_verified": True, "compiler_version": contract_info.get("compiler_version")}))
        if contract_info.get("has_proxy") and not contract_info.get("is_verified"):
            signals.append(self._create_signal(SignalType.NEGATIVE, "Unverified Proxy Contract",
                "Observed risk signal: this is a proxy contract with an unverified implementation, so the logic it delegates to cannot be confirmed. Requires caution.",
                SIGNAL_WEIGHTS["unverified_proxy_contract"], "contract_analysis", severity="high", evidence={"has_proxy": True, "is_verified": False}))
        creation_time = contract_info.get("creation_timestamp")
        if creation_time:
            days_old = (datetime.utcnow() - creation_time).days
            if days_old < 30:
                signals.append(self._create_signal(SignalType.NEGATIVE, "Recently Deployed Contract",
                    f"Observed risk signal: contract was deployed only {days_old} day(s) ago; newly deployed contracts have a short track record.",
                    SIGNAL_WEIGHTS["recently_deployed_contract"], "contract_analysis", severity="medium", evidence={"days_old": days_old}))
        return signals

    def _token_transfer_signals(self, token_transfers: List[Dict]) -> List[Signal]:
        if len(token_transfers) > 100:
            return [self._create_signal(SignalType.POSITIVE, "Active Token Holder",
                f"Observed risk signal (positive): address has participated in {len(token_transfers)} token transfers.",
                SIGNAL_WEIGHTS["active_token_holder"], "token_analysis", evidence={"token_transfer_count": len(token_transfers), "threshold": "more than 100"})]
        return []

    def _time_based_signals(self, first_tx_timestamp: datetime) -> List[Signal]:
        days_active = max(0, (datetime.utcnow() - first_tx_timestamp).days)
        if days_active > 365:
            return [self._create_signal(SignalType.POSITIVE, "Long Activity History",
                f"Observed risk signal (positive): address has been active for over {days_active} days. Long history alone does not prove legitimacy, but it is a data point.",
                SIGNAL_WEIGHTS["long_activity_history"], "temporal_analysis", evidence={"days_active": days_active})]
        if days_active > 180:
            return [self._create_signal(SignalType.POSITIVE, "Established History",
                f"Observed risk signal (positive): address has been active for {days_active} days.",
                SIGNAL_WEIGHTS["established_activity_history"], "temporal_analysis", evidence={"days_active": days_active})]
        if days_active < 30:
            return [self._create_signal(SignalType.NEGATIVE, "New Address",
                f"Observed risk signal: address is only {days_active} day(s) old. New addresses simply have less history to evaluate — this is not proof of malicious intent.",
                SIGNAL_WEIGHTS["new_address"], "temporal_analysis", severity="low", evidence={"days_active": days_active})]
        return []

    def _create_signal(self, signal_type, name, description, weight, source, severity="info", evidence=None, confidence=1.0):
        return Signal(signal_type=signal_type, name=name, description=description, weight=weight,
                      severity=severity, evidence=evidence, source=source, confidence=confidence)
