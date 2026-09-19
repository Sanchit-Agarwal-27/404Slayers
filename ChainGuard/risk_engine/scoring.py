"""
Reputation Score Calculation

Combines signals into an explainable 0-100 reputation score. This module
is entirely deterministic and rule-based: given the same signals, it
always returns the same score. No LLM is involved in computing the score
or inventing evidence — see core/models.py Signal, which requires every
signal to carry its own source and (where relevant) evidence.
"""

import logging
from typing import List, Dict, Tuple, Optional
from datetime import datetime

from core.models import Signal, SignalType, ReputationScore, RiskLevel
from risk_engine.signals import SignalExtractor

logger = logging.getLogger(__name__)


class ReputationScorer:
    """Calculates a deterministic reputation score from a list of Signals."""

    SCORE_MIN = 0
    SCORE_MAX = 100
    BASE_SCORE = 50  # Neutral starting point before any signal is applied

    # Score -> risk level thresholds. Inclusive upper bounds.
    RISK_THRESHOLDS: List[Tuple[int, RiskLevel]] = [
        (20, RiskLevel.CRITICAL),
        (40, RiskLevel.HIGH),
        (60, RiskLevel.MODERATE),
        (80, RiskLevel.LOW),
        (100, RiskLevel.VERY_LOW),
    ]

    RECOMMENDATIONS: Dict[RiskLevel, str] = {
        RiskLevel.CRITICAL: (
            "Multiple high-severity risk signals were found, including at least one match against the "
            "threat-intelligence dataset in some cases. Avoid interacting with this address until you "
            "have independently reviewed the evidence below."
        ),
        RiskLevel.HIGH: (
            "Significant risk signals were found. Exercise extreme caution — review every piece of "
            "evidence below before sending funds or granting approvals."
        ),
        RiskLevel.MODERATE: (
            "Signals are mixed. Proceed with caution: verify counterparties and contract permissions "
            "independently before any high-value interaction."
        ),
        RiskLevel.LOW: (
            "Signals are mostly positive with no major red flags detected. Standard precautions still "
            "apply — this is not a guarantee of safety."
        ),
        RiskLevel.VERY_LOW: (
            "This address shows a strong positive track record across the signals ChainGuard checks. "
            "It still is not a certified guarantee of legitimacy — verify anything unusual directly."
        ),
    }

    def __init__(self, threat_intel_lookup: Optional[Dict] = None):
        self.signal_extractor = SignalExtractor(threat_intel_lookup=threat_intel_lookup)

    def calculate_score(self, signals: List[Signal]) -> Tuple[int, str]:
        """
        Calculate final reputation score from signals.

        Returns:
            Tuple of (score: 0-100, reasoning: str)
        """
        if not signals:
            return self.BASE_SCORE, "Insufficient evidence: no signals were available for scoring."

        score = self.BASE_SCORE
        positive_weight = 0.0
        negative_weight = 0.0

        for signal in signals:
            weight = signal.weight
            if weight > 0:
                positive_weight += weight
            elif weight < 0:
                negative_weight += abs(weight)
            score += weight

        final_score = max(self.SCORE_MIN, min(self.SCORE_MAX, int(round(score))))
        reasoning = self._generate_reasoning(final_score, len(signals), positive_weight, negative_weight)

        return final_score, reasoning

    def calculate_full_reputation(
        self,
        address: str,
        transactions: List = None,
        is_contract: bool = False,
        contract_info: Dict = None,
        balance: float = 0.0,
        token_transfers: List[Dict] = None,
        first_tx_timestamp: Optional[datetime] = None,
        threat_intel_lookup: Optional[Dict] = None,
    ) -> ReputationScore:
        """
        Calculate the complete reputation score, including signals, risk
        level, human-readable reasoning, and a security recommendation.
        """
        if threat_intel_lookup is not None:
            self.signal_extractor.threat_intel_lookup = threat_intel_lookup

        signals, metrics = self.signal_extractor.extract_signals(
            address=address,
            transactions=transactions or [],
            is_contract=is_contract,
            contract_info=contract_info,
            balance=balance,
            token_transfers=token_transfers,
            first_tx_timestamp=first_tx_timestamp,
        )

        score, reasoning = self.calculate_score(signals)
        risk_level = self.score_to_risk_level(score)

        positive_count = sum(1 for s in signals if s.weight > 0)
        negative_count = sum(1 for s in signals if s.weight < 0)

        return ReputationScore(
            score=score,
            risk_level=risk_level,
            signals=signals,
            positive_signal_count=positive_count,
            negative_signal_count=negative_count,
            reasoning=reasoning,
            recommendation=self.RECOMMENDATIONS[risk_level],
        )

    def score_to_risk_level(self, score: int) -> RiskLevel:
        """Convert a numeric score to a risk level using RISK_THRESHOLDS."""
        for upper_bound, level in self.RISK_THRESHOLDS:
            if score <= upper_bound:
                return level
        return RiskLevel.VERY_LOW

    # Backwards-compatible alias
    def _score_to_risk_level(self, score: int) -> RiskLevel:
        return self.score_to_risk_level(score)

    def _generate_reasoning(
        self,
        score: int,
        signal_count: int,
        positive_weight: float,
        negative_weight: float,
    ) -> str:
        """Generate a human-readable explanation of how the score was reached."""

        if score <= 20:
            level = "Critical"
        elif score <= 40:
            level = "High"
        elif score <= 60:
            level = "Moderate"
        elif score <= 80:
            level = "Low"
        else:
            level = "Very low"
        base_msg = f"{level} risk level ({signal_count} signal(s) evaluated)."

        # The detail sentence is derived from the actual signal weights, never
        # from the score band, so it cannot contradict the evidence shown.
        if negative_weight == 0 and positive_weight == 0:
            detail = "No signal moved the score away from the neutral baseline of 50."
        elif negative_weight == 0:
            detail = "No negative signals were found; only positive signals raised the score."
        elif positive_weight == 0:
            detail = "No positive signals were found; only negative signals lowered the score."
        elif negative_weight > positive_weight * 2:
            detail = "Negative signals substantially outweigh positive ones."
        elif positive_weight > negative_weight * 2:
            detail = "Positive signals substantially outweigh negative ones."
        else:
            detail = "Positive and negative signals are more evenly balanced — requires caution."

        return f"{base_msg} {detail}"


# Singleton instance
_scorer: Optional[ReputationScorer] = None


def get_scorer() -> ReputationScorer:
    """Get or create the reputation scorer singleton."""
    global _scorer
    if _scorer is None:
        _scorer = ReputationScorer()
    return _scorer
