"""
ChainGuard tests.

Covers address validation, deterministic signal extraction and scoring, the
four demo scenarios, the HTTP API (via FastAPI's TestClient), frontend asset
wiring, and the live-mode Etherscan provider (with the network mocked — no
real Etherscan calls are made).

Run with:  python -m pytest test_core.py -v
"""

import asyncio
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from blockchain import eth_provider as eth_provider_module
from blockchain.demo_provider import (
    ACTIVE_DEFI_ADDRESS,
    DEMO_SCENARIO_ADDRESSES,
    DRAINER_ADDRESS,
    HIGH_RISK_ADDRESS,
    LOW_RISK_ADDRESS,
    SUSPICIOUS_CONTRACT_ADDRESS,
    DemoProvider,
)
from blockchain.eth_provider import EthereumProvider, _utc_naive
from blockchain.provider import Transaction
from core.config import ETHERSCAN_V2_URL, NETWORKS, Settings
from core.models import AddressAnalysisRequest, RiskLevel, Signal, SignalType
from risk_engine.scoring import ReputationScorer
from risk_engine.signals import SIGNAL_WEIGHTS, SignalExtractor
from threat_intel.database import get_threat_intel

ROOT = Path(__file__).parent
NOW = datetime.utcnow()
WALLET = "0x1234567890123456789012345678901234567890"
OTHER = "0x9999999999999999999999999999999999999999"


def make_tx(to=OTHER, frm=WALLET, days_ago=1.0, failed=False, value=1.0, n=0):
    return Transaction(
        hash="0x" + format(n, "064x"),
        from_address=frm,
        to_address=to,
        value=value,
        gas_price=50.0,
        gas_used=21000,
        timestamp=NOW - timedelta(days=days_ago),
        block_number=1000 + n,
        is_failed=failed,
    )


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """Keep API tests from touching the real data/ directory."""
    import storage.database as db

    monkeypatch.setattr(db, "ANALYSES_FILE", tmp_path / "analyses.json")
    monkeypatch.setattr(db, "SEARCH_HISTORY_FILE", tmp_path / "search_history.json")


@pytest.fixture()
def client():
    from main import app

    return TestClient(app)


# ============================================================================
# Address validation
# ============================================================================


class TestAddressValidation:
    def test_valid_address(self):
        assert AddressAnalysisRequest(address=LOW_RISK_ADDRESS).address == LOW_RISK_ADDRESS

    def test_address_lowercased(self):
        request = AddressAnalysisRequest(address=LOW_RISK_ADDRESS.upper().replace("0X", "0x"))
        assert request.address == LOW_RISK_ADDRESS

    @pytest.mark.parametrize(
        "bad",
        [
            "not_an_address",
            "0x123",
            "0xZZZZ000000000000000000000000000000000001",
            "0x" + "defi" + "0" * 35 + "3",  # the historic invalid demo address: 'i' is not hex
        ],
    )
    def test_invalid_addresses_rejected(self, bad):
        with pytest.raises(ValueError):
            AddressAnalysisRequest(address=bad)


# ============================================================================
# Signal extraction
# ============================================================================


class TestSignalExtraction:
    def test_no_transactions_is_neutral_with_evidence(self):
        signals, metrics = SignalExtractor().extract_signals(WALLET, [], is_contract=False)
        assert metrics["transaction_count"] == 0
        assert len(signals) == 1
        assert signals[0].signal_type == SignalType.NEUTRAL
        assert signals[0].weight == 0
        assert signals[0].evidence == {"transaction_count": 0}

    def test_long_history_positive_signal(self):
        old = NOW - timedelta(days=730)
        signals, _ = SignalExtractor().extract_signals(
            WALLET, [make_tx(days_ago=730)], is_contract=False, first_tx_timestamp=old
        )
        assert [s.name for s in signals] == ["Long Activity History"]
        assert signals[0].weight == SIGNAL_WEIGHTS["long_activity_history"]

    def test_new_address_negative_signal(self):
        signals, _ = SignalExtractor().extract_signals(
            WALLET, [make_tx(days_ago=1)], is_contract=False, first_tx_timestamp=NOW - timedelta(days=1)
        )
        assert any(s.name == "New Address" and s.weight == SIGNAL_WEIGHTS["new_address"] for s in signals)

    def test_flagged_counterparty_interaction(self):
        lookup = {OTHER: {"risk_type": "drainer", "severity": "critical", "source": "test", "description": "d"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(
            WALLET, [make_tx(to=OTHER, n=7)], is_contract=False
        )
        flagged = [s for s in signals if s.name == "Interaction with Flagged Addresses"]
        assert len(flagged) == 1
        sig_ = flagged[0]
        assert sig_.weight == SIGNAL_WEIGHTS["flagged_address_interaction"]
        assert sig_.severity == "critical"
        match = sig_.evidence["matches"][0]
        assert match["address"] == OTHER
        assert match["interaction_count"] == 1
        assert match["transaction_hashes"] == ["0x" + format(7, "064x")]

    def test_inbound_flagged_counterparty_is_detected(self):
        lookup = {OTHER: {"severity": "high"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(
            WALLET, [make_tx(frm=OTHER, to=WALLET)], is_contract=False
        )
        assert any(s.name == "Interaction with Flagged Addresses" for s in signals)

    def test_low_severity_watchlist_entry_never_scores(self):
        """A benign 'low' entry (e.g. null address) must not be a scoring red flag."""
        lookup = {OTHER: {"risk_type": "null_address", "severity": "low"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(
            WALLET, [make_tx(to=OTHER)], is_contract=False
        )
        info = [s for s in signals if "Low-Severity" in s.name]
        assert len(info) == 1 and info[0].weight == 0 and info[0].signal_type == SignalType.NEUTRAL
        assert not any(s.weight < 0 and s.source == "threat_intelligence" for s in signals)

    def test_self_flagged_address(self):
        lookup = {WALLET: {"risk_type": "scam", "severity": "high", "source": "test", "description": "d"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(
            WALLET, [make_tx()], is_contract=False
        )
        sig_ = next(s for s in signals if s.name == "Address Present in Threat Intelligence")
        assert sig_.weight == SIGNAL_WEIGHTS["flagged_address_self"] < 0
        assert sig_.evidence["address"] == WALLET
        assert sig_.evidence["risk_type"] == "scam"

    def test_self_flag_detected_even_with_no_transactions(self):
        lookup = {WALLET: {"severity": "critical"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(WALLET, [], is_contract=False)
        assert any(s.name == "Address Present in Threat Intelligence" for s in signals)

    def test_self_flag_low_severity_is_informational(self):
        lookup = {WALLET: {"severity": "low"}}
        signals, _ = SignalExtractor(threat_intel_lookup=lookup).extract_signals(WALLET, [], is_contract=False)
        listed = next(s for s in signals if "Low Severity" in s.name)
        assert listed.weight == 0

    def test_unverified_contract_signals(self):
        signals, _ = SignalExtractor().extract_signals(
            WALLET,
            [make_tx(days_ago=3)],
            is_contract=True,
            contract_info={
                "is_verified": False,
                "has_proxy": True,
                "creation_timestamp": NOW - timedelta(days=3),
                "compiler_version": None,
            },
            first_tx_timestamp=NOW - timedelta(days=3),
        )
        names = {s.name for s in signals}
        assert {"Unverified Smart Contract", "Unverified Proxy Contract", "Recently Deployed Contract"} <= names

    def test_verified_contract_positive_signal(self):
        signals, _ = SignalExtractor().extract_signals(
            WALLET,
            [make_tx(days_ago=400)],
            is_contract=True,
            contract_info={"is_verified": True, "compiler_version": "v0.8.20"},
            first_tx_timestamp=NOW - timedelta(days=400),
        )
        verified = next(s for s in signals if s.name == "Verified Smart Contract")
        assert verified.weight == SIGNAL_WEIGHTS["verified_contract"]
        assert verified.evidence["compiler_version"] == "v0.8.20"

    def test_failed_transaction_rate_tiers(self):
        def failed_signal(n_failed, n_total):
            txs = [make_tx(days_ago=90, failed=(i < n_failed), n=i) for i in range(n_total)]
            signals, _ = SignalExtractor().extract_signals(WALLET, txs, is_contract=False)
            return [s.name for s in signals if "Failed" in s.name]

        assert failed_signal(6, 10) == ["High Failed Transaction Rate"]  # 60%
        assert failed_signal(3, 10) == ["Elevated Failed Transactions"]  # 30%
        assert failed_signal(1, 10) == []  # 10%

    def test_recent_activity_burst(self):
        txs = [make_tx(days_ago=1, failed=(i % 2 == 0), n=i) for i in range(25)]
        signals, _ = SignalExtractor().extract_signals(WALLET, txs, is_contract=False)
        burst = next(s for s in signals if s.name == "Recent Activity Burst")
        assert burst.evidence["recent_transaction_count"] == 25

    def test_volume_and_token_signals_carry_evidence(self):
        txs = [make_tx(days_ago=90, n=i) for i in range(150)]
        tokens = [{"hash": "0x1"}] * 120
        signals, _ = SignalExtractor().extract_signals(WALLET, txs, is_contract=False, token_transfers=tokens)
        by_name = {s.name: s for s in signals}
        assert by_name["Moderate Transaction Volume"].evidence["transaction_count"] == 150
        assert by_name["Active Token Holder"].evidence["token_transfer_count"] == 120

    def test_extraction_is_deterministic(self):
        txs = [make_tx(days_ago=5, failed=(i % 3 == 0), n=i) for i in range(30)]

        def dump():
            signals, _ = SignalExtractor().extract_signals(
                WALLET, txs, is_contract=False, first_tx_timestamp=NOW - timedelta(days=5)
            )
            return [s.model_dump() for s in signals]

        assert dump() == dump()


# ============================================================================
# Scoring
# ============================================================================


def sig(weight):
    return Signal(
        signal_type=SignalType.POSITIVE if weight > 0 else SignalType.NEGATIVE,
        name="t",
        description="t",
        weight=weight,
        source="test",
    )


class TestScoring:
    def test_no_signals_gives_base_score(self):
        score, reasoning = ReputationScorer().calculate_score([])
        assert score == ReputationScorer.BASE_SCORE == 50
        assert "no signals" in reasoning.lower()

    def test_positive_and_negative_signals_move_score(self):
        assert ReputationScorer().calculate_score([sig(10)])[0] == 60
        assert ReputationScorer().calculate_score([sig(-10)])[0] == 40

    def test_score_is_clamped(self):
        assert ReputationScorer().calculate_score([sig(100)] * 10)[0] == 100
        assert ReputationScorer().calculate_score([sig(-100)] * 10)[0] == 0

    def test_score_is_weight_sum_only(self):
        """Score = 50 + sum(weights): confidence and severity do not alter it."""
        low_conf = sig(-20).model_copy(update={"confidence": 0.1, "severity": "info"})
        assert ReputationScorer().calculate_score([low_conf])[0] == 30

    @pytest.mark.parametrize(
        "score,level",
        [
            (0, RiskLevel.CRITICAL), (20, RiskLevel.CRITICAL),
            (21, RiskLevel.HIGH), (40, RiskLevel.HIGH),
            (41, RiskLevel.MODERATE), (60, RiskLevel.MODERATE),
            (61, RiskLevel.LOW), (80, RiskLevel.LOW),
            (81, RiskLevel.VERY_LOW), (100, RiskLevel.VERY_LOW),
        ],
    )
    def test_risk_level_boundaries(self, score, level):
        assert ReputationScorer().score_to_risk_level(score) == level

    def test_reasoning_never_contradicts_weights(self):
        scorer = ReputationScorer()
        _, only_positive = scorer.calculate_score([sig(5), sig(2)])
        assert "No negative signals" in only_positive
        _, only_negative = scorer.calculate_score([sig(-5)])
        assert "No positive signals" in only_negative

    def test_full_reputation_populates_all_fields(self):
        rep = ReputationScorer().calculate_full_reputation(
            address=WALLET,
            transactions=[make_tx(days_ago=800)],
            first_tx_timestamp=NOW - timedelta(days=800),
        )
        assert rep.score == 55 and rep.risk_level == RiskLevel.MODERATE
        assert rep.positive_signal_count == 1 and rep.negative_signal_count == 0
        assert rep.recommendation and rep.reasoning

    def test_no_llm_anywhere_in_the_risk_engine(self):
        """The score must be rule-based: the risk engine may not import an LLM/HTTP client."""
        for path in (ROOT / "risk_engine").glob("*.py"):
            text = path.read_text().lower()
            for banned in ("groq", "anthropic", "openai", "aiohttp", "requests", "httpx"):
                assert f"import {banned}" not in text and f"from {banned}" not in text, (path.name, banned)


# ============================================================================
# Demo provider + the four demo scenarios (deterministic pipeline, end to end)
# ============================================================================

EXPECTED = {
    # scenario: (score, risk_level, must-have signal names)
    "low_risk_wallet": (55, "moderate", {"Long Activity History"}),
    "suspicious_contract": (
        0,
        "critical",
        {
            "Address Present in Threat Intelligence",
            "Unverified Smart Contract",
            "Recently Deployed Contract",
            "New Address",
            "Elevated Failed Transactions",
        },
    ),
    "active_defi_wallet": (
        59,
        "moderate",
        {"Moderate Transaction Volume", "Active Token Holder", "Long Activity History"},
    ),
    "high_risk_wallet": (
        12,
        "critical",
        {"Interaction with Flagged Addresses", "Recent Activity Burst", "High Failed Transaction Rate", "New Address"},
    ),
}


class TestDemoScenarios:
    def test_the_four_demo_addresses(self):
        assert DEMO_SCENARIO_ADDRESSES == {
            "low_risk_wallet": "0xabcd000000000000000000000000000000000001",
            "suspicious_contract": "0xdead000000000000000000000000000000000002",
            "active_defi_wallet": "0xdef1000000000000000000000000000000000003",
            "high_risk_wallet": "0xbad0000000000000000000000000000000000004",
        }

    def test_all_demo_addresses_are_valid_and_distinct(self):
        addrs = list(DEMO_SCENARIO_ADDRESSES.values())
        assert len(set(addrs)) == 4
        for a in addrs:
            assert AddressAnalysisRequest(address=a).address == a

    def test_router_uses_the_same_addresses(self):
        from routers.analyze import DEMO_SCENARIOS

        assert DEMO_SCENARIOS == DEMO_SCENARIO_ADDRESSES

    def test_addresses_referenced_consistently_across_the_project(self):
        bad = "0x" + "defi"  # the historic invalid address prefix
        text_files = [
            p
            for p in ROOT.rglob("*")
            if p.is_file()
            and p.suffix in {".py", ".md", ".js", ".html", ".css", ".json", ".txt", ".example"}
            and "__pycache__" not in p.parts
            and p.name != "test_core.py"
        ]
        for p in text_files:
            assert bad not in p.read_text(errors="ignore"), f"stale invalid demo address in {p.relative_to(ROOT)}"

        readme = (ROOT / "README.md").read_text()
        for addr in DEMO_SCENARIO_ADDRESSES.values():
            assert addr in readme, f"{addr} missing from README.md"

        # Every 42-char 0x token in the docs must be a genuinely valid hex address.
        for doc in ("README.md", "ARCHITECTURE.md", "RISK_ENGINE.md"):
            for token in re.findall(r"0x[0-9A-Za-z]{40}\b", (ROOT / doc).read_text()):
                assert re.fullmatch(r"0x[0-9a-fA-F]{40}", token), f"{doc}: invalid address {token}"

    def test_provider_data_shape(self):
        p = DemoProvider()
        assert run(p.is_contract(SUSPICIOUS_CONTRACT_ADDRESS)) is True
        assert run(p.is_contract(LOW_RISK_ADDRESS)) is False
        assert run(p.get_contract_info(SUSPICIOUS_CONTRACT_ADDRESS)).is_verified is False
        assert len(run(p.get_transactions(ACTIVE_DEFI_ADDRESS))) == 150
        assert len(run(p.get_token_transfers(ACTIVE_DEFI_ADDRESS))) == 120
        assert DRAINER_ADDRESS in run(p.get_flagged_addresses())
        assert run(p.get_transactions("0x" + "1" * 40)) == []  # unknown address -> empty, not an error

    def test_transactions_are_most_recent_first(self):
        for addr in DEMO_SCENARIO_ADDRESSES.values():
            txs = run(DemoProvider().get_transactions(addr))
            stamps = [t.timestamp for t in txs]
            assert stamps == sorted(stamps, reverse=True)

    @pytest.mark.parametrize("scenario", list(EXPECTED))
    def test_scenario_via_api(self, client, scenario):
        score, level, required = EXPECTED[scenario]
        r = client.get(f"/api/analyze/demo/{scenario}")
        assert r.status_code == 200, r.text
        body = r.json()
        rep = body["reputation_score"]

        assert body["is_demo_data"] is True and body["data_source"] == "demo"
        assert body["address_info"]["address"] == DEMO_SCENARIO_ADDRESSES[scenario]
        assert (rep["score"], rep["risk_level"]) == (score, level)
        names = {s["name"] for s in rep["signals"]}
        assert required <= names, required - names
        assert body["interaction_graph"]["nodes"][0]["is_central"] is True
        assert len(body["interaction_graph"]["nodes"]) >= 3
        assert body["recent_transactions"]

        # Score is exactly base + sum(weights), clamped — nothing else contributes.
        raw = 50 + sum(s["weight"] for s in rep["signals"])
        assert rep["score"] == max(0, min(100, round(raw)))

    @pytest.mark.parametrize("scenario", list(EXPECTED))
    def test_every_scoring_signal_has_evidence(self, client, scenario):
        for s in client.get(f"/api/analyze/demo/{scenario}").json()["reputation_score"]["signals"]:
            assert s["evidence"], f"{scenario}: '{s['name']}' has no evidence"
            assert s["source"]
            assert 0 <= s["confidence"] <= 1

    def test_scenarios_are_repeatable(self, client):
        def snapshot():
            rep = client.get("/api/analyze/demo/high_risk_wallet").json()["reputation_score"]
            return rep["score"], [(s["name"], s["weight"]) for s in rep["signals"]]

        assert snapshot() == snapshot()

    def test_flagged_nodes_in_graph(self, client):
        g = client.get("/api/analyze/demo/high_risk_wallet").json()["interaction_graph"]
        assert [n["address"] for n in g["nodes"] if n["is_flagged"]] == [DRAINER_ADDRESS]
        g = client.get("/api/analyze/demo/suspicious_contract").json()["interaction_graph"]
        assert next(n for n in g["nodes"] if n["is_central"])["is_flagged"] is True

    def test_threat_intel_dataset_loads_and_is_labelled(self):
        db = get_threat_intel()
        assert "DEMO" in db.disclaimer and "NOT" in db.disclaimer
        assert DRAINER_ADDRESS in db.get_flagged_addresses("ethereum_mainnet")
        assert DRAINER_ADDRESS not in db.get_flagged_addresses("sepolia")


# ============================================================================
# Documentation accuracy (docs must not drift from the code)
# ============================================================================


class TestDocs:
    def test_every_weight_is_documented_with_its_actual_value(self):
        doc = (ROOT / "RISK_ENGINE.md").read_text()
        for key, weight in SIGNAL_WEIGHTS.items():
            m = re.search(rf"\| `{key}` \| ([+\-−]?\d+) \|", doc)
            assert m, f"{key} missing from RISK_ENGINE.md catalog"
            assert int(m.group(1).replace("−", "-")) == weight, f"{key}: doc says {m.group(1)}, code says {weight}"

    def test_docs_point_to_the_real_weight_location(self):
        doc = (ROOT / "RISK_ENGINE.md").read_text()
        assert "risk_engine/signals.py" in doc
        assert "SIGNAL_WEIGHTS" in (ROOT / "risk_engine" / "signals.py").read_text()
        assert "weights in `core/config.py`" not in doc

    def test_files_mentioned_in_docs_exist(self):
        allowed_runtime = {"data/analyses.json", "data/search_history.json", "analyses.json", "search_history.json", ".env"}
        for doc in ("README.md", "ARCHITECTURE.md", "RISK_ENGINE.md"):
            text = (ROOT / doc).read_text()
            for ref in set(re.findall(r"`([\w./-]+\.(?:py|js|html|css|json|md|txt|example))`", text)):
                if ref in allowed_runtime or "*" in ref or ref.startswith("/"):  # runtime files / URL paths
                    continue
                candidates = [ROOT / ref] + [ROOT / d / ref for d in ("core", "blockchain", "risk_engine",
                                                                     "routers", "threat_intel", "storage",
                                                                     "frontend", "frontend/js")]
                assert any(c.exists() for c in candidates), f"{doc} mentions missing file `{ref}`"

    def test_readme_makes_no_unimplemented_claims(self):
        readme = (ROOT / "README.md").read_text().lower()
        assert "no ai explainer is implemented" in readme
        assert "multi-chain" not in readme.replace("no multi-chain analysis", "")


# ============================================================================
# HTTP API
# ============================================================================


class TestAPI:
    def test_health(self, client):
        body = client.get("/health").json()
        assert body["status"] == "healthy" and body["demo_mode"] is True

    def test_api_status(self, client):
        body = client.get("/api/status").json()
        assert body["message"] == "ChainGuard API" and body["demo_mode"] is True

    def test_post_analyze(self, client):
        r = client.post("/api/analyze", json={"address": HIGH_RISK_ADDRESS.upper().replace("0X", "0x")})
        assert r.status_code == 200
        assert r.json()["reputation_score"]["score"] == 12

    def test_post_analyze_options_respected(self, client):
        r = client.post(
            "/api/analyze",
            json={"address": LOW_RISK_ADDRESS, "include_graph": False, "include_transactions": False},
        )
        body = r.json()
        assert body["interaction_graph"] is None and body["recent_transactions"] == []

    def test_post_analyze_unknown_address_is_insufficient_evidence(self, client):
        r = client.post("/api/analyze", json={"address": "0x" + "5" * 40})
        rep = r.json()["reputation_score"]
        assert rep["score"] == 50
        assert rep["signals"][0]["name"] == "No Transaction History"

    @pytest.mark.parametrize(
        "payload",
        [{"address": "nope"}, {"address": "0x123"}, {"address": LOW_RISK_ADDRESS, "chain": "solana"}, {}],
    )
    def test_post_analyze_validation_errors(self, client, payload):
        assert client.post("/api/analyze", json=payload).status_code == 422

    def test_unknown_demo_scenario(self, client):
        r = client.get("/api/analyze/demo/nope")
        assert r.status_code == 404 and "low_risk_wallet" in r.json()["detail"]

    def test_address_endpoint_cache_flow(self, client):
        assert client.get(f"/api/address/{LOW_RISK_ADDRESS}").status_code == 404
        client.post("/api/analyze", json={"address": LOW_RISK_ADDRESS})
        r = client.get(f"/api/address/{LOW_RISK_ADDRESS}")
        assert r.status_code == 200 and r.json()["reputation_score"]["score"] == 55
        assert client.get(f"/api/address/{LOW_RISK_ADDRESS}?chain=nope").status_code == 400

    def test_history_endpoint(self, client):
        assert client.get("/api/history").json() == {"entries": [], "total_count": 0}
        client.get("/api/analyze/demo/low_risk_wallet")
        client.get("/api/analyze/demo/high_risk_wallet")
        body = client.get("/api/history").json()
        assert body["total_count"] == 2
        assert body["entries"][0]["address"] == HIGH_RISK_ADDRESS  # most recent first
        assert body["entries"][0]["is_demo"] is True

    def test_live_mode_without_key_errors_instead_of_falling_back_to_demo(self, client, monkeypatch):
        import routers.analyze as analyze_router

        live = Settings(_env_file=None, use_demo_mode=False, eth_mainnet_etherscan="")
        monkeypatch.setattr(analyze_router, "get_settings", lambda: live)
        r = client.post("/api/analyze", json={"address": LOW_RISK_ADDRESS})
        assert r.status_code == 400
        assert "ETH_MAINNET_ETHERSCAN" in r.json()["detail"]

    def test_live_mode_upstream_failure_is_a_502_not_empty_data(self, client, monkeypatch):
        import routers.analyze as analyze_router

        async def boom(self, params):
            raise ConnectionError("Etherscan API error: Invalid API Key")

        live = Settings(_env_file=None, use_demo_mode=False, eth_mainnet_etherscan="k")
        monkeypatch.setattr(analyze_router, "get_settings", lambda: live)
        monkeypatch.setattr(EthereumProvider, "_etherscan_request", boom)
        r = client.post("/api/analyze", json={"address": LOW_RISK_ADDRESS})
        assert r.status_code == 502 and "Invalid API Key" in r.json()["detail"]

    def test_stray_env_keys_do_not_crash_settings(self):
        Settings(_env_file=None, demo_mode_default="True")  # unknown key is ignored


# ============================================================================
# Frontend wiring
# ============================================================================


class TestFrontend:
    def test_static_assets_are_served(self, client):
        html = client.get("/")
        assert html.status_code == 200 and "ChainGuard" in html.text
        assert client.get("/styles.css").status_code == 200
        assert client.get("/js/api.js").status_code == 200
        assert client.get("/js/app.js").status_code == 200

    def test_html_references_resolve_to_files(self):
        html = (ROOT / "frontend" / "index.html").read_text()
        refs = re.findall(r'(?:src|href)="([^"#]+)"', html)
        assert {"styles.css", "js/api.js", "js/app.js"} <= set(refs)
        for ref in refs:
            assert (ROOT / "frontend" / ref).is_file(), ref

    def test_every_dom_id_used_by_app_js_exists_in_html(self):
        html = (ROOT / "frontend" / "index.html").read_text()
        js = (ROOT / "frontend" / "js" / "app.js").read_text()
        html_ids = set(re.findall(r'id="([^"]+)"', html))
        used = set(re.findall(r"getElementById\('([^']+)'\)", js))
        assert used <= html_ids, used - html_ids

    def test_api_js_calls_only_real_endpoints(self, client):
        js = (ROOT / "frontend" / "js" / "api.js").read_text()
        assert "const API_BASE_URL = '/api'" in js
        for fragment in ("/analyze`", "/analyze/demo/", "/address/", "/history`", "'/health'"):
            assert fragment in js, fragment
        # ...and those endpoints exist on the backend
        paths = set(client.get("/openapi.json").json()["paths"])
        for p in ("/health", "/api/status", "/api/analyze", "/api/analyze/demo/{scenario}",
                  "/api/address/{address}", "/api/history"):
            assert p in paths, p

    def test_every_css_class_used_is_defined(self):
        css = (ROOT / "frontend" / "styles.css").read_text()
        defined = set(re.findall(r"\.([a-zA-Z][\w-]*)", css))
        wrappers = {"analysis", "history", "score-content"}  # structural containers, intentionally unstyled
        html = (ROOT / "frontend" / "index.html").read_text()
        js = (ROOT / "frontend" / "js" / "app.js").read_text()
        used = set()
        for text in (html, js):
            for m in re.finditer(r"""class(?:Name)?\s*=\s*\\?["'`]([^"'`$]+)["'`]""", text):
                used.update(c for c in m.group(1).split() if re.fullmatch(r"[a-zA-Z][\w-]*", c))
        assert not (used - defined - wrappers), sorted(used - defined - wrappers)


# ============================================================================
# Live-mode Etherscan provider (network mocked)
# ============================================================================


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status = payload, status

    async def json(self, content_type=None):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class FakeSession:
    calls = []
    payload = {}
    status = 200

    def __init__(self, *a, **k):
        pass

    def get(self, url, params=None):
        FakeSession.calls.append((url, dict(params or {})))
        return FakeResponse(FakeSession.payload, FakeSession.status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


@pytest.fixture()
def fake_http(monkeypatch):
    FakeSession.calls, FakeSession.payload, FakeSession.status = [], {}, 200
    monkeypatch.setattr(eth_provider_module.aiohttp, "ClientSession", FakeSession)
    return FakeSession


def live_provider(network="ethereum_mainnet"):
    n = NETWORKS[network]
    return EthereumProvider(network, n["chain_id"], "KEY", n["etherscan_url"])


class TestEthereumProvider:
    def test_uses_etherscan_v2_with_chainid(self, fake_http):
        assert ETHERSCAN_V2_URL == "https://api.etherscan.io/v2/api"
        assert all(n["etherscan_url"] == ETHERSCAN_V2_URL for n in NETWORKS.values())
        fake_http.payload = {"status": "1", "result": "1000000000000000000"}
        assert run(live_provider().get_balance(WALLET)) == 1.0
        url, params = fake_http.calls[0]
        assert url == ETHERSCAN_V2_URL and params["chainid"] == "1" and params["apikey"] == "KEY"
        run(live_provider("sepolia").get_balance(WALLET))
        assert fake_http.calls[1][1]["chainid"] == "11155111"

    def test_notok_is_an_error_not_empty_data(self, fake_http):
        fake_http.payload = {"status": "0", "message": "NOTOK", "result": "Invalid API Key"}
        with pytest.raises(ConnectionError, match="Invalid API Key"):
            run(live_provider().get_transactions(WALLET))

    def test_http_error_is_an_error(self, fake_http):
        fake_http.status = 500
        with pytest.raises(ConnectionError):
            run(live_provider().get_transactions(WALLET))

    def test_no_transactions_found_is_legitimately_empty(self, fake_http):
        fake_http.payload = {"status": "0", "message": "No transactions found", "result": []}
        assert run(live_provider().get_transactions(WALLET)) == []

    def test_unverified_contract_is_classified_as_contract(self, fake_http):
        """Regression: getsourcecode-based detection labelled unverified contracts as wallets."""
        fake_http.payload = {"jsonrpc": "2.0", "id": 1, "result": "0x6080604052"}
        assert run(live_provider().is_contract(WALLET)) is True
        assert fake_http.calls[0][1]["action"] == "eth_getCode"
        fake_http.payload = {"jsonrpc": "2.0", "id": 1, "result": "0x"}
        assert run(live_provider().is_contract(WALLET)) is False

    def test_transaction_parsing_uses_utc(self, fake_http):
        fake_http.payload = {
            "status": "1",
            "message": "OK",
            "result": [
                {
                    "hash": "0xabc", "from": WALLET.upper(), "to": OTHER, "value": "2500000000000000000",
                    "gasPrice": "50000000000", "gasUsed": "21000", "timeStamp": "0",
                    "blockNumber": "1", "isError": "1", "input": "0x",
                }
            ],
        }
        (tx,) = run(live_provider().get_transactions(WALLET))
        assert tx.value == 2.5 and tx.gas_used == 21000 and tx.is_failed is True
        assert tx.from_address == WALLET  # lower-cased
        assert tx.timestamp == datetime(1970, 1, 1)  # exactly epoch, independent of local timezone
        assert _utc_naive(86400) == datetime(1970, 1, 2)
