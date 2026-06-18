from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

from app.integration_engine.core import (
    BaseConnector,
    BaseCorrelationEngine,
    BaseValidator,
    IntegrationContext,
    IntegrationEngine,
    IntegrationError,
    IntegrationRegistry,
    IntegrationResult,
    IntegrationSchemaError,
    IntegrationTransientError,
)

# ---------------------------------------------------------
# Connectors Definitions for OSINT reputation checks
# ---------------------------------------------------------

class VirusTotalConnector(BaseConnector):
    name = "virustotal"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        indicator = payload.get("indicator")
        if not indicator:
            raise IntegrationError("Missing indicator payload")
        if indicator == "timeout":
            raise IntegrationTransientError("VirusTotal API request timeout")
        if indicator == "rate_limit":
            raise IntegrationTransientError("VirusTotal rate limit (HTTP 429)")
        if indicator == "malicious":
            return {"malicious_hits": 14, "total_scans": 72, "verdict": "malicious"}
        return {"malicious_hits": 0, "total_scans": 72, "verdict": "clean"}


class AbuseIPDBConnector(BaseConnector):
    name = "abuseipdb"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        ip = payload.get("ip")
        if not ip:
            raise IntegrationError("Missing IP address")
        if ip == "rate_limit":
            raise IntegrationTransientError("AbuseIPDB rate limit exceeded")
        if ip == "bad":
            return {"abuse_confidence_score": 98, "total_reports": 156, "verdict": "suspicious"}
        return {"abuse_confidence_score": 0, "total_reports": 0, "verdict": "clean"}


class AlienVaultOTXConnector(BaseConnector):
    name = "alienvault_otx"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        indicator = payload.get("indicator")
        if indicator == "timeout":
            raise IntegrationTransientError("AlienVault timeout")
        if indicator == "bad":
            return {"pulse_count": 8, "threat_score": 85.0}
        return {"pulse_count": 0, "threat_score": 0.0}


class ShodanConnector(BaseConnector):
    name = "shodan"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        ip = payload.get("ip")
        if ip == "bad":
            return {"ports": [22, 80, 443, 8080], "vulns": ["CVE-2021-44228"], "is_compromised": True}
        return {"ports": [80, 443], "vulns": [], "is_compromised": False}


class CensysConnector(BaseConnector):
    name = "censys"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        ip = payload.get("ip")
        if ip == "bad":
            return {"has_malicious_cert": True, "protocols": ["ssh", "http"]}
        return {"has_malicious_cert": False, "protocols": ["http"]}


class SecurityTrailsConnector(BaseConnector):
    name = "securitytrails"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        domain = payload.get("domain")
        if domain == "bad":
            return {"historical_ips_count": 45, "alexa_rank": None, "suspicious_subdomains": True}
        return {"historical_ips_count": 2, "alexa_rank": 1500, "suspicious_subdomains": False}


class CrtShConnector(BaseConnector):
    name = "crt_sh"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        domain = payload.get("domain")
        if domain == "bad":
            return {"cert_count": 1, "self_signed": True, "issuer": "Unknown CA"}
        return {"cert_count": 15, "self_signed": False, "issuer": "Let's Encrypt"}


class WhoisConnector(BaseConnector):
    name = "whois"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        domain = payload.get("domain")
        if domain == "bad":
            return {"registrar": "ShadyRegistrar LLC", "creation_date": "2026-06-15", "age_days": 2}
        return {"registrar": "GoDaddy Online", "creation_date": "2010-05-12", "age_days": 5880}


class GoogleFactCheckConnector(BaseConnector):
    name = "google_fact_check"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        query = payload.get("query")
        if query == "deepfake_news":
            return {"fact_checks": [{"claim": "Video of prime minister is real", "verdict": "False/Manipulated"}]}
        return {"fact_checks": []}


class ReutersFactCheckConnector(BaseConnector):
    name = "reuters_fact_check"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        query = payload.get("query")
        if query == "deepfake_news":
            return {"fact_checks": [{"claim": "Video of politician cloned voice", "verdict": "Spurious/Synthetic"}]}
        return {"fact_checks": []}


class C2PAConnector(BaseConnector):
    name = "c2pa_verifier"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        path = payload.get("path")
        if path == "bad":
            return {"c2pa_present": True, "signature_valid": False, "reason": "Manifest hash mismatch"}
        return {"c2pa_present": True, "signature_valid": True, "reason": "Trusted creator signature matches"}


class AdobeCredentialsConnector(BaseConnector):
    name = "adobe_credentials"
    version = "1.0.0"

    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        path = payload.get("path")
        if path == "bad":
            return {"adobe_credentials_found": True, "valid": False}
        return {"adobe_credentials_found": True, "valid": True}


# ---------------------------------------------------------
# Correlation Engine for combining evidence
# ---------------------------------------------------------

class OSINTCorrelationEngine(BaseCorrelationEngine):
    name = "osint-correlation"

    def correlate(self, records: Any) -> Dict[str, Any]:
        score_penalty = 0
        verdicts = []
        conflicts = False

        for r in records:
            if r.status != "ok":
                continue
            
            data = r.data
            src = r.source

            if src == "virustotal" and data.get("verdict") == "malicious":
                score_penalty += 40
                verdicts.append("VirusTotal flags indicator as malicious")
            elif src == "abuseipdb" and data.get("verdict") == "suspicious":
                score_penalty += 35
                verdicts.append("AbuseIPDB lists IP as highly abused")
            elif src == "alienvault_otx" and data.get("threat_score", 0) > 50:
                score_penalty += 20
                verdicts.append("AlienVault OTX active pulses match threat")
            elif src == "shodan" and data.get("is_compromised"):
                score_penalty += 25
                verdicts.append("Shodan lists IP as actively compromised/vulnerable")
            elif src == "whois" and data.get("age_days", 9999) < 30:
                score_penalty += 15
                verdicts.append("WHOIS shows domain was registered very recently")
            elif src == "c2pa_verifier" and not data.get("signature_valid"):
                score_penalty += 50
                verdicts.append("C2PA manifest signature is corrupted or forged")
            elif src == "adobe_credentials" and not data.get("valid"):
                score_penalty += 45
                verdicts.append("Adobe Content Credentials validation failed")

        # Check for conflicting evidence (e.g. C2PA claims signature is valid, but VirusTotal claims host is bad, etc.)
        c2pa_valid = any(r.source == "c2pa_verifier" and r.data.get("signature_valid") for r in records if r.status == "ok")
        has_bad_signal = any(
            (r.source == "virustotal" and r.data.get("verdict") == "malicious") or
            (r.source == "abuseipdb" and r.data.get("verdict") == "suspicious")
            for r in records if r.status == "ok"
        )
        if c2pa_valid and has_bad_signal:
            conflicts = True

        trust_score = max(0, 100 - score_penalty)
        return {
            "trust_score": trust_score,
            "verdicts": verdicts,
            "conflicting_evidence": conflicts,
            "explainable_summary": (
                "Conflicting credentials: valid C2PA container but associated with malicious reputations."
                if conflicts else f"Correlated score: {trust_score}. Issues: {len(verdicts)}."
            )
        }


# ---------------------------------------------------------
# Test Cases
# ---------------------------------------------------------

@pytest.mark.realtime
def test_all_connectors_valid_responses() -> None:
    clock = lambda: datetime.now(timezone.utc)
    registry = IntegrationRegistry()
    
    registry.register_connector(VirusTotalConnector(clock=clock))
    registry.register_connector(AbuseIPDBConnector(clock=clock))
    registry.register_connector(AlienVaultOTXConnector(clock=clock))
    registry.register_connector(ShodanConnector(clock=clock))
    registry.register_connector(CensysConnector(clock=clock))
    registry.register_connector(SecurityTrailsConnector(clock=clock))
    registry.register_connector(CrtShConnector(clock=clock))
    registry.register_connector(WhoisConnector(clock=clock))
    registry.register_connector(GoogleFactCheckConnector(clock=clock))
    registry.register_connector(ReutersFactCheckConnector(clock=clock))
    registry.register_connector(C2PAConnector(clock=clock))
    registry.register_connector(AdobeCredentialsConnector(clock=clock))

    engine = IntegrationEngine(registry=registry, audit_log=[])
    ctx = IntegrationContext(source="realtime-suite", request_id="req-valid")

    # Verify a subset of connectors for clean outputs
    res_vt = engine.run(connector_name="virustotal", payload={"indicator": "clean.com"}, context=ctx)
    assert res_vt.status == "ok"
    assert res_vt.data["verdict"] == "clean"

    res_abuse = engine.run(connector_name="abuseipdb", payload={"ip": "1.1.1.1"}, context=ctx)
    assert res_abuse.status == "ok"
    assert res_abuse.data["abuse_confidence_score"] == 0

    res_whois = engine.run(connector_name="whois", payload={"domain": "trusted.org"}, context=ctx)
    assert res_whois.status == "ok"
    assert res_whois.data["age_days"] == 5880

    res_c2pa = engine.run(connector_name="c2pa_verifier", payload={"path": "clean_report.pdf"}, context=ctx)
    assert res_c2pa.status == "ok"
    assert res_c2pa.data["signature_valid"] is True


@pytest.mark.realtime
def test_connectors_timeouts_and_retries() -> None:
    # Set retry_attempts=2, retry_backoff_seconds=0
    connector = VirusTotalConnector(clock=lambda: datetime.now(timezone.utc), retry_attempts=2, retry_backoff_seconds=0)
    ctx = IntegrationContext(source="virustotal", request_id="req-retry")

    # Triggering timeout should throw IntegrationTransientError after retries exhausted
    with pytest.raises(IntegrationTransientError):
        connector.run({"indicator": "timeout"}, ctx)


@pytest.mark.realtime
def test_connectors_rate_limiting_circuit_breaker() -> None:
    clock_values = [datetime(2026, 6, 17, 22, 0, 0, tzinfo=timezone.utc)]
    def mock_clock() -> datetime:
        return clock_values[0]

    # Circuit breaker threshold = 2, reset = 60s
    connector = AbuseIPDBConnector(
        clock=mock_clock,
        retry_attempts=0,
        retry_backoff_seconds=0,
        circuit_breaker_threshold=2,
        circuit_breaker_reset_seconds=60,
    )
    ctx = IntegrationContext(source="abuseipdb", request_id="req-cb")

    # Failure 1
    with pytest.raises(IntegrationTransientError):
        connector.run({"ip": "rate_limit"}, ctx)

    # Failure 2 (Should open the circuit breaker)
    with pytest.raises(IntegrationTransientError):
        connector.run({"ip": "rate_limit"}, ctx)

    # Call 3 (Should fail fast with Circuit Open IntegrationError)
    with pytest.raises(IntegrationError) as exc:
        connector.run({"ip": "clean"}, ctx)
    assert "circuit open" in str(exc.value).lower()

    # Advance clock by 61 seconds
    clock_values[0] += timedelta(seconds=61)

    # Call 4 should attempt execution again (circuit closed)
    res = connector.run({"ip": "127.0.0.1"}, ctx)
    assert res.status == "ok"
    assert res.data["abuse_confidence_score"] == 0


@pytest.mark.realtime
def test_conflicting_evidence_correlation() -> None:
    records = [
        IntegrationResult(source="c2pa_verifier", version="1", status="ok", data={"signature_valid": True}, latency_ms=10),
        IntegrationResult(source="virustotal", version="1", status="ok", data={"verdict": "malicious"}, latency_ms=10),
        IntegrationResult(source="whois", version="1", status="ok", data={"age_days": 2}, latency_ms=10),
    ]

    correlator = OSINTCorrelationEngine()
    verdict = correlator.correlate(records)

    assert verdict["conflicting_evidence"] is True
    assert verdict["trust_score"] < 50
    assert "Conflicting credentials" in verdict["explainable_summary"]
    assert any("VirusTotal flags" in v for v in verdict["verdicts"])
    assert any("WHOIS shows" in v for v in verdict["verdicts"])
