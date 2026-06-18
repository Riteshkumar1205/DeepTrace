from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.integration_engine.core import (
    BaseConnector,
    BaseCorrelationEngine,
    BaseEnricher,
    BaseExporter,
    BaseValidator,
    IntegrationAuditRecord,
    IntegrationContext,
    IntegrationEngine,
    IntegrationError,
    IntegrationRegistry,
    IntegrationResult,
    IntegrationSchemaError,
    IntegrationTransientError,
)


def _utc_clock_factory():
    current = {"value": datetime(2026, 6, 11, tzinfo=timezone.utc)}

    def clock() -> datetime:
        return current["value"]

    def advance(seconds: int) -> None:
        current["value"] += timedelta(seconds=seconds)

    return clock, advance


class FlakyConnector(BaseConnector):
    name = "flaky"
    version = "1.0.0"

    def __init__(self, *, fail_times: int, clock):
        super().__init__(clock=clock, retry_attempts=2, retry_backoff_seconds=0)
        self.fail_times = fail_times
        self.calls = 0

    def execute(self, payload, context: IntegrationContext):
        self.calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise IntegrationTransientError("temporary upstream failure")
        return {"ok": True, "payload": payload, "source": context.source}


class AlwaysFailConnector(BaseConnector):
    name = "always_fail"
    version = "1.0.0"

    def __init__(self, *, clock):
        super().__init__(
            clock=clock,
            retry_attempts=0,
            retry_backoff_seconds=0,
            circuit_breaker_threshold=1,
            circuit_breaker_reset_seconds=60,
        )

    def execute(self, payload, context: IntegrationContext):
        raise IntegrationTransientError("permanent upstream failure")


class PayloadValidator(BaseValidator):
    name = "payload-validator"

    def validate(self, payload):
        if not isinstance(payload, dict):
            raise IntegrationSchemaError("payload must be a mapping")
        if "evidence_id" not in payload:
            raise IntegrationSchemaError("missing evidence_id")
        return True


class PayloadEnricher(BaseEnricher):
    name = "payload-enricher"

    def enrich(self, payload, context: IntegrationContext):
        enriched = dict(payload)
        enriched["request_id"] = context.request_id
        enriched["source"] = context.source
        return enriched


class ScoreCorrelationEngine(BaseCorrelationEngine):
    name = "score-correlation"

    def correlate(self, records):
        score = 100
        reasons = []
        for record in records:
            score -= int(record.data.get("penalty", 0))
            reasons.extend(record.data.get("reasons", []))

        score = max(0, min(100, score))
        if score >= 85:
            verdict = "HIGH TRUST"
        elif score >= 50:
            verdict = "MODERATE TRUST"
        else:
            verdict = "LOW TRUST"

        return {
            "trust_score": score,
            "verdict": verdict,
            "supporting_evidence": reasons,
        }


class JsonExporter(BaseExporter):
    name = "json"

    def export(self, payload):
        return payload


class CsvExporter(BaseExporter):
    name = "csv"

    def export(self, payload):
        headers = ",".join(payload.keys())
        values = ",".join(str(value) for value in payload.values())
        return f"{headers}\n{values}"


@dataclass(frozen=True)
class SimpleAuditTarget:
    operation: str
    result: str


def test_registry_registers_and_resolves_plugins():
    registry = IntegrationRegistry()
    connector = FlakyConnector(fail_times=0, clock=lambda: datetime.now(timezone.utc))
    validator = PayloadValidator()
    enricher = PayloadEnricher()
    engine = ScoreCorrelationEngine()
    exporter = JsonExporter()

    registry.register_connector(connector)
    registry.register_validator(validator)
    registry.register_enricher(enricher)
    registry.register_correlation_engine(engine)
    registry.register_exporter(exporter)

    assert registry.get_connector("flaky") is connector
    assert registry.get_validator("payload-validator") is validator
    assert registry.get_enricher("payload-enricher") is enricher
    assert registry.get_correlation_engine("score-correlation") is engine
    assert registry.get_exporter("json") is exporter

    plugin_names = registry.list_plugin_names()
    assert "flaky" in plugin_names["connectors"]
    assert "payload-validator" in plugin_names["validators"]
    assert "payload-enricher" in plugin_names["enrichers"]
    assert "score-correlation" in plugin_names["correlation_engines"]
    assert "json" in plugin_names["exporters"]


def test_registry_rejects_duplicate_connector_registration():
    registry = IntegrationRegistry()
    clock = lambda: datetime.now(timezone.utc)
    registry.register_connector(FlakyConnector(fail_times=0, clock=clock))

    with pytest.raises(IntegrationError):
        registry.register_connector(FlakyConnector(fail_times=0, clock=clock))


def test_connector_retries_transient_failures_and_recovers():
    clock, _ = _utc_clock_factory()
    connector = FlakyConnector(fail_times=1, clock=clock)
    result = connector.run({"evidence_id": "EV-1"}, IntegrationContext(source="virustotal", request_id="req-1"))

    assert connector.calls == 2
    assert result.status == "ok"
    assert result.data["ok"] is True
    assert result.data["source"] == "virustotal"


def test_connector_opens_circuit_after_repeated_failures():
    clock, advance = _utc_clock_factory()
    connector = AlwaysFailConnector(clock=clock)

    with pytest.raises(IntegrationTransientError):
        connector.run({"evidence_id": "EV-1"}, IntegrationContext(source="otx", request_id="req-2"))

    with pytest.raises(IntegrationError) as exc:
        connector.run({"evidence_id": "EV-1"}, IntegrationContext(source="otx", request_id="req-2"))

    assert "circuit" in str(exc.value).lower()

    advance(61)
    with pytest.raises(IntegrationTransientError):
        connector.run({"evidence_id": "EV-1"}, IntegrationContext(source="otx", request_id="req-2"))


def test_validator_rejects_missing_required_fields():
    validator = PayloadValidator()

    with pytest.raises(IntegrationSchemaError):
        validator.validate({"source": "otx"})


def test_enricher_adds_context_fields():
    enricher = PayloadEnricher()
    context = IntegrationContext(source="misp", request_id="req-3")
    enriched = enricher.enrich({"evidence_id": "EV-7"}, context)

    assert enriched["evidence_id"] == "EV-7"
    assert enriched["request_id"] == "req-3"
    assert enriched["source"] == "misp"


def test_correlation_engine_computes_explainable_verdict():
    engine = ScoreCorrelationEngine()
    result = engine.correlate(
        [
            IntegrationResult(source="vt", version="1", status="ok", data={"penalty": 10, "reasons": ["hash matched"]}, latency_ms=5),
            IntegrationResult(source="c2pa", version="1", status="ok", data={"penalty": 5, "reasons": ["manifest valid"]}, latency_ms=7),
        ]
    )

    assert result["trust_score"] == 85
    assert result["verdict"] == "HIGH TRUST"
    assert result["supporting_evidence"] == ["hash matched", "manifest valid"]


def test_exporters_format_payloads():
    json_exporter = JsonExporter()
    csv_exporter = CsvExporter()
    payload = {"evidence_id": "EV-9", "verdict": "LOW TRUST"}

    assert json_exporter.export(payload) == payload
    assert csv_exporter.export(payload) == "evidence_id,verdict\nEV-9,LOW TRUST"


def test_integration_engine_validates_and_audits_run():
    clock, _ = _utc_clock_factory()
    registry = IntegrationRegistry()
    connector = FlakyConnector(fail_times=0, clock=clock)
    validator = PayloadValidator()
    enricher = PayloadEnricher()

    registry.register_connector(connector)
    registry.register_validator(validator)
    registry.register_enricher(enricher)

    engine = IntegrationEngine(registry=registry, audit_log=[])
    result = engine.run(
        connector_name="flaky",
        payload={"evidence_id": "EV-42"},
        context=IntegrationContext(source="misp", request_id="req-42"),
        validator_name="payload-validator",
        enricher_name="payload-enricher",
    )

    assert result.status == "ok"
    assert result.data["request_id"] == "req-42"
    assert result.data["source"] == "misp"
    assert len(engine.audit_log) == 1
    audit_record = engine.audit_log[0]
    assert isinstance(audit_record, IntegrationAuditRecord)
    assert audit_record.connector_name == "flaky"
