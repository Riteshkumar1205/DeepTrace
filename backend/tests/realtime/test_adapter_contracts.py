from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.integration_engine.core import (
    BaseConnector,
    BaseValidator,
    IntegrationContext,
    IntegrationEngine,
    IntegrationError,
    IntegrationRegistry,
    IntegrationSchemaError,
    IntegrationTransientError,
)


class ReputationValidator(BaseValidator):
    name = "reputation-validator"

    def validate(self, payload):
        if not isinstance(payload, dict):
            raise IntegrationSchemaError("payload must be a mapping")
        if "indicator" not in payload:
            raise IntegrationSchemaError("missing indicator")
        return True


class ReputationConnector(BaseConnector):
    name = "virustotal"
    version = "1.0.0"

    def __init__(self, *, clock):
        super().__init__(clock=clock, retry_attempts=1, retry_backoff_seconds=0)
        self.calls = 0

    def execute(self, payload, context: IntegrationContext):
        self.calls += 1
        if payload.get("indicator") == "timeout":
            raise IntegrationTransientError("upstream timeout")
        return {
            "source": context.source,
            "indicator": payload["indicator"],
            "reputation": "malicious" if payload["indicator"] == "bad" else "clean",
        }


@pytest.mark.realtime
def test_realtime_adapter_contract_accepts_valid_indicator_payload() -> None:
    clock = lambda: datetime.now(timezone.utc)
    registry = IntegrationRegistry()
    registry.register_validator(ReputationValidator())
    registry.register_connector(ReputationConnector(clock=clock))
    engine = IntegrationEngine(registry=registry, audit_log=[])

    result = engine.run(
        connector_name="virustotal",
        payload={"indicator": "bad"},
        context=IntegrationContext(source="virustotal", request_id="req-1"),
        validator_name="reputation-validator",
    )

    assert result.status == "ok"
    assert result.data["reputation"] == "malicious"
    assert result.data["source"] == "virustotal"


@pytest.mark.realtime
def test_realtime_adapter_contract_retries_and_surfaces_transient_errors() -> None:
    clock = lambda: datetime.now(timezone.utc)
    registry = IntegrationRegistry()
    registry.register_validator(ReputationValidator())
    registry.register_connector(ReputationConnector(clock=clock))
    engine = IntegrationEngine(registry=registry, audit_log=[])

    with pytest.raises(IntegrationTransientError):
        engine.run(
            connector_name="virustotal",
            payload={"indicator": "timeout"},
            context=IntegrationContext(source="virustotal", request_id="req-2"),
            validator_name="reputation-validator",
        )

    assert engine.audit_log == []
