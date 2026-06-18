from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from time import sleep
from typing import Any, Callable, Dict, Iterable, List, MutableMapping, Optional


Clock = Callable[[], datetime]


class IntegrationError(Exception):
    """Base error for integration engine failures."""


class IntegrationSchemaError(IntegrationError):
    """Raised when integration payload validation fails."""


class IntegrationTransientError(IntegrationError):
    """Raised for retryable upstream failures."""


@dataclass(frozen=True)
class IntegrationContext:
    """Execution context shared by all integrations."""

    source: str
    request_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationResult:
    """Normalized result returned by connectors."""

    source: str
    version: str
    status: str
    data: Dict[str, Any]
    latency_ms: int
    errors: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class IntegrationAuditRecord:
    """Immutable audit event emitted for every integration execution."""

    timestamp: datetime
    connector_name: str
    version: str
    source: str
    request_id: str
    status: str
    latency_ms: int
    validation_passed: bool


class BaseValidator(ABC):
    """Validate payload shape and semantics before execution."""

    name: str = "validator"

    @abstractmethod
    def validate(self, payload: Any) -> bool:
        raise NotImplementedError


class BaseEnricher(ABC):
    """Enrich payloads with derived or contextual data."""

    name: str = "enricher"

    @abstractmethod
    def enrich(self, payload: Any, context: IntegrationContext) -> Any:
        raise NotImplementedError


class BaseCorrelationEngine(ABC):
    """Aggregate results into explainable verdicts."""

    name: str = "correlation-engine"

    @abstractmethod
    def correlate(self, records: Iterable[IntegrationResult]) -> Dict[str, Any]:
        raise NotImplementedError


class BaseExporter(ABC):
    """Format integration outputs for downstream systems."""

    name: str = "exporter"

    @abstractmethod
    def export(self, payload: Any) -> Any:
        raise NotImplementedError


class BaseConnector(ABC):
    """Base class for all external integrations."""

    name: str = "connector"
    version: str = "0.0.0"

    def __init__(
        self,
        *,
        clock: Optional[Clock] = None,
        retry_attempts: int = 2,
        retry_backoff_seconds: int = 1,
        circuit_breaker_threshold: int = 3,
        circuit_breaker_reset_seconds: int = 60,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.retry_attempts = max(0, retry_attempts)
        self.retry_backoff_seconds = max(0, retry_backoff_seconds)
        self.circuit_breaker_threshold = max(1, circuit_breaker_threshold)
        self.circuit_breaker_reset_seconds = max(1, circuit_breaker_reset_seconds)
        self._failure_count = 0
        self._circuit_open_until: Optional[datetime] = None

    @abstractmethod
    def execute(self, payload: Any, context: IntegrationContext) -> Dict[str, Any]:
        raise NotImplementedError

    def health_check(self) -> bool:
        return True

    def run(self, payload: Any, context: IntegrationContext) -> IntegrationResult:
        self._ensure_circuit_closed()
        started_at = self.clock()

        attempt = 0
        while True:
            try:
                data = self.execute(payload, context)
            except IntegrationTransientError:
                if attempt < self.retry_attempts:
                    attempt += 1
                    if self.retry_backoff_seconds > 0:
                        sleep(self.retry_backoff_seconds)
                    continue
                self._register_failure()
                raise
            except IntegrationError:
                self._register_failure()
                raise
            except Exception as exc:  # pragma: no cover - safety net
                self._register_failure()
                raise IntegrationError(str(exc)) from exc

            self._register_success()
            latency_ms = self._latency_ms(started_at, self.clock())
            return IntegrationResult(
                source=context.source,
                version=self.version,
                status="ok",
                data=data,
                latency_ms=latency_ms,
            )

    def _ensure_circuit_closed(self) -> None:
        if self._circuit_open_until is None:
            return
        if self.clock() < self._circuit_open_until:
            raise IntegrationError(f"Circuit open for connector '{self.name}'")
        self._circuit_open_until = None
        self._failure_count = 0

    def _register_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.circuit_breaker_threshold:
            self._circuit_open_until = self.clock() + timedelta(seconds=self.circuit_breaker_reset_seconds)

    def _register_success(self) -> None:
        self._failure_count = 0
        self._circuit_open_until = None

    @staticmethod
    def _latency_ms(started_at: datetime, finished_at: datetime) -> int:
        delta = finished_at - started_at
        return max(0, int(delta.total_seconds() * 1000))


class IntegrationRegistry:
    """Plugin registry for connectors, validators, enrichers, engines, and exporters."""

    def __init__(self) -> None:
        self._connectors: Dict[str, BaseConnector] = {}
        self._validators: Dict[str, BaseValidator] = {}
        self._enrichers: Dict[str, BaseEnricher] = {}
        self._correlation_engines: Dict[str, BaseCorrelationEngine] = {}
        self._exporters: Dict[str, BaseExporter] = {}

    def register_connector(self, connector: BaseConnector) -> None:
        self._register(self._connectors, connector.name, connector, "connector")

    def register_validator(self, validator: BaseValidator) -> None:
        self._register(self._validators, validator.name, validator, "validator")

    def register_enricher(self, enricher: BaseEnricher) -> None:
        self._register(self._enrichers, enricher.name, enricher, "enricher")

    def register_correlation_engine(self, engine: BaseCorrelationEngine) -> None:
        self._register(self._correlation_engines, engine.name, engine, "correlation engine")

    def register_exporter(self, exporter: BaseExporter) -> None:
        self._register(self._exporters, exporter.name, exporter, "exporter")

    def get_connector(self, name: str) -> BaseConnector:
        return self._get(self._connectors, name, "connector")

    def get_validator(self, name: str) -> BaseValidator:
        return self._get(self._validators, name, "validator")

    def get_enricher(self, name: str) -> BaseEnricher:
        return self._get(self._enrichers, name, "enricher")

    def get_correlation_engine(self, name: str) -> BaseCorrelationEngine:
        return self._get(self._correlation_engines, name, "correlation engine")

    def get_exporter(self, name: str) -> BaseExporter:
        return self._get(self._exporters, name, "exporter")

    def list_plugin_names(self) -> Dict[str, List[str]]:
        return {
            "connectors": sorted(self._connectors),
            "validators": sorted(self._validators),
            "enrichers": sorted(self._enrichers),
            "correlation_engines": sorted(self._correlation_engines),
            "exporters": sorted(self._exporters),
        }

    @staticmethod
    def _register(store: MutableMapping[str, Any], name: str, plugin: Any, label: str) -> None:
        if name in store:
            raise IntegrationError(f"Duplicate {label} registration: {name}")
        store[name] = plugin

    @staticmethod
    def _get(store: MutableMapping[str, Any], name: str, label: str) -> Any:
        try:
            return store[name]
        except KeyError as exc:
            raise IntegrationError(f"Unknown {label}: {name}") from exc


class IntegrationEngine:
    """Coordinate validation, enrichment, execution, and auditing."""

    def __init__(self, *, registry: IntegrationRegistry, audit_log: Optional[List[IntegrationAuditRecord]] = None, clock: Optional[Clock] = None) -> None:
        self.registry = registry
        self.audit_log = audit_log if audit_log is not None else []
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(
        self,
        *,
        connector_name: str,
        payload: Any,
        context: IntegrationContext,
        validator_name: Optional[str] = None,
        enricher_name: Optional[str] = None,
    ) -> IntegrationResult:
        validation_passed = False

        if validator_name:
            validator = self.registry.get_validator(validator_name)
            validation_result = validator.validate(payload)
            if validation_result is False:
                raise IntegrationSchemaError(f"Validation failed for {validator_name}")
            validation_passed = True

        if enricher_name:
            enricher = self.registry.get_enricher(enricher_name)
            payload = enricher.enrich(payload, context)

        connector = self.registry.get_connector(connector_name)
        started_at = self.clock()
        result = connector.run(payload, context)
        finished_at = self.clock()

        if isinstance(payload, dict) and isinstance(result.data, dict):
            result.data = {**result.data, **payload}

        self.audit_log.append(
            IntegrationAuditRecord(
                timestamp=finished_at,
                connector_name=connector.name,
                version=connector.version,
                source=context.source,
                request_id=context.request_id,
                status=result.status,
                latency_ms=max(0, int((finished_at - started_at).total_seconds() * 1000)),
                validation_passed=validation_passed,
            )
        )
        return result
