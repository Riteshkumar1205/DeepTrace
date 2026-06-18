"""Plugin-driven integration engine foundation."""

from .core import (
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

