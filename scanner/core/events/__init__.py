"""Event schema (SOC v2) — tipos e validação unificados."""

from scanner.core.events.schema import (
    Event,
    EventType,
    Severity,
    build_event,
    default_severity_for_type,
    validate_event_type,
)

__all__ = [
    "Event",
    "EventType",
    "Severity",
    "build_event",
    "default_severity_for_type",
    "validate_event_type",
]
