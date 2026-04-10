"""Modelo unificado de eventos SOC v2 — todos os eventos do sistema devem passar por aqui."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from scanner.core.models import utc_now_iso


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EventType(str, Enum):
    TARGET_LOADED = "target_loaded"
    CRAWL_STARTED = "crawl_started"
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    REQUEST_SENT = "request_sent"
    RESPONSE_RECEIVED = "response_received"
    BASELINE_STORED = "baseline_stored"
    MUTATION_APPLIED = "mutation_applied"
    DIFF_COMPUTED = "diff_computed"
    ANOMALY_DETECTED = "anomaly_detected"
    RISK_SCORED = "risk_scored"
    HYPOTHESIS_GENERATED = "hypothesis_generated"
    INVESTIGATION_RECOMMENDED = "investigation_recommended"
    REPORT_GENERATED = "report_generated"
    INCIDENT_DETECTED = "incident_detected"


KNOWN_EVENT_TYPES: frozenset[str] = frozenset(e.value for e in EventType)


def validate_event_type(event_type: str) -> None:
    if event_type not in KNOWN_EVENT_TYPES:
        raise ValueError(f"event_type desconhecido: {event_type!r}")


def default_severity_for_type(event_type: str) -> Severity:
    if event_type == EventType.INCIDENT_DETECTED.value:
        return Severity.HIGH
    if event_type == EventType.ANOMALY_DETECTED.value:
        return Severity.MEDIUM
    if event_type == EventType.HYPOTHESIS_GENERATED.value:
        return Severity.LOW
    if event_type in (EventType.RISK_SCORED.value, EventType.DIFF_COMPUTED.value):
        return Severity.LOW
    return Severity.INFO


@dataclass(slots=True)
class Event:
    """Contrato SOC v2 — nenhum dict solto no bus sem conversão para Event."""

    event_id: str
    event_type: str
    timestamp: str
    source: str
    target: str
    correlation_id: str | None
    payload: dict[str, Any]
    severity: Severity

    def __post_init__(self) -> None:
        validate_event_type(self.event_type)
        if not isinstance(self.payload, dict):
            raise TypeError("payload deve ser dict")

    def to_handler_dict(self) -> dict[str, Any]:
        """Dict entregue aos handlers: metadados + payload achatado (compat legado)."""
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event": self.event_type,
            "ts": self.timestamp,
            "timestamp": self.timestamp,
            "source": self.source,
            "target": self.target,
            "correlation_id": self.correlation_id,
            "severity": self.severity.value,
        }
        out.update(self.payload)
        return out

    def to_ndjson_record(self) -> dict[str, Any]:
        """Registo para ficheiros (timeline / NDJSON) com schema completo."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "ts": self.timestamp,
            "timestamp": self.timestamp,
            "source": self.source,
            "target": self.target,
            "correlation_id": self.correlation_id,
            "severity": self.severity.value,
            "payload": self.payload,
        }


def build_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    source: str = "core",
    target: str | None = None,
    correlation_id: str | None = None,
    severity: Severity | None = None,
    event_id: str | None = None,
) -> Event:
    validate_event_type(event_type)
    tid = target if target is not None else str(payload.get("target") or payload.get("endpoint") or "")
    sev = severity if severity is not None else default_severity_for_type(event_type)
    return Event(
        event_id=event_id or str(uuid.uuid4()),
        event_type=event_type,
        timestamp=utc_now_iso(),
        source=source,
        target=tid,
        correlation_id=correlation_id,
        payload=dict(payload),
        severity=sev,
    )
