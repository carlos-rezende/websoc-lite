from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from scanner.core.models import utc_now_iso

# Mandatory event names — all modules communicate through these identifiers.
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
REPORT_GENERATED = "report_generated"

# Backward-compatible aliases.
ON_TARGET_LOADED = TARGET_LOADED
ON_URL_DISCOVERED = ENDPOINT_DISCOVERED
ON_REQUEST_SENT = REQUEST_SENT
ON_RESPONSE_RECEIVED = RESPONSE_RECEIVED
ON_BASELINE_STORED = BASELINE_STORED
ON_DIFF_COMPUTED = DIFF_COMPUTED
ON_ANOMALY_DETECTED = ANOMALY_DETECTED
ON_FINDING_CREATED = RISK_SCORED

EventHandler = Callable[[dict[str, Any]], Awaitable[None]]


class EventBus:
    """Async internal event bus. No global singleton — instantiated per framework runtime."""

    __slots__ = ("_handlers", "_timeline", "_record_timeline", "_lock")

    def __init__(self, *, record_timeline: bool = True) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._timeline: list[dict[str, Any]] = []
        self._record_timeline = record_timeline
        self._lock = asyncio.Lock()

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        self._handlers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        if handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)

    async def emit(self, event_name: str, payload: dict[str, Any]) -> None:
        """Emit event: first record timeline (metadata-only contract), then notify subscribers."""
        entry: dict[str, Any] = {"event": event_name, "ts": utc_now_iso()}
        entry.update(payload)
        async with self._lock:
            if self._record_timeline:
                self._timeline.append(entry)
        merged = {"event": event_name, **payload}
        for handler in list(self._handlers.get(event_name, [])):
            await handler(dict(merged))

    @property
    def timeline(self) -> list[dict[str, Any]]:
        return list(self._timeline)

    def clear_timeline(self) -> None:
        self._timeline.clear()
