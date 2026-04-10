from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from scanner.core.backpressure import AsyncEventIngress, QueueStrategy
from scanner.core.events.schema import Event, Severity, build_event, validate_event_type
from scanner.core.metrics import MetricsRegistry
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
HYPOTHESIS_GENERATED = "hypothesis_generated"
INVESTIGATION_RECOMMENDED = "investigation_recommended"
REPORT_GENERATED = "report_generated"
INCIDENT_DETECTED = "incident_detected"

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
    """
    Event bus SOC v2: todos os eventos são `Event` validados.
    Fila opcional (max_queue_size>0) com backpressure; max_queue_size=0 = despacho síncrono (testes).
    """

    __slots__ = (
        "_handlers",
        "_timeline",
        "_record_timeline",
        "_lock",
        "_max_queue_size",
        "_strategy",
        "_ingress",
        "_consumer_task",
        "_metrics",
        "_drop_callback",
    )

    def __init__(
        self,
        *,
        record_timeline: bool = True,
        max_queue_size: int = 0,
        queue_strategy: str = "block",
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        # Registo append-only e imutável em termos de produtor: apenas novas entradas; sem reescrita in-place.
        self._timeline: list[dict[str, Any]] = []
        self._record_timeline = record_timeline
        self._lock = asyncio.Lock()
        self._max_queue_size = max_queue_size
        strat = QueueStrategy.BLOCK if queue_strategy == "block" else QueueStrategy.DROP_NEW
        self._strategy = strat
        self._ingress: AsyncEventIngress | None = None
        self._consumer_task: asyncio.Task[None] | None = None
        self._metrics = metrics
        self._drop_callback = lambda: self._metrics.inc("events_dropped", 1) if self._metrics else None
        if max_queue_size > 0:
            self._ingress = AsyncEventIngress(
                max_queue_size,
                strat,
                on_drop=self._drop_callback,
            )

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        validate_event_type(event_name)
        self._handlers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        if handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)

    async def start(self) -> None:
        """Inicia consumidor assíncrono da fila (necessário se max_queue_size>0)."""
        if self._max_queue_size <= 0 or self._ingress is None:
            return
        if self._consumer_task is not None:
            return

        async def _consume() -> None:
            assert self._ingress is not None
            q = self._ingress.queue
            while True:
                ev = await q.get()
                t0 = time.perf_counter()
                try:
                    await self._dispatch_event(ev)
                finally:
                    self._ingress.observe_dispatch_latency(t0)
                    q.task_done()
                    if self._metrics:
                        self._metrics.inc("events_emitted", 1)
                        depth = q.qsize()
                        self._metrics.max_queue_depth(depth)

        self._consumer_task = asyncio.create_task(_consume(), name="eventbus-consumer")

    async def emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        source: str = "core",
        target: str | None = None,
        correlation_id: str | None = None,
        severity: Severity | str | None = None,
    ) -> None:
        """Emite evento validado (schema SOC v2)."""
        validate_event_type(event_type)
        sev: Severity | None
        if severity is None:
            sev = None
        elif isinstance(severity, Severity):
            sev = severity
        else:
            sev = Severity(str(severity))
        ev = build_event(
            event_type,
            payload,
            source=source,
            target=target,
            correlation_id=correlation_id,
            severity=sev,
        )
        if self._max_queue_size <= 0 or self._ingress is None:
            await self._dispatch_event(ev)
            if self._metrics:
                self._metrics.inc("events_emitted", 1)
            return
        ok = await self._ingress.put(ev)
        if not ok and self._metrics:
            self._metrics.inc("events_dropped", 1)

    async def _dispatch_event(self, ev: Event) -> None:
        handler_dict = ev.to_handler_dict()
        async with self._lock:
            if self._record_timeline:
                self._timeline.append(handler_dict)
        for handler in list(self._handlers.get(ev.event_type, [])):
            await handler(handler_dict)

    @property
    def timeline(self) -> list[dict[str, Any]]:
        return list(self._timeline)

    def clear_timeline(self) -> None:
        self._timeline.clear()
