"""Controlo de fluxo e backpressure no bus de eventos (Raspberry Pi / memória limitada)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class QueueStrategy(str, Enum):
    BLOCK = "block"
    DROP_NEW = "drop_new"


@dataclass(slots=True)
class BackpressureStats:
    dropped_events: int = 0
    queue_depth: int = 0
    processing_latency_ms_sum: float = 0.0
    processing_latency_samples: int = 0


class AsyncEventIngress:
    """
    Fila limitada: produtores fazem await put; consumidor processa com dispatch.
    Estratégia block: backpressure natural quando a fila enche.
    drop_new: descarta eventos novos se cheio (proteção extrema de memória).
    """

    def __init__(
        self,
        maxsize: int,
        strategy: QueueStrategy,
        on_drop: Callable[[], None] | None = None,
    ) -> None:
        self._maxsize = max(1, maxsize)
        self._strategy = strategy
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=self._maxsize)
        self._on_drop = on_drop
        self.stats = BackpressureStats()

    @property
    def queue(self) -> asyncio.Queue[Any]:
        return self._queue

    async def put(self, item: Any) -> bool:
        """Devolve False se o evento foi descartado (drop_new)."""
        self.stats.queue_depth = self._queue.qsize()
        if self._strategy == QueueStrategy.BLOCK:
            await self._queue.put(item)
            return True
        try:
            self._queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            self.stats.dropped_events += 1
            if self._on_drop:
                self._on_drop()
            return False

    def observe_dispatch_latency(self, started: float) -> None:
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.stats.processing_latency_ms_sum += elapsed_ms
        self.stats.processing_latency_samples += 1
