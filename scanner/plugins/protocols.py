from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EventEmitter(Protocol):
    """Plugins depend only on this contract — not on EventBus internals."""

    async def emit(self, event_name: str, payload: dict[str, Any]) -> None: ...


@runtime_checkable
class HTTPClientPort(Protocol):
    """Minimal HTTP surface for crawlers (duck-typed RequestEngine)."""

    async def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any: ...
