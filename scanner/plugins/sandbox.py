"""
Sandbox de execução de plugins SOC v2 — sem imports diretos de stores internos;
apenas interfaces públicas e event bus.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from scanner.plugins.protocols import EventEmitter

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(slots=True)
class PluginExecutionContext:
    """Contexto limitado passado a plugins (permissões explícitas)."""

    plugin_id: str
    bus: "EventEmitter"
    timeout_seconds: float = 45.0
    allow_raw_core_imports: bool = False


async def run_with_timeout(coro: Any, *, timeout_seconds: float, plugin_id: str) -> Any:
    """Isola falhas: exceções do plugin não rebentam o pipeline."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except TimeoutError:
        logger.warning("plugin timeout plugin_id=%s after=%ss", plugin_id, timeout_seconds)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.exception("plugin error plugin_id=%s err=%s", plugin_id, exc)
        return None


async def run_analyzer_sandboxed(
    analyze_coro: Any,
    *,
    ctx: PluginExecutionContext,
) -> Any:
    return await run_with_timeout(analyze_coro, timeout_seconds=ctx.timeout_seconds, plugin_id=ctx.plugin_id)
