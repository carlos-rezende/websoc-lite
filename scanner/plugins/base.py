from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.core.models import DiffSignal, Finding, HTTPResult, RiskAssessment
    from scanner.core.mutation import MutationStrategy
    from scanner.plugins.protocols import EventEmitter, HTTPClientPort


class PluginBase(ABC):
    name: str = "plugin.base"


class CrawlerPlugin(PluginBase, ABC):
    @abstractmethod
    async def crawl(self, target: str, bus: "EventEmitter", request_engine: "HTTPClientPort") -> None:
        """Discover URLs and emit `on_url_discovered` for each (no return list — event-driven)."""


class AnalyzerPlugin(PluginBase, ABC):
    @abstractmethod
    async def analyze(
        self,
        target: str,
        endpoint: str,
        baseline: "HTTPResult",
        mutated: "HTTPResult",
        signal: "DiffSignal",
        probe_token: str,
        *,
        risk_assessment: "RiskAssessment | None" = None,
    ) -> list["Finding"]:
        """Derive findings from behavioral comparison."""


class ReporterPlugin(PluginBase, ABC):
    @abstractmethod
    async def emit(
        self,
        results: list[Any],
        output_dir: str,
        *,
        timeline: list[dict[str, Any]] | None = None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> str:
        """Persist report; timeline e incidentes correlacionados são opcionais."""


class MutationPlugin(PluginBase, ABC):
    @abstractmethod
    def strategies(self) -> list["MutationStrategy"]:
        """Additional controlled perturbation strategies (no exploit payloads)."""
