from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from scanner.core.baseline import BaselineEngine
from scanner.core.diff import DiffEngine
from scanner.core.event_bus import ON_TARGET_LOADED, ON_URL_DISCOVERED, EventBus
from scanner.core.models import HTTPResult
from scanner.core.mutation import MutationEngine
from scanner.core.pipeline import ObservabilityPipeline, PipelineContext
from scanner.core.risk import RiskScoringEngine
from scanner.core.telemetry import TelemetryEngine
from scanner.plugins.base import CrawlerPlugin


def test_event_bus_emit_delivers_payload() -> None:
    seen: list[dict[str, object]] = []

    async def _run() -> None:
        bus = EventBus(record_timeline=False)

        async def h(p: dict[str, object]) -> None:
            seen.append(p)

        bus.subscribe(ON_TARGET_LOADED, h)
        await bus.emit(ON_TARGET_LOADED, {"target": "https://example.com"})

    asyncio.run(_run())
    assert seen and seen[0].get("event") == ON_TARGET_LOADED
    assert seen[0].get("target") == "https://example.com"


def test_diff_engine_produces_bounded_scores() -> None:
    de = DiffEngine()
    a = HTTPResult(
        url="https://x/a",
        method="GET",
        status_code=200,
        headers={},
        text="hello world",
        elapsed_ms=1.0,
    )
    b = HTTPResult(
        url="https://x/b",
        method="GET",
        status_code=500,
        headers={},
        text="different content " * 10,
        elapsed_ms=2.0,
    )
    sig = de.compare(a, b)
    assert 0.0 <= sig.structural_diff_score <= 1.0
    assert 0.0 <= sig.semantic_divergence_score <= 1.0
    assert 0.0 <= sig.entropy_change_ratio <= 1.0


def test_pipeline_runs_with_mock_http() -> None:
    async def _run() -> None:
        bus = EventBus(record_timeline=True)

        class OneUrlCrawler(CrawlerPlugin):
            name = "test.one"

            async def crawl(self, target: str, bus_inner, request_engine) -> None:
                await bus_inner.emit(ON_URL_DISCOVERED, {"url": "https://example.test/page", "source": self.name})

        async def fake_request(method: str, url: str, **kwargs: object) -> HTTPResult:
            return HTTPResult(
                url=url,
                method=method,
                status_code=200,
                headers={},
                text="<html>ok</html>",
                elapsed_ms=1.0,
            )

        req = MagicMock()
        req.request = AsyncMock(side_effect=fake_request)

        ctx = PipelineContext(
            target="https://example.test/",
            bus=bus,
            request_engine=req,
            baseline_engine=BaselineEngine(),
            mutation_engine=MutationEngine(),
            diff_engine=DiffEngine(),
            risk_engine=RiskScoringEngine(),
            telemetry_engine=TelemetryEngine(),
            crawlers=[OneUrlCrawler()],
            analyzers=[],
            max_endpoints=10,
        )

        pipe = ObservabilityPipeline()
        return await pipe.run_target(ctx)

    result = asyncio.run(_run())
    assert result.target == "https://example.test/"
    assert "https://example.test/page" in result.crawled_endpoints
    assert result.observations
