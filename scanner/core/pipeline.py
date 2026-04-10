from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.core.baseline import BaselineEngine
from scanner.core.diff import DiffEngine
from scanner.core.event_bus import (
    ANOMALY_DETECTED,
    BASELINE_STORED,
    CRAWL_STARTED,
    DIFF_COMPUTED,
    ENDPOINT_DISCOVERED,
    MUTATION_APPLIED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    RISK_SCORED,
    TARGET_LOADED,
    EventBus,
)
from scanner.core.http import RequestEngine
from scanner.core.models import EndpointObservation, Finding, HTTPResult, ScanResult
from scanner.core.mutation import MutationEngine, MutationRequestSpec
from scanner.core.risk import RiskScoringEngine
from scanner.core.telemetry import TelemetryEngine
from scanner.plugins.base import AnalyzerPlugin, CrawlerPlugin
logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 0.35


@dataclass(slots=True)
class PipelineContext:
    target: str
    bus: EventBus
    request_engine: RequestEngine
    baseline_engine: BaselineEngine
    mutation_engine: MutationEngine
    diff_engine: DiffEngine
    risk_engine: RiskScoringEngine
    telemetry_engine: TelemetryEngine
    crawlers: list[CrawlerPlugin]
    analyzers: list[AnalyzerPlugin]
    max_endpoints: int


def _append_probe_param(url: str, token: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["__obs_probe"] = token
    new_query = urlencode(query)
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_query, parts.fragment))


class ObservabilityPipeline:
    """Formal pipeline: Target → Crawl → Request → Baseline → Mutate → Diff → Analyze → Score → Report hooks."""

    async def run_target(self, ctx: PipelineContext) -> ScanResult:
        result = ScanResult(target=ctx.target)
        await ctx.bus.emit(TARGET_LOADED, {"target": ctx.target})

        discovered: list[str] = []

        async def _collect_url(payload: dict[str, Any]) -> None:
            u = payload.get("url")
            if isinstance(u, str):
                discovered.append(u)

        ctx.bus.subscribe(ENDPOINT_DISCOVERED, _collect_url)

        try:
            await ctx.bus.emit(CRAWL_STARTED, {"target": ctx.target})
            for crawler in ctx.crawlers:
                await crawler.crawl(ctx.target, ctx.bus, ctx.request_engine)
        finally:
            ctx.bus.unsubscribe(ENDPOINT_DISCOVERED, _collect_url)

        endpoints = list(dict.fromkeys(discovered))[: ctx.max_endpoints]
        result.crawled_endpoints = endpoints

        for endpoint in endpoints:
            await self._process_endpoint(ctx, endpoint, result)

        return result

    async def _process_endpoint(self, ctx: PipelineContext, endpoint: str, result: ScanResult) -> None:
        token = f"OBS-{uuid.uuid4().hex[:12]}"

        baseline = await ctx.request_engine.request("GET", endpoint)
        await ctx.bus.emit(
            REQUEST_SENT,
            ctx.telemetry_engine.build_request_telemetry(
                target=ctx.target,
                endpoint=endpoint,
                method="GET",
                phase="baseline",
                request_fingerprint=baseline.request_fingerprint,
                request_size=baseline.request_size,
            ),
        )
        await ctx.bus.emit(RESPONSE_RECEIVED, ctx.telemetry_engine.build_response_telemetry(target=ctx.target, endpoint=endpoint, phase="baseline", result=baseline))

        rec = ctx.baseline_engine.store_from_response(endpoint, baseline)
        await ctx.bus.emit(
            BASELINE_STORED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "version": rec.version,
                "status_code": rec.status_code,
                "body_hash": rec.body_hash,
                "response_size": rec.response_size,
            },
        )

        specs = ctx.mutation_engine.collect_mutations(endpoint)
        mutated_url = _mutation_url_for_probe(endpoint, specs)
        mutated_url = _append_probe_param(mutated_url, token)
        await ctx.bus.emit(
            MUTATION_APPLIED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "mutated_endpoint": mutated_url,
                "mutation": specs[0].label if specs else "probe_only",
            },
        )

        mutated = await ctx.request_engine.request("GET", mutated_url)
        await ctx.bus.emit(
            REQUEST_SENT,
            ctx.telemetry_engine.build_request_telemetry(
                target=ctx.target,
                endpoint=mutated_url,
                method="GET",
                phase="mutated",
                request_fingerprint=mutated.request_fingerprint,
                request_size=mutated.request_size,
            ),
        )
        await ctx.bus.emit(RESPONSE_RECEIVED, ctx.telemetry_engine.build_response_telemetry(target=ctx.target, endpoint=mutated_url, phase="mutated", result=mutated))

        signal = ctx.diff_engine.compare(baseline, mutated)
        await ctx.bus.emit(
            DIFF_COMPUTED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "signal": signal.as_dict(),
            },
        )

        extra: dict[str, Any] = {}
        if token in mutated.text:
            extra["has_reflection"] = True

        assessment = ctx.risk_engine.assess(signal, extra_context=extra)

        await ctx.bus.emit(
            RISK_SCORED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "risk_score": assessment.score,
                "reasoning_factors": assessment.reasoning_factors,
            },
        )

        if assessment.score >= ANOMALY_THRESHOLD:
            await ctx.bus.emit(
                ANOMALY_DETECTED,
                {
                    "target": ctx.target,
                    "endpoint": endpoint,
                    "score": assessment.score,
                    "signal": signal.as_dict(),
                },
            )

        result.observations.append(
            EndpointObservation(
                endpoint=endpoint,
                anomaly_score=assessment.score,
                signal=signal.as_dict(),
                risk_reasoning=assessment.reasoning_factors,
                probe_token=token,
            )
        )

        for analyzer in ctx.analyzers:
            findings = await analyzer.analyze(
                ctx.target,
                endpoint,
                baseline,
                mutated,
                signal,
                token,
                risk_assessment=assessment,
            )
            for f in findings:
                result.findings.append(f)
                await ctx.bus.emit(
                    RISK_SCORED,
                    {
                        "target": ctx.target,
                        "endpoint": endpoint,
                        "plugin": f.plugin,
                        "risk_score": f.risk_score,
                        "title": f.title,
                    },
                )


def _mutation_url_for_probe(endpoint: str, specs: list[MutationRequestSpec]) -> str:
    if specs:
        return specs[0].url
    return endpoint
