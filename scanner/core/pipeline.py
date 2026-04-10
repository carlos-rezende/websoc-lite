from __future__ import annotations

import logging
import time
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
    HYPOTHESIS_GENERATED,
    INVESTIGATION_RECOMMENDED,
    MUTATION_APPLIED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    RISK_SCORED,
    TARGET_LOADED,
    EventBus,
)
from scanner.core.http import RequestEngine
from scanner.core.hypothesis import HypothesisEngine, rank_investigation_targets
from scanner.core.models import EndpointObservation, Finding, HTTPResult, ScanResult, utc_now_iso
from scanner.core.mutation import MutationEngine, MutationRequestSpec
from scanner.core.metrics import MetricsRegistry
from scanner.core.risk import RiskScoringEngine
from scanner.core.state_store import StateStore
from scanner.core.telemetry import TelemetryEngine
from scanner.plugins.base import AnalyzerPlugin, CrawlerPlugin
from scanner.plugins.sandbox import PluginExecutionContext, run_analyzer_sandboxed

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
    state_store: StateStore | None = None
    metrics: MetricsRegistry | None = None
    hypothesis_engine: HypothesisEngine | None = None


def _append_probe_param(url: str, token: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["__obs_probe"] = token
    new_query = urlencode(query)
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_query, parts.fragment))


class ObservabilityPipeline:
    """Formal pipeline: Target → Crawl → Request → Baseline → Mutate → Diff → Analyze → Score → Report hooks."""

    async def run_target(self, ctx: PipelineContext) -> ScanResult:
        t_pipeline = time.perf_counter()
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
        if ctx.metrics:
            ctx.metrics.max_crawl_depth(len(endpoints))

        hyp_engine = ctx.hypothesis_engine or HypothesisEngine()

        for endpoint in endpoints:
            await self._process_endpoint(ctx, endpoint, result, hypothesis_engine=hyp_engine)

        ranked = rank_investigation_targets(
            [{"endpoint": o.endpoint, "anomaly_score": o.anomaly_score} for o in result.observations]
        )
        await ctx.bus.emit(
            INVESTIGATION_RECOMMENDED,
            {
                "target": ctx.target,
                "ranked_endpoints": ranked[:40],
                "note": "Priorização para revisão manual — não implica vulnerabilidade confirmada.",
            },
        )

        if ctx.metrics:
            ctx.metrics.observe_latency_ms((time.perf_counter() - t_pipeline) * 1000.0)
        return result

    async def _process_endpoint(
        self,
        ctx: PipelineContext,
        endpoint: str,
        result: ScanResult,
        *,
        hypothesis_engine: HypothesisEngine,
    ) -> None:
        token = f"OBS-{uuid.uuid4().hex[:12]}"

        baseline = await ctx.request_engine.request("GET", endpoint)
        if ctx.metrics:
            ctx.metrics.inc("requests_total", 1)
        ts = utc_now_iso()
        peek = ctx.baseline_engine.get(endpoint)
        rec = ctx.baseline_engine.store_from_response(endpoint, baseline)
        if ctx.metrics and peek is not None and rec is peek:
            ctx.metrics.inc("baseline_cache_hits", 1)

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

        if ctx.state_store:
            fp = StateStore.fingerprint_from_result(baseline)
            await ctx.state_store.record_baseline_row(
                endpoint,
                version=rec.version,
                status_code=rec.status_code,
                body_hash=rec.body_hash,
                response_size=rec.response_size,
                ts=ts,
            )
            await ctx.state_store.record_fingerprint(endpoint, fp, ts)

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
        if ctx.metrics:
            ctx.metrics.inc("requests_total", 1)
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

        signal = ctx.diff_engine.compare(baseline, mutated, probe_token=token)
        await ctx.bus.emit(
            DIFF_COMPUTED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "signal": signal.as_dict(),
            },
        )
        if ctx.state_store:
            await ctx.state_store.record_diff(endpoint, signal.as_dict(), ts)

        inst_proxy = (signal.structural_diff_score + signal.semantic_divergence_score) / 2.0
        extra: dict[str, Any] = {"response_instability_proxy": inst_proxy}

        assessment = ctx.risk_engine.assess(signal, extra_context=extra, endpoint=endpoint)

        await ctx.bus.emit(
            RISK_SCORED,
            {
                "target": ctx.target,
                "endpoint": endpoint,
                "risk_score": assessment.score,
                "reasoning_factors": assessment.reasoning_factors,
            },
        )
        if ctx.state_store:
            await ctx.state_store.record_risk(
                endpoint,
                ctx.target,
                assessment.score,
                assessment.reasoning_factors,
                ts,
            )

        if assessment.score >= ANOMALY_THRESHOLD:
            anomaly_evt_id = str(uuid.uuid4())
            await ctx.bus.emit(
                ANOMALY_DETECTED,
                {
                    "target": ctx.target,
                    "endpoint": endpoint,
                    "score": assessment.score,
                    "signal": signal.as_dict(),
                    "event_id": anomaly_evt_id,
                },
            )
            if ctx.metrics:
                ctx.metrics.inc("anomalies_detected", 1)

        for hyp in hypothesis_engine.generate(
            target=ctx.target,
            endpoint=endpoint,
            baseline=baseline,
            mutated=mutated,
            signal=signal,
            assessment=assessment,
            probe_token=token,
        ):
            result.hypotheses.append(hyp)
            await ctx.bus.emit(
                HYPOTHESIS_GENERATED,
                {
                    "target": ctx.target,
                    "hypothesis": hyp.as_dict(),
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
            pctx = PluginExecutionContext(plugin_id=analyzer.name, bus=ctx.bus)
            raw = await run_analyzer_sandboxed(
                analyzer.analyze(
                    ctx.target,
                    endpoint,
                    baseline,
                    mutated,
                    signal,
                    token,
                    risk_assessment=assessment,
                ),
                ctx=pctx,
            )
            findings = raw if isinstance(raw, list) else []
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
