from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.core.baseline import BaselineEngine
from scanner.core.correlation import CorrelationEngine
from scanner.core.diff import DiffEngine
from scanner.core.event_bus import (
    ANOMALY_DETECTED,
    BASELINE_STORED,
    CRAWL_STARTED,
    DIFF_COMPUTED,
    ENDPOINT_DISCOVERED,
    HYPOTHESIS_GENERATED,
    INCIDENT_DETECTED,
    INVESTIGATION_RECOMMENDED,
    MUTATION_APPLIED,
    REPORT_GENERATED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    RISK_SCORED,
    TARGET_LOADED,
    EventBus,
)
from scanner.core.http import RequestEngine
from scanner.core.metrics import MetricsRegistry
from scanner.core.models import ScanResult
from scanner.core.hypothesis import HypothesisEngine
from scanner.core.mutation import MutationEngine, MutationStrategy
from scanner.core.pipeline import ObservabilityPipeline, PipelineContext
from scanner.core.risk import RiskScoringEngine
from scanner.core.state_store import StateStore
from scanner.core.telemetry import TelemetryEngine
from scanner.plugins.manager import PluginRuntime
from scanner.utils.config import AppConfig

logger = logging.getLogger(__name__)
SOC_EVENTS = (
    TARGET_LOADED,
    CRAWL_STARTED,
    ENDPOINT_DISCOVERED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    BASELINE_STORED,
    MUTATION_APPLIED,
    DIFF_COMPUTED,
    RISK_SCORED,
    HYPOTHESIS_GENERATED,
    INVESTIGATION_RECOMMENDED,
    ANOMALY_DETECTED,
    INCIDENT_DETECTED,
    REPORT_GENERATED,
)


class FrameworkRuntime:
    """Inicializa o runtime SOC v2: bus com schema, métricas, correlação, estado opcional."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.metrics = MetricsRegistry()
        self.bus = EventBus(
            record_timeline=True,
            max_queue_size=config.soc_v2_event_queue_size,
            queue_strategy=config.soc_v2_queue_strategy,
            metrics=self.metrics,
        )
        self.plugins = PluginRuntime()
        self.extension_sandbox: Any | None = None
        self.state_store: StateStore | None = None
        if config.state_store_enabled:
            self.state_store = StateStore(Path(config.output_dir) / "state" / "observability.db")
        self.correlation: CorrelationEngine | None = None
        if config.correlation_enabled:
            self.correlation = CorrelationEngine(self.bus, metrics=self.metrics)
        self._incidents: list[dict[str, Any]] = []
        self._load_plugins()
        self._setup_extension_sandbox()

    def _load_plugins(self) -> None:
        self.plugins.load_crawlers(self.config.crawler_plugins)
        self.plugins.load_analyzers(self.config.analyzer_plugins)
        self.plugins.load_reporters(self.config.reporter_plugins)
        self.plugins.load_mutations(self.config.mutation_plugins)

    def _setup_extension_sandbox(self) -> None:
        if not self.config.enable_experimental_extensions:
            return
        from scanner.extensions.sandbox import ExtensionSandbox

        self.extension_sandbox = ExtensionSandbox(self.config.experimental_extension_plugins)

    async def run(self) -> list[str]:
        await self.bus.start()

        if self.correlation:

            async def _corr_anomaly(payload: dict[str, Any]) -> None:
                await self.correlation.handle_anomaly_payload(payload)

            self.bus.subscribe(ANOMALY_DETECTED, _corr_anomaly)

        async def _capture_incident(payload: dict[str, Any]) -> None:
            self._incidents.append(
                {
                    "incident_id": payload.get("incident_id"),
                    "pattern": payload.get("pattern"),
                    "severity_score": payload.get("severity_score"),
                    "affected_endpoints": payload.get("affected_endpoints"),
                    "timeline_start_iso": payload.get("timeline_start_iso"),
                    "timeline_end_iso": payload.get("timeline_end_iso"),
                    "correlated_events": payload.get("correlated_events"),
                }
            )

        self.bus.subscribe(INCIDENT_DETECTED, _capture_incident)

        stream_path: Path | None = None
        stream_lock: asyncio.Lock | None = None
        if self.config.stream_logs:
            out_dir = Path(self.config.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            stream_path = out_dir / self.config.realtime_event_log_file
            stream_path.write_text("", encoding="utf-8")
            stream_lock = asyncio.Lock()

        if self.config.stream_logs:
            async def _stream(payload: dict[str, Any]) -> None:
                logger.info("stream event=%s", payload.get("event"))

            async def _stream_to_file(payload: dict[str, Any]) -> None:
                if not stream_path or not stream_lock:
                    return
                entry = {
                    "ts": datetime.now(tz=timezone.utc).isoformat(),
                    **payload,
                }
                async with stream_lock:
                    with stream_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(entry, ensure_ascii=True) + "\n")

            for ev in SOC_EVENTS:
                self.bus.subscribe(ev, _stream)
                self.bus.subscribe(ev, _stream_to_file)

        if self.extension_sandbox:
            async def _dispatch_to_sandbox(payload: dict[str, Any]) -> None:
                await self.extension_sandbox.dispatch(str(payload.get("event", "")), payload)

            for ev in SOC_EVENTS:
                self.bus.subscribe(ev, _dispatch_to_sandbox)

        extra_strategies: list[MutationStrategy] = []
        for mp in self.plugins.mutations:
            extra_strategies.extend(mp.strategies())

        results: list[ScanResult] = []
        async with RequestEngine(
            timeout_seconds=self.config.timeout_seconds,
            retries=self.config.retries,
        ) as request_engine:
            baseline_engine = BaselineEngine()
            mutation_engine = MutationEngine(extra=extra_strategies or None)
            diff_engine = DiffEngine()
            risk_engine = RiskScoringEngine()
            telemetry_engine = TelemetryEngine()
            pipeline = ObservabilityPipeline()
            hypothesis_engine = HypothesisEngine()

            for target in self.config.targets:
                self.bus.clear_timeline()
                ctx = PipelineContext(
                    target=target,
                    bus=self.bus,
                    request_engine=request_engine,
                    baseline_engine=baseline_engine,
                    mutation_engine=mutation_engine,
                    diff_engine=diff_engine,
                    risk_engine=risk_engine,
                    telemetry_engine=telemetry_engine,
                    crawlers=self.plugins.crawlers,
                    analyzers=self.plugins.analyzers,
                    max_endpoints=self.config.max_endpoints_per_target,
                    state_store=self.state_store,
                    metrics=self.metrics,
                    hypothesis_engine=hypothesis_engine,
                )
                result = await pipeline.run_target(ctx)
                result.event_timeline = list(self.bus.timeline)
                result.finalize()
                results.append(result)

        outputs: list[str] = []
        for reporter in self.plugins.reporters:
            path = await reporter.emit(
                results,
                self.config.output_dir,
                timeline=self._merge_timelines(results),
                incidents=list(self._incidents),
            )
            await self.bus.emit(REPORT_GENERATED, {"reporter": reporter.name, "path": path}, source="reporter")
            outputs.append(path)

        if self.config.metrics_file:
            mp = Path(self.config.output_dir) / self.config.metrics_file
            self.metrics.dump_json(mp)
        return outputs

    @staticmethod
    def _merge_timelines(results: list[ScanResult]) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        for r in results:
            merged.extend(r.event_timeline)
        return merged
