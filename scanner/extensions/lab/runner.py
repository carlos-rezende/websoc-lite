"""Entrada do modo laboratório — não invoca o pipeline principal de crawl."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from scanner.core.event_bus import EventBus
from scanner.core.http import RequestEngine
from scanner.extensions.lab.experiments import run_safe_mutation_campaign
from scanner.utils.config import AppConfig

logger = logging.getLogger(__name__)


async def run_lab_mode(config: AppConfig) -> list[str]:
    """
    Opt-in explícito: campanhas seguras por URL, saída NDJSON (telemetria estruturada).
    Não executa crawl amplo nem o pipeline `ObservabilityPipeline`.
    """
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = out_dir / getattr(config, "lab_telemetry_file", "lab_telemetry.ndjson")

    bus = EventBus(record_timeline=True, max_queue_size=0)
    await bus.start()

    summaries: list[dict[str, object]] = []

    async with RequestEngine(
        timeout_seconds=config.timeout_seconds,
        retries=config.retries,
    ) as request_engine:
        for target in config.targets:
            summary = await run_safe_mutation_campaign(
                target=target,
                endpoint=target,
                bus=bus,
                request_engine=request_engine,
                rounds=getattr(config, "lab_mutation_rounds", 3),
            )
            summaries.append(summary)

    # Timeline append-only do bus + resumo agregado (reproduzível).
    with ndjson_path.open("w", encoding="utf-8") as fh:
        for row in bus.timeline:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")
        fh.write(json.dumps({"lab_summary": summaries, "kind": "lab_aggregate"}, ensure_ascii=True) + "\n")

    logger.info("lab_telemetry_written path=%s events=%s", ndjson_path, len(bus.timeline))
    return [str(ndjson_path)]
