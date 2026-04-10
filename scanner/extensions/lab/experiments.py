"""Campanhas benignas de mutação para telemetria — sem payloads de exploit nem bypass."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.core.baseline import BaselineEngine
from scanner.core.diff import DiffEngine
from scanner.core.event_bus import (
    BASELINE_STORED,
    DIFF_COMPUTED,
    EventBus,
    MUTATION_APPLIED,
    REQUEST_SENT,
    RESPONSE_RECEIVED,
    RISK_SCORED,
    TARGET_LOADED,
)
from scanner.core.http import RequestEngine
from scanner.core.models import utc_now_iso
from scanner.core.mutation import MutationEngine, MutationRequestSpec
from scanner.core.risk import RiskScoringEngine
from scanner.core.telemetry import TelemetryEngine


def _append_probe(url: str, token: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["__lab_probe"] = token
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(query), parts.fragment))


def _pick_mutation_url(endpoint: str, specs: list[MutationRequestSpec]) -> str:
    if specs:
        return specs[0].url
    return endpoint


async def run_safe_mutation_campaign(
    *,
    target: str,
    endpoint: str,
    bus: EventBus,
    request_engine: RequestEngine,
    rounds: int = 3,
) -> dict[str, Any]:
    """
    Uma sequência determinística de pedidos baseline + perturbados (modo seguro).
    Emite apenas eventos de telemetria aprovados pelo schema.
    """
    token = f"LAB-{uuid.uuid4().hex[:12]}"
    telemetry = TelemetryEngine()
    baseline_engine = BaselineEngine()
    mutation_engine = MutationEngine()
    diff_engine = DiffEngine()
    risk_engine = RiskScoringEngine()

    await bus.emit(TARGET_LOADED, {"target": target, "lab_mode": True})

    baseline = await request_engine.request("GET", endpoint)
    rec = baseline_engine.store_from_response(endpoint, baseline)
    ts = utc_now_iso()

    await bus.emit(
        REQUEST_SENT,
        telemetry.build_request_telemetry(
            target=target,
            endpoint=endpoint,
            method="GET",
            phase="lab_baseline",
            request_fingerprint=baseline.request_fingerprint,
            request_size=baseline.request_size,
        ),
    )
    await bus.emit(RESPONSE_RECEIVED, telemetry.build_response_telemetry(target=target, endpoint=endpoint, phase="lab_baseline", result=baseline))
    await bus.emit(
        BASELINE_STORED,
        {
            "target": target,
            "endpoint": endpoint,
            "version": rec.version,
            "status_code": rec.status_code,
            "body_hash": rec.body_hash,
            "response_size": rec.response_size,
            "lab_mode": True,
        },
    )

    signals: list[dict[str, Any]] = []
    for i in range(max(1, rounds)):
        specs = mutation_engine.collect_mutations(endpoint)
        mutated_url = _pick_mutation_url(endpoint, specs)
        mutated_url = _append_probe(mutated_url, f"{token}-{i}")

        await bus.emit(
            MUTATION_APPLIED,
            {
                "target": target,
                "endpoint": endpoint,
                "mutated_endpoint": mutated_url,
                "mutation": specs[0].label if specs else "lab_probe_only",
                "round": i,
                "lab_mode": True,
            },
        )

        mutated = await request_engine.request("GET", mutated_url)
        await bus.emit(
            REQUEST_SENT,
            telemetry.build_request_telemetry(
                target=target,
                endpoint=mutated_url,
                method="GET",
                phase="lab_mutated",
                request_fingerprint=mutated.request_fingerprint,
                request_size=mutated.request_size,
            ),
        )
        await bus.emit(RESPONSE_RECEIVED, telemetry.build_response_telemetry(target=target, endpoint=mutated_url, phase="lab_mutated", result=mutated))

        signal = diff_engine.compare(baseline, mutated, probe_token=f"{token}-{i}")
        signals.append(signal.as_dict())
        await bus.emit(
            DIFF_COMPUTED,
            {
                "target": target,
                "endpoint": endpoint,
                "signal": signal.as_dict(),
                "round": i,
                "lab_mode": True,
            },
        )

        extra = {"response_instability_proxy": (signal.structural_diff_score + signal.semantic_divergence_score) / 2.0}
        assessment = risk_engine.assess(signal, extra_context=extra, endpoint=endpoint)
        await bus.emit(
            RISK_SCORED,
            {
                "target": target,
                "endpoint": endpoint,
                "risk_score": assessment.score,
                "reasoning_factors": assessment.reasoning_factors,
                "round": i,
                "lab_mode": True,
            },
        )

    return {
        "target": target,
        "endpoint": endpoint,
        "timestamp": ts,
        "rounds": rounds,
        "signals": signals,
        "probe_prefix": token,
    }
