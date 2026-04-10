"""
Demonstração mínima: várias anomalias na mesma janela temporal → evento `incident_detected`.

Executar: python -m scanner.examples.soc_v2_correlation_demo
"""

from __future__ import annotations

import asyncio
from typing import Any

from scanner.core.correlation import CorrelationEngine
from scanner.core.event_bus import INCIDENT_DETECTED, EventBus


async def _main() -> None:
    bus = EventBus(record_timeline=True, max_queue_size=0)
    await bus.start()

    incidents: list[dict[str, Any]] = []

    async def _on_incident(payload: dict[str, Any]) -> None:
        incidents.append(payload)

    bus.subscribe(INCIDENT_DETECTED, _on_incident)

    # Janela larga; pico com apenas 3 eventos (ajuste para demo rápida)
    engine = CorrelationEngine(
        bus,
        window_seconds=600.0,
        spike_min_anomalies=3,
        min_anomalies_same_endpoint=50,
    )

    for i in range(3):
        await engine.handle_anomaly_payload(
            {
                "target": "https://demo.internal/",
                "endpoint": f"https://demo.internal/path{i}",
                "score": 0.72,
                "event_id": f"evt-{i}",
            }
        )

    assert len(incidents) == 1, "esperado um incidente por pico temporal"
    p0 = incidents[0]
    assert p0.get("pattern") == "temporal_spike"
    print("OK: incidente correlacionado:", p0.get("incident_id"), "endpoints=", p0.get("affected_endpoints"))


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
