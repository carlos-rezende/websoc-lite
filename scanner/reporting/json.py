from __future__ import annotations

import json
from pathlib import Path

from scanner.core.models import ScanResult
from scanner.plugins.base import ReporterPlugin


def _risk_ranking_for_result(result: ScanResult) -> list[dict[str, object]]:
    rows = [
        {
            "endpoint": o.endpoint,
            "anomaly_score": o.anomaly_score,
            "probe_token": o.probe_token,
        }
        for o in result.observations
    ]
    return sorted(rows, key=lambda x: float(x["anomaly_score"]), reverse=True)


class JSONReport(ReporterPlugin):
    name = "reporter.json"

    async def emit(
        self,
        results: list[ScanResult],
        output_dir: str,
        *,
        timeline: list[dict[str, object]] | None = None,
        incidents: list[dict[str, object]] | None = None,
    ) -> str:
        output_path = Path(output_dir) / "report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload: list[dict[str, object]] = []
        for result in results:
            payload.append(
                {
                    "target": result.target,
                    "started_at": result.started_at,
                    "finished_at": result.finished_at,
                    "crawled_endpoints": result.crawled_endpoints,
                    "event_timeline": result.event_timeline,
                    "risk_ranking": _risk_ranking_for_result(result),
                    "hypotheses": [h.as_dict() for h in result.hypotheses],
                    "observations": [
                        {
                            "endpoint": o.endpoint,
                            "anomaly_score": o.anomaly_score,
                            "signal": o.signal,
                            "risk_reasoning": o.risk_reasoning,
                            "probe_token": o.probe_token,
                        }
                        for o in result.observations
                    ],
                    "findings": [
                        {
                            "plugin": finding.plugin,
                            "title": finding.title,
                            "description": finding.description,
                            "endpoint": finding.endpoint,
                            "risk_score": finding.risk_score,
                            "evidence": finding.evidence,
                            "created_at": finding.created_at,
                        }
                        for finding in result.findings
                    ],
                }
            )

        out: dict[str, object] = {
            "runs": payload,
            "merged_timeline": timeline or [],
            "incident_clusters": incidents or [],
            "evidence_trail_note": "Timeline unificada + incidentes correlacionados; validação manual obrigatória.",
        }
        output_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return str(output_path)
