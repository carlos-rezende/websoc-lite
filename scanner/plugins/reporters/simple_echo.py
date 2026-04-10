from __future__ import annotations

import logging
from pathlib import Path

from scanner.core.models import ScanResult
from scanner.plugins.base import ReporterPlugin

logger = logging.getLogger(__name__)


class SimpleEchoReporter(ReporterPlugin):
    """Example reporter: streams a short summary to logs (optional complement to JSON/HTML)."""

    name = "plugin.reporter.simple_echo"

    async def emit(self, results: list[ScanResult], output_dir: str, *, timeline: list[dict[str, object]] | None = None) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        marker = Path(output_dir) / "echo_summary.txt"
        lines = [f"targets={len(results)} timeline_events={len(timeline or [])}"]
        for r in results:
            lines.append(f"{r.target} findings={len(r.findings)} endpoints={len(r.crawled_endpoints)}")
        text = "\n".join(lines) + "\n"
        marker.write_text(text, encoding="utf-8")
        logger.info("simple_echo_reporter %s", text.strip())
        return str(marker)
