from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AppConfig:
    targets: list[str]
    output_dir: str = "reports"
    timeout_seconds: int = 8
    retries: int = 2
    debug: bool = False
    max_endpoints_per_target: int = 80
    stream_logs: bool = False
    realtime_event_log_file: str = "realtime.ndjson"
    enable_experimental_extensions: bool = False
    analyzer_plugins: list[str] = field(
        default_factory=lambda: [
            "scanner.plugins.analyzers.response_diff.ResponseDiffAnalyzer",
            "scanner.plugins.analyzers.reflection.ReflectionAnalyzer",
        ]
    )
    crawler_plugins: list[str] = field(
        default_factory=lambda: [
            "scanner.crawler.seeder.EndpointSeeder",
            "scanner.crawler.html.HTMLCrawler",
            "scanner.crawler.playwright_stub.PlaywrightCrawlerStub",
        ]
    )
    reporter_plugins: list[str] = field(
        default_factory=lambda: [
            "scanner.reporting.json.JSONReport",
            "scanner.reporting.html.HTMLReport",
        ]
    )
    mutation_plugins: list[str] = field(
        default_factory=lambda: [
            "scanner.plugins.mutations.extra_suffix.ExtraSuffixMutationPlugin",
        ]
    )
    experimental_extension_plugins: list[str] = field(default_factory=list)


def merge_config_from_file(path: str | None, base: AppConfig) -> AppConfig:
    if not path:
        return base
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    names = {f.name for f in fields(AppConfig)}
    kwargs = {k: raw[k] for k in raw if k in names}
    return replace(base, **kwargs)
