from __future__ import annotations

from urllib.parse import urljoin

from scanner.core.event_bus import ON_URL_DISCOVERED
from scanner.crawler.base import BaseCrawler
from scanner.plugins.protocols import EventEmitter, HTTPClientPort

COMMON_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1",
    "/api/v1/health",
    "/graphql",
    "/health",
)


class EndpointSeeder(BaseCrawler):
    """Static + lightweight path guessing — emits URLs as events (no bulk return)."""

    name = "crawler.seeder"

    async def crawl(self, target: str, bus: EventEmitter, request_engine: HTTPClientPort) -> None:
        base = target.rstrip("/") + "/"
        for p in COMMON_PATHS:
            u = urljoin(base, p.lstrip("/"))
            await bus.emit(ON_URL_DISCOVERED, {"url": u, "source": self.name})
