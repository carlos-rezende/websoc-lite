from __future__ import annotations

from urllib.parse import urljoin

from scanner.core.event_bus import ON_URL_DISCOVERED
from scanner.plugins.base import CrawlerPlugin
from scanner.plugins.protocols import EventEmitter, HTTPClientPort


class SimpleExtraPathCrawler(CrawlerPlugin):
    """Example crawler plugin: emits one additional well-known path for observability seeding."""

    name = "plugin.crawler.simple_extra_path"

    async def crawl(self, target: str, bus: EventEmitter, request_engine: HTTPClientPort) -> None:
        base = target.rstrip("/") + "/"
        extra = urljoin(base, "favicon.ico")
        await bus.emit(ON_URL_DISCOVERED, {"url": extra, "source": self.name})
