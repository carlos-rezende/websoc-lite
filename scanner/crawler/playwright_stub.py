from __future__ import annotations

from scanner.core.event_bus import ON_URL_DISCOVERED
from scanner.crawler.base import BaseCrawler
from scanner.plugins.protocols import EventEmitter, HTTPClientPort


class PlaywrightCrawlerStub(BaseCrawler):
    """Future JS-rendered crawl extension — stub re-announces target only (placeholder)."""

    name = "crawler.playwright_stub"

    async def crawl(self, target: str, bus: EventEmitter, request_engine: HTTPClientPort) -> None:
        await bus.emit(ON_URL_DISCOVERED, {"url": target, "source": self.name, "note": "playwright_stub_noop"})
