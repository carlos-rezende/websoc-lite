from __future__ import annotations

import asyncio

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scanner.core.event_bus import ON_URL_DISCOVERED
from scanner.crawler.base import BaseCrawler
from scanner.plugins.protocols import EventEmitter, HTTPClientPort


class HTMLCrawler(BaseCrawler):
    name = "crawler.html"

    async def crawl(self, target: str, bus: EventEmitter, request_engine: HTTPClientPort) -> None:
        await bus.emit(ON_URL_DISCOVERED, {"url": target, "source": self.name})
        response = await request_engine.request("GET", target)
        if response.error or response.status_code >= 400:
            return

        soup = BeautifulSoup(response.text, "html.parser")
        target_host = urlparse(target).netloc

        for node in soup.find_all("a", href=True):
            full = urljoin(target, str(node["href"]).strip())
            if urlparse(full).netloc == target_host:
                await bus.emit(ON_URL_DISCOVERED, {"url": full, "source": self.name})
                await asyncio.sleep(0.05)
