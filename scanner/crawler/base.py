from __future__ import annotations

from scanner.plugins.base import CrawlerPlugin


class BaseCrawler(CrawlerPlugin):
    name = "crawler.base"

    async def crawl(self, target: str, bus: object, request_engine: object) -> None:
        raise NotImplementedError
