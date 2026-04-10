from __future__ import annotations

from scanner.plugins.base import AnalyzerPlugin, CrawlerPlugin, MutationPlugin, ReporterPlugin
from scanner.plugins.loader import load_plugin


class PluginRuntime:
    """Loads plugins by dotted path; keeps lists per role."""

    def __init__(self) -> None:
        self.crawlers: list[CrawlerPlugin] = []
        self.analyzers: list[AnalyzerPlugin] = []
        self.reporters: list[ReporterPlugin] = []
        self.mutations: list[MutationPlugin] = []

    def load_crawlers(self, paths: list[str]) -> None:
        for p in paths:
            self.crawlers.append(load_plugin(p, CrawlerPlugin))

    def load_analyzers(self, paths: list[str]) -> None:
        for p in paths:
            self.analyzers.append(load_plugin(p, AnalyzerPlugin))

    def load_reporters(self, paths: list[str]) -> None:
        for p in paths:
            self.reporters.append(load_plugin(p, ReporterPlugin))

    def load_mutations(self, paths: list[str]) -> None:
        for p in paths:
            self.mutations.append(load_plugin(p, MutationPlugin))
