from __future__ import annotations

import importlib
from typing import TypeVar

from scanner.plugins.base import AnalyzerPlugin, CrawlerPlugin, MutationPlugin, ReporterPlugin

T = TypeVar("T")


def load_plugin(dotted_path: str, plugin_type: type[T]) -> T:
    module_name, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    klass = getattr(module, class_name)
    instance = klass()
    if not isinstance(instance, plugin_type):
        raise TypeError(f"Plugin {dotted_path} is not a {plugin_type.__name__}")
    return instance
