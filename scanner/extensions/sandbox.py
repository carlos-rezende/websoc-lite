from __future__ import annotations

import copy
import importlib
from typing import Any

from scanner.extensions.base import ExperimentalExtension


class ExtensionSandbox:
    """Roteia eventos para extensoes experimentais em isolamento por copia."""

    def __init__(self, dotted_paths: list[str]) -> None:
        self._extensions: list[ExperimentalExtension] = []
        for path in dotted_paths:
            self._extensions.append(self._load(path))

    def _load(self, path: str) -> ExperimentalExtension:
        module_path, class_name = path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        inst = cls()
        if not isinstance(inst, ExperimentalExtension):
            raise TypeError(f"{path} must inherit ExperimentalExtension")
        return inst

    async def dispatch(self, event_name: str, payload: dict[str, Any]) -> None:
        # Copy payload per extension to avoid shared mutable state.
        for ext in self._extensions:
            await ext.on_event(event_name, copy.deepcopy(payload))
