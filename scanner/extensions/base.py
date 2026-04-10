from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ExperimentalExtension(ABC):
    """Base para extensoes experimentais isoladas do core."""

    name = "extension.experimental"

    @abstractmethod
    async def on_event(self, event_name: str, payload: dict[str, Any]) -> None:
        """Recebe copia de eventos do core; sem acesso a estado interno."""
