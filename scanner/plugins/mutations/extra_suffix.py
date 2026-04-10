from __future__ import annotations

from scanner.core.mutation import MutationRequestSpec, MutationStrategy
from scanner.plugins.base import MutationPlugin


class ExtraSuffixStrategy(MutationStrategy):
    """Controlled URL shape variation (trailing slash) — behavioral, not exploitation."""

    name = "mutation.extra_suffix"

    def apply(self, url: str) -> list[MutationRequestSpec]:
        if not url:
            return []
        if url.endswith("/"):
            return [MutationRequestSpec(label="strip_trailing_slash", url=url.rstrip("/"))]
        return [MutationRequestSpec(label="add_trailing_slash", url=url + "/")]


class ExtraSuffixMutationPlugin(MutationPlugin):
    name = "mutation.extra_suffix"

    def strategies(self) -> list[MutationStrategy]:
        return [ExtraSuffixStrategy()]
