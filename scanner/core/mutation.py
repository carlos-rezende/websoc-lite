from __future__ import annotations

import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class MutationRequestSpec:
    """Describes a single controlled perturbation (not exploit payloads)."""

    label: str
    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    json_body: dict[str, Any] | None = None


class MutationStrategy(ABC):
    name: str = "mutation.strategy"

    @abstractmethod
    def apply(self, url: str) -> list[MutationRequestSpec]:
        """Return zero or more mutation specs for the given endpoint URL."""


class NumericVariationStrategy(MutationStrategy):
    name = "mutation.numeric_variation"

    def apply(self, url: str) -> list[MutationRequestSpec]:
        parts = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not q:
            return []
        out: list[MutationRequestSpec] = []
        for key, val in q:
            if val.isdigit():
                alt = str(int(val) + 1)
                new_q = [(k, alt if k == key else v) for k, v in q]
                new_url = urllib.parse.urlunparse(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        parts.params,
                        urllib.parse.urlencode(new_q),
                        parts.fragment,
                    )
                )
                out.append(MutationRequestSpec(label=f"numeric_inc:{key}", url=new_url))
        return out[:3]


class StringPerturbationStrategy(MutationStrategy):
    name = "mutation.string_perturbation"

    def apply(self, url: str) -> list[MutationRequestSpec]:
        parts = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not q:
            return []
        out: list[MutationRequestSpec] = []
        for key, val in q:
            if val:
                alt = val + "_obs"
                new_q = [(k, alt if k == key else v) for k, v in q]
                new_url = urllib.parse.urlunparse(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        parts.params,
                        urllib.parse.urlencode(new_q),
                        parts.fragment,
                    )
                )
                out.append(MutationRequestSpec(label=f"string_append:{key}", url=new_url))
        return out[:2]


class NullInjectionSimulationStrategy(MutationStrategy):
    """Simulates empty/absent parameter values (behavioral, not injection exploits)."""

    name = "mutation.null_simulation"

    def apply(self, url: str) -> list[MutationRequestSpec]:
        parts = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not q:
            return []
        key, _ = q[0]
        new_q = [(k, "" if k == key else v) for k, v in q]
        new_url = urllib.parse.urlunparse(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                parts.params,
                urllib.parse.urlencode(new_q),
                parts.fragment,
            )
        )
        return [MutationRequestSpec(label=f"empty_value:{key}", url=new_url)]


class EncodingVariationStrategy(MutationStrategy):
    name = "mutation.encoding_variation"

    def apply(self, url: str) -> list[MutationRequestSpec]:
        parts = urllib.parse.urlparse(url)
        if not parts.query:
            return []
        encoded = urllib.parse.quote(parts.query, safe="=&")
        new_url = urllib.parse.urlunparse(
            (parts.scheme, parts.netloc, parts.path, parts.params, encoded, parts.fragment)
        )
        if new_url != url:
            return [MutationRequestSpec(label="query_reencoded", url=new_url)]
        return []


class MutationEngine:
    """Orchestrates built-in strategies and plugin-provided strategies."""

    __slots__ = ("_strategies",)

    def __init__(self, extra: list[MutationStrategy] | None = None) -> None:
        self._strategies: list[MutationStrategy] = [
            NumericVariationStrategy(),
            StringPerturbationStrategy(),
            NullInjectionSimulationStrategy(),
            EncodingVariationStrategy(),
        ]
        if extra:
            self._strategies.extend(extra)

    def collect_mutations(self, url: str) -> list[MutationRequestSpec]:
        specs: list[MutationRequestSpec] = []
        seen: set[str] = set()
        for strat in self._strategies:
            for spec in strat.apply(url):
                if spec.url not in seen:
                    seen.add(spec.url)
                    specs.append(spec)
        return specs
