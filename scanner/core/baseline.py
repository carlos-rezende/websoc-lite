from __future__ import annotations

from scanner.core.models import BaselineRecord, HTTPResult
from scanner.utils.hashing import body_hash_normalized


def endpoint_key(url: str) -> str:
    """Stable key for baseline storage (full URL string)."""
    return url.strip()


class BaselineEngine:
    """Stateful memory: canonical response metadata per endpoint with incremental versioning."""

    __slots__ = ("_store",)

    def __init__(self) -> None:
        self._store: dict[str, BaselineRecord] = {}

    def store_from_response(self, url: str, result: HTTPResult) -> BaselineRecord:
        key = endpoint_key(url)
        bh = body_hash_normalized(result.text)
        if key in self._store:
            prev = self._store[key]
            if prev.body_hash == bh and prev.status_code == result.status_code:
                return prev
            rec = BaselineRecord(
                endpoint_key=key,
                status_code=result.status_code,
                response_size=result.size,
                body_hash=bh,
                version=prev.version + 1,
            )
            self._store[key] = rec
            return rec
        rec = BaselineRecord(
            endpoint_key=key,
            status_code=result.status_code,
            response_size=result.size,
            body_hash=bh,
            version=1,
        )
        self._store[key] = rec
        return rec

    def get(self, url: str) -> BaselineRecord | None:
        return self._store.get(endpoint_key(url))
