from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any

import httpx

from scanner.core.models import HTTPResult
from scanner.utils.hashing import request_fingerprint
from scanner.utils.hashing import body_hash_normalized


class RequestEngine:
    """Async HTTP layer: httpx connection pooling, retries, timeouts, request fingerprinting."""

    __slots__ = (
        "_client",
        "_timeout_seconds",
        "_retries",
        "_user_agent",
        "_seen_fingerprints",
    )

    def __init__(
        self,
        timeout_seconds: int = 8,
        retries: int = 2,
        user_agent: str = "security-observability-framework/1.0",
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._user_agent = user_agent
        self._client: httpx.AsyncClient | None = None
        self._seen_fingerprints: set[str] = set()

    async def __aenter__(self) -> RequestEngine:
        limits = httpx.Limits(max_connections=30, max_keepalive_connections=15)
        timeout = httpx.Timeout(float(self._timeout_seconds))
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": self._user_agent},
            limits=limits,
            follow_redirects=True,
            verify=True,
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self._seen_fingerprints.clear()

    def fingerprint_seen(self, fp: str) -> bool:
        if fp in self._seen_fingerprints:
            return True
        self._seen_fingerprints.add(fp)
        return False

    async def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> HTTPResult:
        if not self._client:
            raise RuntimeError("RequestEngine is not initialized; use async context manager.")

        hdrs = {k: str(v) for k, v in (headers or {}).items()}
        body_bytes: bytes | None = content
        if json_body is not None:
            import json as _json

            body_bytes = _json.dumps(json_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        elif data is not None:
            from urllib.parse import urlencode

            body_bytes = urlencode(dict(data)).encode("utf-8")

        fp = request_fingerprint(method, url, headers=hdrs, body_bytes=body_bytes)
        self.fingerprint_seen(fp)
        req_size = len(body_bytes or b"")

        last_error: str | None = None
        method_u = method.upper()
        for attempt in range(self._retries + 1):
            started = time.perf_counter()
            try:
                resp = await self._client.request(
                    method_u,
                    url,
                    headers=hdrs or None,
                    json=json_body if content is None and data is None else None,
                    data=data if json_body is None and content is None else None,
                    content=content,
                )
                text = resp.text
                elapsed_ms = (time.perf_counter() - started) * 1000
                return HTTPResult(
                    url=str(resp.url),
                    method=method_u,
                    status_code=resp.status_code,
                    headers={k: v for k, v in resp.headers.items()},
                    text=text,
                    elapsed_ms=elapsed_ms,
                    error=None,
                    request_fingerprint=fp,
                    response_hash=body_hash_normalized(text),
                    request_size=req_size,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                if attempt < self._retries:
                    await asyncio.sleep(0.25 * (attempt + 1))

        return HTTPResult(
            url=url,
            method=method_u,
            status_code=0,
            headers={},
            text="",
            elapsed_ms=0.0,
            error=last_error or "unknown_request_error",
            request_fingerprint=fp,
            response_hash="",
            request_size=req_size,
        )
