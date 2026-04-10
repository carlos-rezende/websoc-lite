from __future__ import annotations

import hashlib
from collections.abc import Mapping


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def body_hash_normalized(text: str) -> str:
    """Canonical hash of response body for baseline comparison (UTF-8, replacement)."""
    return sha256_hex(text.encode("utf-8", errors="replace"))


def request_fingerprint(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body_bytes: bytes | None = None,
) -> str:
    """Stable hash for deduplicating logical requests within a run."""
    h_items = ""
    if headers:
        h_items = "|".join(f"{k.lower()}:{headers[k]}" for k in sorted(headers.keys()))
    bh = sha256_hex(body_bytes) if body_bytes else ""
    raw = f"{method.upper()}|{url}|{h_items}|{bh}"
    return sha256_hex(raw.encode("utf-8", errors="replace"))
