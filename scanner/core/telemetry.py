from __future__ import annotations

from typing import Any

from scanner.core.models import HTTPResult


class TelemetryEngine:
    """Builds SOC-friendly request/response telemetry payloads."""

    def build_request_telemetry(
        self,
        *,
        target: str,
        endpoint: str,
        method: str,
        phase: str,
        request_fingerprint: str,
        request_size: int,
    ) -> dict[str, Any]:
        return {
            "target": target,
            "endpoint": endpoint,
            "phase": phase,
            "method": method,
            "telemetry": {
                "request": {
                    "fingerprint": request_fingerprint,
                    "size": request_size,
                }
            },
        }

    def build_response_telemetry(
        self,
        *,
        target: str,
        endpoint: str,
        phase: str,
        result: HTTPResult,
    ) -> dict[str, Any]:
        return {
            "target": target,
            "endpoint": endpoint,
            "phase": phase,
            "telemetry": {
                "request": {
                    "fingerprint": result.request_fingerprint,
                    "size": result.request_size,
                },
                "response": {
                    "status_code": result.status_code,
                    "elapsed_ms": round(result.elapsed_ms, 2),
                    "size": result.size,
                    "hash": result.response_hash,
                    "content_type_fingerprint": result.content_type,
                    "headers_snapshot": dict(list(result.headers.items())[:24]),
                    "error": result.error,
                },
            },
        }
