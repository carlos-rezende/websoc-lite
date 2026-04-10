"""Cliente mínimo da Docker Engine API via Unix socket (painel no mesmo host que o daemon)."""

from __future__ import annotations

import os
from typing import Any

_SOCK = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock").replace("unix://", "")
_API = os.environ.get("DOCKER_API_VERSION", "v1.43")


def _http() -> Any:
    import httpx

    return httpx.Client(transport=httpx.HTTPTransport(uds=_SOCK), timeout=60.0)


def docker_available() -> bool:
    return os.path.exists(_SOCK)


def container_inspect(name: str) -> dict[str, Any] | None:
    if not docker_available():
        return None
    try:
        with _http() as c:
            r = c.get(f"http://docker/{_API}/containers/{name}/json")
            if r.status_code != 200:
                return None
            return r.json()
    except Exception:
        return None


def container_state(name: str) -> tuple[str | None, bool | None]:
    """(status_text, running_or_none se desconhecido)."""
    data = container_inspect(name)
    if data is None:
        return "desconhecido", None
    st = data.get("State") or {}
    running = bool(st.get("Running"))
    status = str(st.get("Status", "unknown"))
    return status, running


def container_stop(name: str, *, timeout_sec: int = 15) -> tuple[bool, str]:
    if not docker_available():
        return False, "socket_docker_indisponivel"
    try:
        with _http() as c:
            r = c.post(f"http://docker/{_API}/containers/{name}/stop?t={timeout_sec}")
            if r.status_code in (204, 304):
                return True, "ok"
            if r.status_code == 404:
                return False, "container_nao_encontrado"
            return False, f"http_{r.status_code}:{r.text[:200]}"
    except Exception as exc:
        return False, str(exc)


def container_start(name: str) -> tuple[bool, str]:
    if not docker_available():
        return False, "socket_docker_indisponivel"
    try:
        with _http() as c:
            r = c.post(f"http://docker/{_API}/containers/{name}/start")
            if r.status_code in (204, 304):
                return True, "ok"
            if r.status_code == 404:
                return False, "container_nao_encontrado"
            return False, f"http_{r.status_code}:{r.text[:200]}"
    except Exception as exc:
        return False, str(exc)
