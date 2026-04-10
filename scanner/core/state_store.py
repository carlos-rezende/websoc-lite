"""Camada de estado persistente leve (SQLite) — escritas não bloqueantes via executor."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

from scanner.core.models import HTTPResult


class StateStore:
    """Snapshots de baseline, fingerprints, histórico de diff e risco (append-friendly)."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS baseline_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    version INTEGER,
                    status_code INTEGER,
                    body_hash TEXT,
                    response_size INTEGER,
                    UNIQUE(endpoint, version)
                );
                CREATE TABLE IF NOT EXISTS endpoint_fingerprints (
                    endpoint TEXT PRIMARY KEY,
                    request_fp TEXT,
                    last_seen_ts TEXT
                );
                CREATE TABLE IF NOT EXISTS diff_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    signal_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    target TEXT,
                    endpoint TEXT NOT NULL,
                    risk_score REAL,
                    factors_json TEXT
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    async def record_baseline_row(
        self,
        endpoint: str,
        *,
        version: int,
        status_code: int,
        body_hash: str,
        response_size: int,
        ts: str,
    ) -> None:
        def _w() -> None:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO baseline_snapshots
                    (ts, endpoint, version, status_code, body_hash, response_size)
                    VALUES (?,?,?,?,?,?)""",
                    (ts, endpoint, version, status_code, body_hash, response_size),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_w)

    async def record_fingerprint(self, endpoint: str, request_fp: str, ts: str) -> None:
        def _w() -> None:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO endpoint_fingerprints(endpoint, request_fp, last_seen_ts)
                    VALUES(?,?,?)
                    ON CONFLICT(endpoint) DO UPDATE SET request_fp=excluded.request_fp,
                    last_seen_ts=excluded.last_seen_ts""",
                    (endpoint, request_fp, ts),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_w)

    async def record_diff(self, endpoint: str, signal: dict[str, Any], ts: str) -> None:
        def _w() -> None:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO diff_history(ts, endpoint, signal_json) VALUES(?,?,?)",
                    (ts, endpoint, json.dumps(signal, ensure_ascii=True)),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_w)

    async def record_risk(
        self,
        endpoint: str,
        target: str,
        risk_score: float,
        factors: list[dict[str, Any]],
        ts: str,
    ) -> None:
        def _w() -> None:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO risk_history(ts, target, endpoint, risk_score, factors_json) VALUES(?,?,?,?,?)",
                    (ts, target, endpoint, risk_score, json.dumps(factors, ensure_ascii=True)),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_w)

    @staticmethod
    def fingerprint_from_result(result: HTTPResult) -> str:
        return result.request_fingerprint or ""
