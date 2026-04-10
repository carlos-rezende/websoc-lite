from __future__ import annotations

import argparse
import asyncio
import json
import logging
from dataclasses import replace
from pathlib import Path

from scanner.core.engine import FrameworkRuntime
from scanner.utils.config import AppConfig, merge_config_from_file
from scanner.utils.logger import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security Observability Framework")
    parser.add_argument("--url", action="append", help="Target URL (can be repeated)")
    parser.add_argument("--file", help="File containing targets (one per line)")
    parser.add_argument("--config", help="JSON configuration file (plugins, timeouts, etc.)")
    parser.add_argument("--output-dir", default="reports", help="Output folder for reports")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Retry count")
    parser.add_argument("--debug", action="store_true", help="Enable debug logs")
    parser.add_argument("--max-endpoints", type=int, default=80, help="Endpoint cap per target")
    parser.add_argument("--stream-logs", action="store_true", help="Stream pipeline events to logs")
    parser.add_argument("--realtime", action="store_true", help="Alias for --stream-logs (SOC realtime event stream)")
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="Imprime métricas SOC v2 para stdout e grava metrics.json no output-dir",
    )
    parser.add_argument(
        "--lab-mode",
        action="store_true",
        help="Modo laboratório (opt-in): campanha segura por URL, telemetria NDJSON — não executa o pipeline principal",
    )
    return parser.parse_args()


def load_targets(urls: list[str] | None, file_path: str | None) -> list[str]:
    targets = set(urls or [])
    if file_path:
        path = Path(file_path)
        if path.exists():
            lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
            targets.update(line for line in lines if line and not line.startswith("#"))

    return sorted(targets)


def build_config(args: argparse.Namespace) -> AppConfig:
    base = AppConfig(
        targets=[],
        output_dir=args.output_dir,
        timeout_seconds=args.timeout,
        retries=args.retries,
        debug=args.debug,
        max_endpoints_per_target=args.max_endpoints,
        stream_logs=args.stream_logs or args.realtime,
        lab_mode=getattr(args, "lab_mode", False),
    )
    base = merge_config_from_file(getattr(args, "config", None), base)
    targets = load_targets(args.url, args.file)
    if not targets:
        targets = list(base.targets)
    if not targets:
        raw = input("Enter target URLs separated by comma: ").strip()
        if raw:
            targets = sorted(x.strip() for x in raw.split(",") if x.strip())

    if not targets:
        raise ValueError("No targets provided. Use --url, --file, config targets, or interactive input.")

    return replace(base, targets=targets)


async def _async_main(args: argparse.Namespace) -> list[str]:
    config = build_config(args)
    if config.lab_mode:
        from scanner.extensions.lab.runner import run_lab_mode

        return await run_lab_mode(config)

    runtime = FrameworkRuntime(config)
    outputs = await runtime.run()
    if args.metrics:
        print(json.dumps(runtime.metrics.to_dict(), indent=2))
        if config.metrics_file:
            p = Path(config.output_dir) / config.metrics_file
            runtime.metrics.dump_json(p)
            logger.info("metrics written path=%s", p)
    return outputs


def main() -> int:
    args = parse_args()
    configure_logging(debug=args.debug)
    try:
        outputs = asyncio.run(_async_main(args))
    except Exception as exc:  # noqa: BLE001
        logger.exception("execution failed error=%s", exc)
        return 1

    for path in outputs:
        logger.info("report generated path=%s", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
