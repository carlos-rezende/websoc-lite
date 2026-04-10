#!/usr/bin/env bash
set -euo pipefail

OUT="${OUTPUT_DIR:-/data/reports}"
CFG="${SCANNER_CONFIG:-/app/docker/observability.docker.json}"
TGT="${TARGETS_FILE:-/data/targets.txt}"
INTERVAL="${SCANNER_INTERVAL_SECONDS:-300}"

run_once() {
  # shellcheck disable=SC2086
  python -m scanner \
    --config "$CFG" \
    --file "$TGT" \
    --output-dir "$OUT" \
    --realtime \
    ${SCANNER_EXTRA_ARGS:-}
}

if [ "${SCAN_ONCE:-0}" = "1" ]; then
  echo "[soc-scanner] $(date -Iseconds) single run (SCAN_ONCE=1)"
  run_once
  exit 0
fi

echo "[soc-scanner] continuous mode interval=${INTERVAL}s output=${OUT} targets=${TGT}"
while true; do
  echo "[soc-scanner] $(date -Iseconds) starting run"
  run_once || echo "[soc-scanner] run exited with code $?"
  echo "[soc-scanner] sleeping ${INTERVAL}s"
  sleep "$INTERVAL"
done
