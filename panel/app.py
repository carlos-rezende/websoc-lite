from __future__ import annotations

import json
import os
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/data/reports"))
REALTIME_FILE = os.environ.get("REALTIME_FILE", "realtime.ndjson")
HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.35"))
# Leitura incremental do NDJSON (evita ler arquivo inteiro a cada refresh no Pi)
TAIL_CHUNK_BYTES = int(os.environ.get("PANEL_TAIL_CHUNK_BYTES", "786432"))


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _tail_lines(path: Path, max_lines: int, chunk_bytes: int = TAIL_CHUNK_BYTES) -> list[str]:
    """Últimas N linhas: lê só o final do arquivo (Raspberry / logs longos)."""
    if not path.exists() or max_lines < 1:
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    chunk = min(chunk_bytes, size)
    with path.open("rb") as fh:
        fh.seek(size - chunk)
        data = fh.read(chunk)
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if chunk < size and lines:
        lines = lines[1:]
    return lines[-max_lines:]


def _read_events(path: Path, limit: int) -> list[dict]:
    lines = _tail_lines(path, limit)
    out: list[dict] = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _rollup_stream(path: Path, max_lines: int = 8000) -> dict[str, int | bool]:
    """Métricas ao vivo a partir do NDJSON (enquanto report.json ainda não existe)."""
    lines = _tail_lines(path, max_lines)
    if not lines:
        return {
            "stream_active": False,
            "stream_lines": 0,
            "stream_targets": 0,
            "stream_crawl": 0,
            "stream_endpoints": 0,
            "stream_diffs": 0,
            "stream_risk": 0,
            "stream_anomalies": 0,
            "stream_reports": 0,
        }
    targets: set[str] = set()
    evt = Counter()
    for line in lines:
        try:
            o = json.loads(line)
        except Exception:
            continue
        name = str(o.get("event", ""))
        evt[name] += 1
        if name == "target_loaded" and o.get("target"):
            targets.add(str(o["target"]))
    return {
        "stream_active": True,
        "stream_lines": len(lines),
        "stream_targets": len(targets),
        "stream_crawl": int(evt.get("crawl_started", 0)),
        "stream_endpoints": int(evt.get("endpoint_discovered", 0)),
        "stream_diffs": int(evt.get("diff_computed", 0)),
        "stream_risk": int(evt.get("risk_scored", 0)),
        "stream_anomalies": int(evt.get("anomaly_detected", 0)),
        "stream_reports": int(evt.get("report_generated", 0)),
    }


def _progress_estimate(live: dict[str, int | bool], report_ready: bool) -> tuple[int, str, bool]:
    """Percentual aproximado (0–100), fase legível, se ainda há atividade."""
    if report_ready:
        return 100, "Ciclo concluído (relatório disponível)", False
    if not live.get("stream_active"):
        return 0, "Aguardando eventos (scanner parado ou NDJSON vazio)", False
    rep = int(live.get("stream_reports", 0) or 0)
    diff = int(live.get("stream_diffs", 0) or 0)
    risk = int(live.get("stream_risk", 0) or 0)
    ep = int(live.get("stream_endpoints", 0) or 0)
    crawl = int(live.get("stream_crawl", 0) or 0)
    if rep > 0:
        return 97, "Gerando relatórios (JSON/HTML)", True
    if diff > 0 or risk > 0:
        step = max(diff, risk)
        pct = min(92, 22 + min(70, step * 2))
        return pct, "Pipeline por endpoint (diff / risco)", True
    if ep > 0:
        pct = min(28, 8 + min(20, ep // 3))
        return pct, "Descoberta de endpoints (crawl)", True
    if crawl > 0:
        return 12, "Crawl em execução", True
    return 6, "Alvo carregado / início do ciclo", True


def _summary() -> dict:
    nd_path = REPORTS_DIR / REALTIME_FILE
    live = _rollup_stream(nd_path)

    report = _read_json(REPORTS_DIR / "report.json")
    runs = report.get("runs", []) if isinstance(report, dict) else []
    findings = 0
    observations = 0
    anomalies = 0
    for run in runs:
        findings += len(run.get("findings", []))
        obs = run.get("observations", [])
        observations += len(obs)
        anomalies += sum(1 for o in obs if float(o.get("anomaly_score", 0.0)) >= ANOMALY_THRESHOLD)
    report_ready = bool(runs)
    pct, phase, busy = _progress_estimate(live, report_ready)
    hints = {
        "stop_scanner": os.environ.get(
            "PANEL_HINT_STOP",
            "docker compose -f docker-compose.full.yml stop soc-scanner",
        ),
        "start_scanner": os.environ.get(
            "PANEL_HINT_START",
            "docker compose -f docker-compose.full.yml up -d soc-scanner",
        ),
        "stop_all": os.environ.get(
            "PANEL_HINT_STOP_ALL",
            "docker compose -f docker-compose.full.yml down",
        ),
    }
    return {
        "runs": len(runs),
        "findings": findings,
        "observations": observations,
        "anomalies": anomalies,
        "reports_dir": str(REPORTS_DIR),
        "realtime_file": REALTIME_FILE,
        "report_ready": report_ready,
        "progress_pct": pct,
        "phase_label": phase,
        "scan_busy": busy,
        "hints": hints,
        **live,
    }


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SOC Lite Panel</title>
  <style>
    body { margin: 0; background: #0b1220; color: #d9e2f2; font-family: monospace; }
    .wrap { padding: 16px; max-width: 1200px; margin: 0 auto; }
    .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); }
    .card { background: #121b2f; border: 1px solid #27324b; border-radius: 8px; padding: 12px; }
    .v { font-size: 1.4rem; color: #8bd3ff; }
    .events { margin-top: 12px; background: #0f1729; border: 1px solid #27324b; border-radius: 8px; padding: 8px; height: 420px; overflow: auto; }
    .event { border-bottom: 1px solid #1d2a43; padding: 6px 0; }
    .evt { color: #ffd166; }
    .ts { color: #7f8ea6; }
    .progress-wrap { margin: 12px 0 16px 0; }
    .progress-meta { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px; font-size: 0.85rem; color: #94a3b8; }
    .progress { height: 12px; background: #1e293b; border-radius: 6px; overflow: hidden; border: 1px solid #334155; }
    .progress .fill { height: 100%; width: 0%; background: linear-gradient(90deg,#1d4ed8,#38bdf8); transition: width 0.45s ease; border-radius: 6px; }
    .progress .fill.pulsing { animation: progPulse 1.4s ease-in-out infinite; }
    @keyframes progPulse { 0%,100% { opacity: 1; filter: brightness(1); } 50% { opacity: 0.85; filter: brightness(1.15); } }
    .controls { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; align-items: center; }
    .controls button { background: #1e3a5f; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 8px 12px; cursor: pointer; font-family: inherit; font-size: 0.8rem; }
    .controls button:hover { background: #2563eb; border-color: #3b82f6; }
    .controls .note { font-size: 0.75rem; color: #64748b; max-width: 100%; }
  </style>
</head>
<body>
  <div class="wrap">
    <h2>SOC Lite Realtime Panel</h2>
    <p id="hint" style="color:#7f8ea6;font-size:0.85rem;margin:0 0 8px 0"></p>
    <div class="progress-wrap">
      <div class="progress-meta">
        <span id="phaseLabel">—</span>
        <span id="progressPct">0%</span>
      </div>
      <div class="progress" id="progressBar"><div class="fill" id="progressFill"></div></div>
    </div>
    <div class="controls">
      <button type="button" id="btnStop" title="Copia comando para o SSH">Parar scanner (copiar comando)</button>
      <button type="button" id="btnStart" title="Copia comando para o SSH">Iniciar scanner (copiar)</button>
      <button type="button" id="btnDown" title="Copia comando para o SSH">Parar stack (down)</button>
      <span class="note" id="copyFeedback"></span>
    </div>
    <p class="note" style="margin:0 0 8px 0">O painel não controla o Docker por segurança; use os botões para copiar e colar no terminal do Raspberry.</p>
    <div class="grid">
      <div class="card"><div>Alvos (stream)</div><div class="v" id="runs">0</div></div>
      <div class="card"><div>Endpoints (stream)</div><div class="v" id="obs">0</div></div>
      <div class="card"><div>Anomalias (stream)</div><div class="v" id="ano">0</div></div>
      <div class="card"><div>Findings (relatório)</div><div class="v" id="fin">0</div></div>
    </div>
    <div class="events" id="events"></div>
  </div>
  <script>
    function esc(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    /** URL sem user:pass (fetch falha se a página foi aberta como http://user:pass@host/...) */
    function apiUrl(path) {
      var p = path.charAt(0) === '/' ? path : '/' + path;
      return location.protocol + '//' + location.host + p;
    }
    var lastHints = {};
    function copyHint(key) {
      var t = (lastHints && lastHints[key]) ? String(lastHints[key]) : '';
      if (!t) { document.getElementById('copyFeedback').textContent = 'Sem comando.'; return; }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(t).then(function() {
          document.getElementById('copyFeedback').textContent = 'Copiado. Cole no SSH na pasta do projeto.';
          setTimeout(function(){ document.getElementById('copyFeedback').textContent = ''; }, 4000);
        }).catch(function(){ document.getElementById('copyFeedback').textContent = 'Copie manualmente: ' + t; });
      } else {
        document.getElementById('copyFeedback').textContent = t;
      }
    }
    document.getElementById('btnStop').addEventListener('click', function(){ copyHint('stop_scanner'); });
    document.getElementById('btnStart').addEventListener('click', function(){ copyHint('start_scanner'); });
    document.getElementById('btnDown').addEventListener('click', function(){ copyHint('stop_all'); });
    async function refresh() {
      try {
        const s = await fetch(apiUrl('/api/summary')).then(r => r.json());
        const ev = await fetch(apiUrl('/api/events?limit=180')).then(r => r.json());
        lastHints = s.hints || {};
        var pct = Math.max(0, Math.min(100, parseInt(s.progress_pct, 10) || 0));
        document.getElementById('progressPct').textContent = pct + '%';
        document.getElementById('phaseLabel').textContent = s.phase_label || '—';
        var fill = document.getElementById('progressFill');
        fill.style.width = pct + '%';
        fill.className = 'fill' + ((s.scan_busy && pct > 0 && pct < 100) ? ' pulsing' : '');
        document.getElementById('runs').textContent = s.stream_targets ?? 0;
        document.getElementById('obs').textContent = s.stream_endpoints ?? 0;
        document.getElementById('ano').textContent = s.stream_anomalies ?? 0;
        document.getElementById('fin').textContent = s.findings ?? 0;
        var hint = 'Runs no relatório: ' + (s.runs ?? 0);
        if (!s.report_ready) hint += ' — relatório JSON/HTML só após terminar um ciclo completo do scanner.';
        hint += ' | NDJSON ~' + (s.stream_lines ?? 0) + ' linhas (janela)';
        document.getElementById('hint').textContent = hint;
        const box = document.getElementById('events');
        const rows = (ev.events || []).map(function(e) {
          var ep = (e.endpoint != null && String(e.endpoint)) ? String(e.endpoint) : '';
          return '<div class="event"><span class="ts">' + esc(e.ts || '') + '</span> <span class="evt">' + esc(e.event || '') + '</span> ' + esc(ep) + '</div>';
        });
        box.innerHTML = rows.join('');
        box.scrollTop = box.scrollHeight;
      } catch (e) {
        document.getElementById('hint').textContent = 'Erro ao buscar API: ' + e;
      }
    }
    refresh();
    setInterval(refresh, 1500);
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._text(200, INDEX_HTML, content_type="text/html; charset=utf-8")
            return
        if parsed.path == "/health":
            self._json(200, {"ok": True})
            return
        if parsed.path == "/api/summary":
            self._json(200, _summary())
            return
        if parsed.path == "/api/events":
            qs = parse_qs(parsed.query)
            limit = int((qs.get("limit", ["200"])[0]))
            limit = max(1, min(limit, 2000))
            events = _read_events(REPORTS_DIR / REALTIME_FILE, limit)
            self._json(200, {"events": events})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _json(self, status: int, payload: dict) -> None:
        self._text(status, json.dumps(payload, ensure_ascii=True), content_type="application/json")

    def _text(self, status: int, body: str, *, content_type: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"soc-lite-panel listening on http://{HOST}:{PORT} reports_dir={REPORTS_DIR}")  # noqa: T201
    server.serve_forever()


if __name__ == "__main__":
    main()
