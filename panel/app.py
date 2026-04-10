from __future__ import annotations

import json
import os
import sys
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

_PANEL_DIR = Path(__file__).resolve().parent
if str(_PANEL_DIR) not in sys.path:
    sys.path.insert(0, str(_PANEL_DIR))

from docker_api import container_start, container_stop, container_state, docker_available

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/data/reports"))
REALTIME_FILE = os.environ.get("REALTIME_FILE", "realtime.ndjson")
SCANNER_CONTAINER = os.environ.get("SCANNER_CONTAINER_NAME", "soc-scanner")
HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.35"))
TAIL_CHUNK_BYTES = int(os.environ.get("PANEL_TAIL_CHUNK_BYTES", "786432"))

ALLOWED_DOWNLOADS = frozenset({"report.json", "report.html", "realtime.ndjson"})


def _control_token_configured() -> bool:
    return bool(os.environ.get("PANEL_CONTROL_TOKEN", "").strip())


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _tail_lines(path: Path, max_lines: int, chunk_bytes: int = TAIL_CHUNK_BYTES) -> list[str]:
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


def _last_event_detail(nd_path: Path) -> dict[str, str | None]:
    lines = _tail_lines(nd_path, 1)
    if not lines:
        return {"last_event": None, "last_ts": None, "last_endpoint": None}
    try:
        o = json.loads(lines[-1])
    except Exception:
        return {"last_event": None, "last_ts": None, "last_endpoint": None}
    ep = o.get("endpoint")
    if ep is None and isinstance(o.get("telemetry"), dict):
        ep = (o["telemetry"].get("response") or {}).get("url") or o["telemetry"].get("endpoint")
    return {
        "last_event": str(o.get("event", "")) or None,
        "last_ts": str(o.get("ts", "")) or None,
        "last_endpoint": str(ep) if ep else None,
    }


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


def _progress_estimate(
    live: dict[str, int | bool],
    report_ready: bool,
    scanner_running: bool | None,
    last_event: str | None,
) -> tuple[int, str, bool]:
    if scanner_running is False:
        return 0, "Pesquisa parada (container " + SCANNER_CONTAINER + ")", False
    if report_ready:
        return 100, "Ciclo concluído (relatório disponível)", False
    if not live.get("stream_active"):
        if scanner_running is True:
            return 4, "Scanner a iniciar / à espera de eventos no NDJSON", True
        return 0, "Sem atividade recente no stream (Docker indisponível ou NDJSON vazio)", False
    rep = int(live.get("stream_reports", 0) or 0)
    diff = int(live.get("stream_diffs", 0) or 0)
    risk = int(live.get("stream_risk", 0) or 0)
    ep = int(live.get("stream_endpoints", 0) or 0)
    crawl = int(live.get("stream_crawl", 0) or 0)
    tail = ""
    if last_event:
        tail = f" · último evento: {last_event}"
    if rep > 0:
        return 97, "Gerando relatórios (JSON/HTML)" + tail, True
    if diff > 0 or risk > 0:
        step = max(diff, risk)
        pct = min(92, 22 + min(70, step * 2))
        return pct, "Pipeline por endpoint (diff / risco)" + tail, True
    if ep > 0:
        pct = min(28, 8 + min(20, ep // 3))
        return pct, "Descoberta de endpoints (crawl)" + tail, True
    if crawl > 0:
        return 12, "Crawl em execução" + tail, True
    return 6, "Início do ciclo / alvo carregado" + tail, True


def _docker_snapshot() -> dict[str, bool | str | None]:
    if not docker_available():
        return {
            "docker_socket_ok": False,
            "scanner_running": None,
            "scanner_status": "socket ausente",
        }
    status, running = container_state(SCANNER_CONTAINER)
    return {
        "docker_socket_ok": True,
        "scanner_running": running,
        "scanner_status": status,
    }


def _summary() -> dict:
    nd_path = REPORTS_DIR / REALTIME_FILE
    live = _rollup_stream(nd_path)
    last_d = _last_event_detail(nd_path)
    dk = _docker_snapshot()

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
    scanner_running = dk.get("scanner_running")
    if not isinstance(scanner_running, (bool, type(None))):
        scanner_running = None

    pct, phase, busy = _progress_estimate(
        live,
        report_ready,
        scanner_running if isinstance(scanner_running, (bool, type(None))) else None,
        last_d.get("last_event"),
    )

    control_ok = _control_token_configured() and dk.get("docker_socket_ok") is True
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

    status_line_parts: list[str] = []
    if dk.get("docker_socket_ok"):
        sr = dk.get("scanner_running")
        if sr is True:
            status_line_parts.append("Scanner: em execução")
        elif sr is False:
            status_line_parts.append("Scanner: parado")
        else:
            status_line_parts.append("Scanner: estado desconhecido")
        if dk.get("scanner_status"):
            status_line_parts.append(f"({dk['scanner_status']})")
    else:
        status_line_parts.append("Docker: socket não montado no painel")
    if last_d.get("last_event"):
        status_line_parts.append(f"Último evento: {last_d['last_event']}")
    if last_d.get("last_ts"):
        status_line_parts.append(f"@ {last_d['last_ts']}")

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
        "status_line": " · ".join(status_line_parts),
        "control_available": control_ok,
        "control_needs_token": not _control_token_configured(),
        "scanner_container": SCANNER_CONTAINER,
        "hints": hints,
        **last_d,
        **dk,
        **live,
    }


INDEX_HTML = """<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SOC Lite Panel</title>
  <style>
    body { margin: 0; background: #0b1220; color: #d9e2f2; font-family: ui-monospace, monospace; }
    .wrap { padding: 16px; max-width: 1200px; margin: 0 auto; }
    .statusbar { background: #111827; border: 1px solid #334155; border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; font-size: 0.8rem; color: #94a3b8; line-height: 1.5; }
    .statusbar strong { color: #e2e8f0; }
    .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); }
    .card { background: #121b2f; border: 1px solid #27324b; border-radius: 8px; padding: 12px; }
    .v { font-size: 1.4rem; color: #8bd3ff; }
    .events { margin-top: 12px; background: #0f1729; border: 1px solid #27324b; border-radius: 8px; padding: 8px; height: 380px; overflow: auto; }
    .event { border-bottom: 1px solid #1d2a43; padding: 6px 0; font-size: 0.8rem; }
    .evt { color: #ffd166; }
    .ts { color: #7f8ea6; }
    .progress-wrap { margin: 12px 0 16px 0; }
    .progress-meta { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px; font-size: 0.85rem; color: #94a3b8; flex-wrap: wrap; gap: 8px; }
    .progress { height: 12px; background: #1e293b; border-radius: 6px; overflow: hidden; border: 1px solid #334155; }
    .progress .fill { height: 100%; width: 0%; background: linear-gradient(90deg,#1d4ed8,#38bdf8); transition: width 0.45s ease; border-radius: 6px; }
    .progress .fill.pulsing { animation: progPulse 1.4s ease-in-out infinite; }
    .progress .fill.stopped { background: #475569; }
    @keyframes progPulse { 0%,100% { opacity: 1; } 50% { opacity: 0.82; } }
    .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 12px 0; }
    .row input[type=password] { background: #1e293b; border: 1px solid #475569; color: #e2e8f0; padding: 6px 10px; border-radius: 6px; width: 200px; font-family: inherit; }
    button { background: #1e3a5f; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 8px 14px; cursor: pointer; font-family: inherit; font-size: 0.8rem; }
    button:hover { background: #2563eb; border-color: #3b82f6; }
    button.danger { background: #7f1d1d; border-color: #991b1b; }
    button.danger:hover { background: #b91c1c; }
    button.ok { background: #14532d; border-color: #166534; }
    button.ok:hover { background: #15803d; }
    .downloads a { color: #7dd3fc; margin-right: 12px; font-size: 0.85rem; }
    .note { font-size: 0.75rem; color: #64748b; }
    #msg { font-size: 0.8rem; color: #fbbf24; min-height: 1.2em; }
  </style>
</head>
<body>
  <div class="wrap">
    <h2>SOC Lite — Painel</h2>
    <div class="statusbar" id="statusBar"><strong>Estado:</strong> …</div>
    <p id="hint" class="note" style="margin:0 0 8px 0"></p>
    <div class="progress-wrap">
      <div class="progress-meta">
        <span id="phaseLabel">—</span>
        <span id="progressPct">0%</span>
      </div>
      <div class="progress"><div class="fill" id="progressFill"></div></div>
    </div>
    <div class="row">
      <label class="note">Token</label>
      <input type="password" id="ctrlToken" placeholder="PANEL_CONTROL_TOKEN" autocomplete="off" />
      <button type="button" id="btnSaveTok">Guardar no browser</button>
    </div>
    <div class="row">
      <button type="button" class="danger" id="btnStopRun">Encerrar pesquisa</button>
      <button type="button" class="ok" id="btnStartRun">Iniciar pesquisa</button>
      <span id="msg"></span>
    </div>
    <p class="downloads">
      <span class="note">Relatórios:</span>
      <a href="#" id="dlJson">report.json</a>
      <a href="#" id="dlHtml">report.html</a>
      <a href="#" id="dlNdjson">realtime.ndjson</a>
    </p>
    <p class="note" id="copyFallback"></p>
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
    function apiUrl(path) {
      var p = path.charAt(0) === '/' ? path : '/' + path;
      return location.protocol + '//' + location.host + p;
    }
    function getTok() {
      return (document.getElementById('ctrlToken').value || localStorage.getItem('soc_control_token') || '').trim();
    }
    document.getElementById('btnSaveTok').addEventListener('click', function() {
      var t = document.getElementById('ctrlToken').value.trim();
      if (t) localStorage.setItem('soc_control_token', t);
      document.getElementById('msg').textContent = 'Token guardado neste browser.';
      setTimeout(function(){ document.getElementById('msg').textContent=''; }, 3000);
    });
    if (localStorage.getItem('soc_control_token')) {
      document.getElementById('ctrlToken').placeholder = '(token guardado — introduza de novo para alterar)';
    }
    function setDownloadLinks() {
      document.getElementById('dlJson').href = apiUrl('/api/download/report.json');
      document.getElementById('dlHtml').href = apiUrl('/api/download/report.html');
      document.getElementById('dlNdjson').href = apiUrl('/api/download/realtime.ndjson');
    }
    setDownloadLinks();
    async function postControl(action) {
      var tok = getTok();
      if (!tok) {
        document.getElementById('msg').textContent = 'Introduza o token (mesmo que PANEL_CONTROL_TOKEN no .env).';
        return;
      }
      document.getElementById('msg').textContent = 'A enviar…';
      try {
        var r = await fetch(apiUrl('/api/control/' + action), {
          method: 'POST',
          headers: { 'X-Control-Token': tok, 'Content-Type': 'application/json' },
          body: '{}'
        });
        var j = await r.json().catch(function(){ return {}; });
        if (r.ok) {
          document.getElementById('msg').textContent = j.message || 'OK';
        } else {
          document.getElementById('msg').textContent = (j.error || j.detail || 'Erro') + ' (' + r.status + ')';
        }
      } catch (e) {
        document.getElementById('msg').textContent = String(e);
      }
      setTimeout(function(){ refresh(); }, 800);
    }
    document.getElementById('btnStopRun').addEventListener('click', function(){ postControl('stop'); });
    document.getElementById('btnStartRun').addEventListener('click', function(){ postControl('start'); });
    async function refresh() {
      try {
        const s = await fetch(apiUrl('/api/summary')).then(r => r.json());
        const ev = await fetch(apiUrl('/api/events?limit=180')).then(r => r.json());
        document.getElementById('statusBar').innerHTML = '<strong>Estado:</strong> ' + esc(s.status_line || '—');
        var pct = Math.max(0, Math.min(100, parseInt(s.progress_pct, 10) || 0));
        document.getElementById('progressPct').textContent = pct + '%';
        document.getElementById('phaseLabel').textContent = s.phase_label || '—';
        var fill = document.getElementById('progressFill');
        fill.style.width = pct + '%';
        fill.className = 'fill';
        if (s.scanner_running === false) fill.classList.add('stopped');
        else if (s.scan_busy && pct > 0 && pct < 100) fill.classList.add('pulsing');
        document.getElementById('runs').textContent = s.stream_targets ?? 0;
        document.getElementById('obs').textContent = s.stream_endpoints ?? 0;
        document.getElementById('ano').textContent = s.stream_anomalies ?? 0;
        document.getElementById('fin').textContent = s.findings ?? 0;
        var hint = 'Runs no relatório: ' + (s.runs ?? 0);
        if (!s.report_ready) hint += ' — JSON/HTML após cada ciclo completo.';
        hint += ' | NDJSON ~' + (s.stream_lines ?? 0) + ' linhas';
        if (s.control_needs_token) hint += ' | Defina PANEL_CONTROL_TOKEN no .env para controlar o scanner.';
        else if (!s.docker_socket_ok) hint += ' | Monte /var/run/docker.sock no painel para controlos reais.';
        else if (!s.control_available) hint += ' | Controlos: token + Docker.';
        document.getElementById('hint').textContent = hint;
        var cf = '';
        if (s.control_needs_token || !s.docker_socket_ok) {
          var h = s.hints || {};
          cf = 'Comando manual parar: ' + (h.stop_scanner || '') + ' | iniciar: ' + (h.start_scanner || '');
        }
        document.getElementById('copyFallback').textContent = cf;
        const box = document.getElementById('events');
        const rows = (ev.events || []).map(function(e) {
          var ep = (e.endpoint != null && String(e.endpoint)) ? String(e.endpoint) : '';
          return '<div class="event"><span class="ts">' + esc(e.ts || '') + '</span> <span class="evt">' + esc(e.event || '') + '</span> ' + esc(ep) + '</div>';
        });
        box.innerHTML = rows.join('');
        box.scrollTop = box.scrollHeight;
      } catch (e) {
        document.getElementById('hint').textContent = 'Erro: ' + e;
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
        if parsed.path.startswith("/api/download/"):
            name = unquote(parsed.path[len("/api/download/") :]).strip()
            base = Path(name).name
            if base not in ALLOWED_DOWNLOADS:
                self._json(404, {"error": "ficheiro não permitido"})
                return
            fpath = REPORTS_DIR / base
            if not fpath.is_file():
                self._json(404, {"error": "ainda não existe", "file": base})
                return
            try:
                data = fpath.read_bytes()
            except OSError:
                self._json(500, {"error": "leitura falhou"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{base}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in ("/api/control/stop", "/api/control/start"):
            self._json(404, {"error": "not found"})
            return
        if not _control_token_configured():
            self._json(503, {"error": "PANEL_CONTROL_TOKEN não configurado no painel"})
            return
        token = self.headers.get("X-Control-Token", "").strip()
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
        if token != os.environ.get("PANEL_CONTROL_TOKEN", "").strip():
            self._json(403, {"error": "token inválido"})
            return
        if not docker_available():
            self._json(503, {"error": "Docker socket não disponível no painel"})
            return

        action = "stop" if parsed.path.endswith("/stop") else "start"
        if action == "stop":
            ok, detail = container_stop(SCANNER_CONTAINER)
        else:
            ok, detail = container_start(SCANNER_CONTAINER)
        if ok:
            self._json(200, {"ok": True, "message": "Scanner " + ("parado" if action == "stop" else "iniciado"), "detail": detail})
        else:
            self._json(500, {"ok": False, "error": detail})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=True)
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
