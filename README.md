# Security Observability Framework

Motor de **observabilidade de segurança** orientado a eventos para modelar aplicações web como sistemas dinâmicos e destacar anomalias por *diff* comportamental, pipelines e plugins. Não é scanner de vulnerabilidades nem ferramenta de pentest: foca em **comportamento**, baseline, perturbações controladas e sinais explicáveis.

## Objetivos

- Observabilidade comportamental (requisição/resposta, fingerprints, timeline de eventos).
- Pipelines assíncronos (`asyncio` + **httpx**), adequados a Raspberry Pi 5 (ARM64) e escaláveis.
- Extensão por plugins carregados dinamicamente, comunicando-se via **event bus** (sem acoplamento direto entre módulos).

## Arquitetura

### Camadas obrigatórias

| Camada | Função |
|--------|--------|
| **CLI** (`scanner/cli/main.py`) | `--url`, `--file`, `--config`, `--debug`, `--realtime`; inicializa `FrameworkRuntime`. |
| **Event Bus** (`scanner/core/event_bus.py`) | Eventos: `target_loaded`, `crawl_started`, `endpoint_discovered`, `request_sent`, `response_received`, `baseline_stored`, `mutation_applied`, `diff_computed`, `anomaly_detected`, `risk_scored`, `report_generated`. |
| **Pipeline** (`scanner/core/pipeline.py`) | Sequência formal: alvo → crawl → request → baseline → mutação → diff → análise → score → relatórios (via reporters). |
| **Request Engine** (`scanner/core/http.py`) | httpx com pool, retry, timeout, fingerprint de requisição. |
| **Telemetry Engine** (`scanner/core/telemetry.py`) | Metadados estruturados de request/response, tempo, tamanho e hash para observabilidade SOC. |
| **Baseline Engine** (`scanner/core/baseline.py`) | Metadados canônicos por endpoint (status, tamanho, hash do corpo, versão). |
| **Mutation Engine** (`scanner/core/mutation.py`) | Estratégias de perturbação (numérica, string, simulação de nulo, encoding) — **sem payloads de exploit**. |
| **Diff Engine** (`scanner/core/diff.py`) | Sinal estrutural, divergência semântica, variação de entropia, desvio de status. |
| **Risk Engine** (`scanner/core/risk.py`) | Score 0.0–1.0 com **fatores explicáveis**. |
| **Plugins** (`scanner/plugins/`) | Crawler, Analyzer, Mutation, Reporter — carregamento por dotted path. |
| **Reporting** (`scanner/reporting/json.py`, `html.py`) | JSON obrigatório; HTML como relatório complementar. |

### Princípios de design

- **Sem estado global mutável**: `FrameworkRuntime` instancia `EventBus`, plugins e engines por execução.
- **Comunicação por eventos**: núcleo e crawlers emitem eventos; analisadores consomem dados via pipeline (contratos em `scanner/plugins/protocols.py` para plugins).
- **Memória eficiente**: baseline armazena hashes e metadados, não duplica corpos inteiros desnecessariamente.

## Estrutura do repositório

```text
scanner/
├── core/
│   ├── engine.py
│   ├── event_bus.py
│   ├── pipeline.py
│   ├── http.py
│   ├── baseline.py
│   ├── diff.py
│   ├── risk.py
│   ├── mutation.py
│   └── models.py
├── crawler/
│   ├── base.py
│   ├── html.py
│   ├── seeder.py
│   └── playwright_stub.py
├── plugins/
│   ├── base.py
│   ├── loader.py
│   ├── manager.py
│   ├── protocols.py
│   ├── analyzers/
│   ├── crawlers/
│   ├── mutations/
│   └── reporters/
├── reporting/
│   ├── json.py
│   └── html.py
├── cli/
│   └── main.py
├── utils/
│   ├── logger.py
│   ├── config.py
│   └── hashing.py
├── extensions/
│   ├── README.md
│   ├── __init__.py
│   ├── base.py
│   ├── sandbox.py
│   └── latency_guard.py
panel/
└── app.py
docker/
├── observability.docker.json
└── scanner-entrypoint.sh
Dockerfile.panel
Dockerfile.scanner
docker-compose.panel.yml
docker-compose.full.yml
tests/
└── test_pipeline.py
```

## Instalação

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -e .
pip install -e ".[dev]"  # pytest (opcional)
```

Em **Raspberry Pi 5 (ARM64)**, prefira timeouts moderados, limite de endpoints (`--max-endpoints`) e ambiente virtual enxuto.

### Publicar no GitHub e clonar no Raspberry

No PC (primeira vez, pasta do projeto ainda sem Git):

```bash
cd /caminho/para/sistem
git init
git branch -M main
git add .
git commit -m "Initial commit: security observability framework"
```

No GitHub: crie um repositório vazio (sem README licenciado pelo site, se quiser evitar conflito), depois:

```bash
git remote add origin https://github.com/SEU_USUARIO/SEU_REPO.git
git push -u origin main
```

Use **SSH** (`git@github.com:...`) se preferir chave em vez de HTTPS.

No **Raspberry Pi** (Linux):

```bash
sudo apt update && sudo apt install -y git docker.io docker-compose-plugin
# ou: Docker conforme a documentação oficial para Debian/ARM64
git clone https://github.com/SEU_USUARIO/SEU_REPO.git
cd SEU_REPO
# Edite targets.txt com alvos autorizados; crie reports/ vazio se necessário:
mkdir -p reports
docker compose -f docker-compose.full.yml up -d --build
```

O `.gitignore` do projeto ignora `reports/`, caches Python e venv — relatórios gerados no Pi não entram no Git por acidente. Não commite URLs internas ou credenciais em `targets.txt`; use cópia local ou variáveis de ambiente conforme sua política.

## Uso

```bash
python -m scanner --url https://example.com
python -m scanner --url https://a.com --url https://b.com --output-dir reports
python -m scanner --file targets.txt --debug
python -m scanner --config observability.json --url https://example.com
python -m scanner --file targets.txt --stream-logs
python -m scanner --url https://example.com --realtime
python -m scanner --config observability.pi.json --file targets.txt --realtime
```

### Arquivo de configuração (`--config`)

JSON com campos opcionais de `AppConfig`, por exemplo:

```json
{
  "timeout_seconds": 10,
  "max_endpoints_per_target": 40,
  "enable_experimental_extensions": true,
  "experimental_extension_plugins": [
    "my_research_plugins.latency_probe.LatencyProbeExtension"
  ],
  "crawler_plugins": [
    "scanner.crawler.seeder.EndpointSeeder",
    "scanner.crawler.html.HTMLCrawler"
  ],
  "analyzer_plugins": [
    "scanner.plugins.analyzers.response_diff.ResponseDiffAnalyzer"
  ],
  "reporter_plugins": [
    "scanner.reporting.json.JSONReport"
  ],
  "mutation_plugins": [
    "scanner.plugins.mutations.extra_suffix.ExtraSuffixMutationPlugin"
  ]
}
```

Alvos podem vir do arquivo de config (`targets`) ou de `--url` / `--file` (CLI tem precedência quando informado).

## Guia de plugins

### Crawler (`CrawlerPlugin`)

- Implemente `async def crawl(self, target, bus, request_engine)`.
- **Não retorne listas**: emita `endpoint_discovered` para cada URL (`scanner.core.event_bus.ENDPOINT_DISCOVERED`).
- Dependa apenas de `EventEmitter` e `HTTPClientPort` (`protocols.py`).

**Exemplo:** `scanner/plugins/crawlers/simple_extra_path.py`

### Analyzer (`AnalyzerPlugin`)

- Implemente `analyze(..., risk_assessment=None)` retornando `list[Finding]`.
- Use `DiffSignal` e `RiskAssessment` para evidências e scores alinhados ao motor de risco.

**Exemplo:** `scanner/plugins/analyzers/simple_example.py`

### Mutation (`MutationPlugin`)

- Implemente `strategies()` retornando instâncias de `MutationStrategy` (`scanner.core.mutation`).
- Estratégias descrevem **perturbações controladas** (URLs alternativas, parâmetros), não exploits.

**Exemplo:** `scanner.plugins.mutations.extra_suffix.ExtraSuffixMutationPlugin`

### Reporter (`ReporterPlugin`)

- Implemente `async def emit(self, results, output_dir, *, timeline=None)`.
- JSON/HTML oficiais: `scanner.reporting.json.JSONReport`, `scanner.reporting.html.HTMLReport`.

**Exemplo:** `scanner/plugins/reporters/simple_echo.py`

Registre classes nos arrays correspondentes em `AppConfig` ou no JSON de configuração.

## Extensão

1. **Novo estágio de pipeline**: prefira subscrever eventos ou estender `ObservabilityPipeline` mantendo emissões padronizadas.
2. **Novo motor**: injete instâncias em `FrameworkRuntime` (fork) ou adicione um plugin que apenas reaja a eventos via `bus.subscribe`.
3. **Playwright / JS**: substitua ou estenda `PlaywrightCrawlerStub` por um crawler real, mantendo o contrato baseado em eventos.
4. **Exemplo experimental real**: `scanner.extensions.latency_guard.LatencyGuardExtension` (opt-in por config).

### Stream realtime para painel

Quando `--realtime` (ou `stream_logs: true`) está ativo, o scanner grava eventos em:

- `reports/realtime.ndjson` (configurável via `realtime_event_log_file`)

Isso permite que um painel web acompanhe o SOC em tempo real sem acoplar ao core.

## Painel web leve (Docker, ARM64)

Painel minimalista em `panel/app.py` (stdlib Python, sem dependências extras):

```bash
docker compose -f docker-compose.panel.yml up -d --build
```

Abrir no navegador:

- `http://<ip-do-raspberry>:8080`

APIs do painel:

- `GET /health`
- `GET /api/summary`
- `GET /api/events?limit=180`

### Stack completa (scanner contínuo + painel)

Orquestra **dois serviços**: `soc-scanner` (loop com intervalo configurável) e `soc-panel`, compartilhando `./reports` como `/data/reports`.

Pré-requisito: arquivo `targets.txt` na raiz do repositório (montado como somente leitura no container).

```bash
# Intervalo entre rodadas completas (padrão 300 s). Porta do painel opcional via PANEL_PORT.
export SCANNER_INTERVAL_SECONDS=600
export PANEL_PORT=8080
docker compose -f docker-compose.full.yml up -d --build
```

Abrir: `http://<ip-do-raspberry>:8080` (ou a porta definida em `PANEL_PORT`).

Variáveis úteis:

| Variável | Função |
|----------|--------|
| `SCANNER_INTERVAL_SECONDS` | Segundos entre cada execução completa do pipeline (padrão `300`). |
| `PANEL_PORT` | Porta publicada do painel no host (padrão `8080`). |
| `ANOMALY_THRESHOLD` | Limiar para contagem de anomalias no painel (padrão `0.35`). |

**Painel em zero durante o scan:** os cards antigos liam só `report.json`, que só é gravado **ao final** de cada ciclo completo. O painel atual agrega também `realtime.ndjson` (eventos ao vivo). Após atualizar o código, reconstrua a imagem do painel: `docker compose -f docker-compose.full.yml build soc-panel --no-cache && docker compose -f docker-compose.full.yml up -d`.

Execução única (sem loop), por exemplo para teste:

```bash
docker compose -f docker-compose.full.yml run --rm -e SCAN_ONCE=1 soc-scanner
```

Configuração Docker do scanner: `docker/observability.docker.json` (sem `output_dir` fixo; o entrypoint usa `--output-dir /data/reports`).

## Testes

```bash
python -m pytest tests/test_pipeline.py -v
```

## Segurança e ética

- Ferramenta de **pesquisa e observabilidade defensiva**; não inclui bibliotecas de exploit nem automação ofensiva.
- Perturbações são **modelos de variação de entrada** para medir estabilidade e diferenças de resposta, não vetores de ataque prontos.

## Licença de uso

Use em ambientes autorizados e em conformidade com políticas internas e leis aplicáveis.
