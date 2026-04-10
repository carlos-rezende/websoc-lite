#!/usr/bin/env bash
# Inicia painel + scanner (stack completa). Execute na raiz do repositório clonado.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker não encontrado. Instale docker.io e o plugin compose."
  exit 1
fi

if [ ! -f targets.txt ]; then
  echo "Crie targets.txt com os alvos (um URL por linha)."
  exit 1
fi

mkdir -p reports

if [ ! -f .env ] && [ -z "${PANEL_CONTROL_TOKEN:-}" ]; then
  echo "Dica: crie .env com PANEL_CONTROL_TOKEN=uma_senha_forte para os botões Parar/Iniciar no painel."
fi

docker compose -f docker-compose.full.yml up -d --build

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "Painel:  http://${IP:-localhost}:${PANEL_PORT:-8080}"
echo "Relatórios em: $ROOT/reports/"
echo "Parar stack: docker compose -f docker-compose.full.yml down"
