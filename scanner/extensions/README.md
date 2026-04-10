# Experimental Extensions (Isolated)

Este diretório é reservado para plugins de pesquisa e protótipos experimentais.

Regras de segurança:

- Não é importado automaticamente pelo core.
- Só é ativado quando `enable_experimental_extensions: true` no config.
- Deve operar em isolamento, sem compartilhar estado mutável com o runtime principal.

Uso sugerido no config:

```json
{
  "enable_experimental_extensions": true,
  "experimental_extension_plugins": [
    "scanner.extensions.latency_guard.LatencyGuardExtension"
  ]
}
```
