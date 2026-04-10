from __future__ import annotations

from html import escape
from pathlib import Path

from scanner.core.models import ScanResult
from scanner.plugins.base import ReporterPlugin


class HTMLReport(ReporterPlugin):
    name = "reporter.html"

    async def emit(
        self,
        results: list[ScanResult],
        output_dir: str,
        *,
        timeline: list[dict[str, object]] | None = None,
        incidents: list[dict[str, object]] | None = None,
    ) -> str:
        output_path = Path(output_dir) / "report.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        inc_html = ""
        if incidents:
            inc_rows = "".join(
                f"""
                <tr>
                    <td>{escape(str(x.get("incident_id", "")))}</td>
                    <td>{escape(str(x.get("pattern", "")))}</td>
                    <td>{escape(str(x.get("severity_score", "")))}</td>
                    <td><pre>{escape(str(x.get("affected_endpoints", [])))}</pre></td>
                </tr>
                """
                for x in incidents[:50]
            )
            inc_html = f"""
            <section>
                <h2>Incident clusters (correlação)</h2>
                <table>
                    <thead><tr><th>ID</th><th>Padrão</th><th>Severidade</th><th>Endpoints</th></tr></thead>
                    <tbody>{inc_rows}</tbody>
                </table>
            </section>
            """

        blocks: list[str] = []
        for result in results:
            findings_html = "".join(
                f"""
                <tr>
                    <td>{escape(f.endpoint)}</td>
                    <td>{escape(f.title)}</td>
                    <td>{f.risk_score:.2f}</td>
                    <td><pre>{escape(str(f.evidence))}</pre></td>
                </tr>
                """
                for f in result.findings
            )
            obs_rows = "".join(
                f"""
                <tr>
                    <td>{escape(o.endpoint)}</td>
                    <td>{o.anomaly_score:.2f}</td>
                    <td><pre>{escape(str(o.signal))}</pre></td>
                </tr>
                """
                for o in result.observations
            )
            hyp_rows = "".join(
                f"""
                <tr>
                    <td>{escape(h.statement[:200])}</td>
                    <td>{h.confidence:.2f}</td>
                    <td><pre>{escape(str(h.recommended_verification_steps))}</pre></td>
                </tr>
                """
                for h in result.hypotheses
            )
            blocks.append(
                f"""
                <section>
                    <h2>{escape(result.target)}</h2>
                    <p>Endpoints: {len(result.crawled_endpoints)} | Hipóteses: {len(result.hypotheses)} | Findings: {len(result.findings)}</p>
                    <h3>Hipóteses (validação manual)</h3>
                    <table>
                        <thead><tr><th>Enunciado</th><th>Confiança</th><th>Passos sugeridos</th></tr></thead>
                        <tbody>{hyp_rows}</tbody>
                    </table>
                    <h3>Observações por endpoint</h3>
                    <table>
                        <thead><tr><th>Endpoint</th><th>Anomalia</th><th>Signal</th></tr></thead>
                        <tbody>{obs_rows}</tbody>
                    </table>
                    <h3>Findings de plugins</h3>
                    <table>
                        <thead><tr><th>Endpoint</th><th>Finding</th><th>Risk</th><th>Evidence</th></tr></thead>
                        <tbody>{findings_html}</tbody>
                    </table>
                </section>
                """
            )

        tl = timeline or []
        tl_html = "".join(f"<li><code>{escape(str(e))}</code></li>" for e in tl[:200])

        html_doc = f"""
        <!doctype html>
        <html lang="pt">
        <head>
            <meta charset="utf-8" />
            <title>Security Observability Report</title>
            <style>
                body {{ font-family: sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
                section {{ margin-bottom: 2rem; background: #1e293b; padding: 1rem; border-radius: 8px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #334155; padding: 0.5rem; vertical-align: top; }}
                th {{ background: #334155; }}
                pre {{ white-space: pre-wrap; margin: 0; font-size: 0.85rem; }}
                ul {{ max-height: 24rem; overflow: auto; }}
            </style>
        </head>
        <body>
            <h1>Relatório de observabilidade de segurança</h1>
            {inc_html}
            {"".join(blocks)}
            <section>
                <h2>Amostra da timeline de eventos</h2>
                <ul>{tl_html}</ul>
            </section>
        </body>
        </html>
        """
        output_path.write_text(html_doc, encoding="utf-8")
        return str(output_path)
