from __future__ import annotations

from html import escape
from pathlib import Path

from scanner.core.models import ScanResult
from scanner.plugins.base import ReporterPlugin


class HTMLReport(ReporterPlugin):
    name = "reporter.html"

    async def emit(self, results: list[ScanResult], output_dir: str, *, timeline: list[dict[str, object]] | None = None) -> str:
        output_path = Path(output_dir) / "report.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)

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
            blocks.append(
                f"""
                <section>
                    <h2>{escape(result.target)}</h2>
                    <p>Endpoints: {len(result.crawled_endpoints)} | Findings: {len(result.findings)}</p>
                    <h3>Observations</h3>
                    <table>
                        <thead><tr><th>Endpoint</th><th>Anomaly</th><th>Signal</th></tr></thead>
                        <tbody>{obs_rows}</tbody>
                    </table>
                    <h3>Findings</h3>
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
        <html lang="en">
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
            <h1>Security Observability Report</h1>
            {"".join(blocks)}
            <section>
                <h2>Event timeline (sample)</h2>
                <ul>{tl_html}</ul>
            </section>
        </body>
        </html>
        """
        output_path.write_text(html_doc, encoding="utf-8")
        return str(output_path)
