"""
SentinelSec V2 - HTML Security Report Generator
"""

from datetime import datetime
from html import escape
from pathlib import Path


SEVERITIES = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
]


def generate_html_report(report):
    """
    Generate a standalone HTML report from a SentinelSec
    structured security report.
    """

    target = report.get("target", {})
    if not isinstance(target, dict):
        target = {"hostname": str(target)}

    hostname = escape(str(target.get("hostname", "Unknown")))
    ip_address = escape(str(target.get("ip_address", "Unknown")))

    generated_at = escape(
        str(report.get("generated_at") or datetime.now().isoformat(
            timespec="seconds"
        ))
    )

    port_scan = report.get("port_scan") or {}
    port_results = port_scan.get("results") or []

    findings = report.get("findings") or []
    summary = report.get("findings_summary") or {}

    def safe(value):
        """Escape untrusted values before inserting them into HTML."""
        return escape(str(value if value is not None else "N/A"))

    severity_cards = ""

    for severity in SEVERITIES:
        count = summary.get(severity, 0)

        severity_cards += f"""
        <div class="summary-card">
            <span class="severity">{safe(severity)}</span>
            <strong>{safe(count)}</strong>
        </div>
        """

    service_rows = ""

    for result in port_results:
        if not isinstance(result, dict):
            continue

        service_rows += f"""
        <tr>
            <td>{safe(result.get("port"))}</td>
            <td>{safe(result.get("status"))}</td>
            <td>{safe(result.get("service"))}</td>
            <td>{safe(result.get("banner"))}</td>
        </tr>
        """

    if not service_rows:
        service_rows = """
        <tr><td colspan="4">No open services recorded.</td></tr>
        """

    finding_rows = ""

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = str(finding.get("severity", "Informational"))
        severity_class = severity.lower()

        finding_rows += f"""
        <tr>
            <td>{safe(finding.get("finding_id"))}</td>
            <td>
                <span class="badge {safe(severity_class)}">
                    {safe(severity)}
                </span>
            </td>
            <td>{safe(finding.get("title"))}</td>
            <td>{safe(finding.get("asset"))}</td>
            <td>{safe(finding.get("evidence"))}</td>
            <td>{safe(finding.get("recommendation"))}</td>
        </tr>
        """

    if not finding_rows:
        finding_rows = """
        <tr><td colspan="6">No findings recorded.</td></tr>
        """

    total_findings = summary.get("Total", len(findings))
    open_ports = port_scan.get(
        "open_ports_count",
        len(port_results),
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelSec Security Assessment</title>
<style>
    body {{
        margin: 0;
        padding: 30px;
        background: #f3f5f9;
        color: #202938;
        font-family: Arial, sans-serif;
    }}
    .container {{
        max-width: 1250px;
        margin: auto;
    }}
    header {{
        background: #172554;
        color: white;
        padding: 28px;
        border-radius: 12px;
    }}
    header h1 {{
        margin: 0 0 10px;
    }}
    .muted {{
        color: #64748b;
        font-size: 13px;
    }}
    header .muted {{
        color: #cbd5e1;
    }}
    section {{
        background: white;
        padding: 22px;
        margin-top: 22px;
        border-radius: 12px;
        box-shadow: 0 2px 8px #0000000a;
    }}
    .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 12px;
    }}
    .summary-card {{
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
    }}
    .summary-card strong {{
        display: block;
        font-size: 28px;
        margin-top: 8px;
    }}
    .severity {{
        font-size: 13px;
        color: #475569;
    }}
    .table-wrap {{
        overflow-x: auto;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }}
    th, td {{
        text-align: left;
        padding: 12px;
        border-bottom: 1px solid #e2e8f0;
        vertical-align: top;
        overflow-wrap: anywhere;
    }}
    th {{
        background: #f8fafc;
    }}
    .badge {{
        display: inline-block;
        padding: 5px 8px;
        border-radius: 5px;
        font-weight: bold;
    }}
    .critical, .high {{
        background: #fee2e2;
        color: #991b1b;
    }}
    .medium {{
        background: #fef3c7;
        color: #92400e;
    }}
    .low {{
        background: #dbeafe;
        color: #1d4ed8;
    }}
    .informational {{
        background: #e2e8f0;
        color: #334155;
    }}
    footer {{
        margin-top: 20px;
        color: #64748b;
        font-size: 12px;
        text-align: center;
    }}
    @media print {{
        body {{ background: white; padding: 0; }}
        section, header {{ box-shadow: none; }}
    }}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>SentinelSec</h1>
    <p>Network &amp; Web Security Assessment Report</p>
    <p>Target: {hostname} ({ip_address})</p>
    <p class="muted">Generated: {generated_at}</p>
</header>

<section>
    <h2>Assessment Summary</h2>
    <div class="cards">
        <div class="summary-card">
            <span class="severity">Open Ports</span>
            <strong>{safe(open_ports)}</strong>
        </div>
        <div class="summary-card">
            <span class="severity">Total Findings</span>
            <strong>{safe(total_findings)}</strong>
        </div>
        {severity_cards}
    </div>
</section>

<section>
    <h2>Open Services</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>{service_rows}</tbody>
        </table>
    </div>
</section>

<section>
    <h2>Security Findings &amp; Recommendations</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Asset</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>{finding_rows}</tbody>
        </table>
    </div>
    <p class="muted">
        Findings are rule-based observations. Validate each finding
        in context before treating it as a confirmed vulnerability.
    </p>
</section>

<footer>
    SentinelSec V2 | Generated security assessment report
</footer>

</div>
</body>
</html>
"""

    return html_content


def save_html_report(report):
    """
    Save the generated HTML report in the project's reports folder.
    """

    project_root = Path(__file__).resolve().parents[2]
    reports_directory = project_root / "reports"

    reports_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = reports_directory / (
        f"sentinelsec_report_{timestamp}.html"
    )

    html_content = generate_html_report(report)

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    return report_path