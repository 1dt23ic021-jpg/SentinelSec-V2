import json
from datetime import datetime
from pathlib import Path


def create_scan_result(port, banner, service):
    """
    Create a structured result for one open port.
    """

    return {
        "port": port,
        "status": "open",
        "service": service,
        "banner": banner,
    }


def save_json_report(
    target,
    ip_address,
    start_port,
    end_port,
    results,
):
    """
    Save the port-scan results as a JSON report.
    """

    report = {
        "scanner": "SentinelSec",
        "scan_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "target": target,
        "ip_address": ip_address,
        "port_range": {
            "start": start_port,
            "end": end_port,
        },
        "open_ports_count": len(results),
        "results": results,
    }

    project_root = Path(__file__).resolve().parents[2]
    reports_directory = project_root / "reports"

    reports_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = reports_directory / (
        f"sentinel_scan_{timestamp}.json"
    )

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path


def generate_security_report(
    target,
    ip_address,
    scan_results=None,
    packet_analysis=None,
    password_audit=None,
    web_scan=None,
    findings=None,
):
    """
    Create a complete SentinelSec V2 security report.

    The original five parameters remain in the same order.
    The additional optional parameters support V2 findings.
    """

    from modules.reporting.finding_engine import (
        generate_findings,
        summarize_findings,
    )

    if findings is None:
        findings = generate_findings(
            scan_results=scan_results,
            web_result=web_scan,
        )

    report = {
        "scanner": "SentinelSec",
        "report_version": "2.0",
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "target": {
            "hostname": target,
            "ip_address": ip_address,
        },
        "port_scan": {
            "open_ports_count": (
                len(scan_results) if scan_results else 0
            ),
            "results": scan_results or [],
        },
        "web_scan": web_scan or {},
        "packet_analysis": packet_analysis or {},
        "password_audit": password_audit or {},
        "findings_summary": summarize_findings(findings),
        "findings": findings,
    }

    return report


def save_security_report(report):
    """
    Save a complete security assessment report as JSON.
    """

    project_root = Path(__file__).resolve().parents[2]
    reports_directory = project_root / "reports"

    reports_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = reports_directory / (
        f"security_report_{timestamp}.json"
    )

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path