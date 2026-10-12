"""
SentinelSec V2 - Scan History and Change Detection
"""

import json
from datetime import datetime
from pathlib import Path


def get_history_directory():
    """Return the scan history directory."""

    project_root = Path(__file__).resolve().parents[2]
    history_directory = project_root / "reports" / "history"

    history_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return history_directory


def save_scan_history(report):
    """
    Save a snapshot of a security assessment for future comparison.
    """

    history_directory = get_history_directory()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    history_record = {
        "history_id": f"SCAN-{timestamp}",
        "saved_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "report": report,
    }

    history_path = history_directory / (
        f"{history_record['history_id']}.json"
    )

    with open(history_path, "w", encoding="utf-8") as file:
        json.dump(history_record, file, indent=4)

    return history_path


def list_scan_history():
    """Return saved scan history files, newest first."""

    history_directory = get_history_directory()

    return sorted(
        history_directory.glob("SCAN-*.json"),
        reverse=True,
    )


def load_scan_history(history_path):
    """Load one saved scan history record."""

    with open(history_path, "r", encoding="utf-8") as file:
        return json.load(file)


def _get_open_ports(report):
    """Extract open TCP ports from a saved report."""

    port_scan = report.get("port_scan") or {}
    results = port_scan.get("results") or []

    open_ports = {}

    for result in results:
        if not isinstance(result, dict):
            continue

        if str(result.get("status", "")).lower() != "open":
            continue

        try:
            port = int(result["port"])
        except (KeyError, TypeError, ValueError):
            continue

        open_ports[port] = {
            "service": result.get("service") or "Unknown",
            "banner": result.get("banner") or "",
        }

    return open_ports


def compare_scans(previous_report, current_report):
    """
    Compare two reports and identify observable changes.

    The reports should represent the same target and comparable
    port ranges for meaningful results.
    """

    previous_target = previous_report.get("target") or {}
    current_target = current_report.get("target") or {}

    previous_hostname = (
        previous_target.get("hostname")
        if isinstance(previous_target, dict)
        else str(previous_target)
    )

    current_hostname = (
        current_target.get("hostname")
        if isinstance(current_target, dict)
        else str(current_target)
    )

    previous_ip = (
        previous_target.get("ip_address")
        if isinstance(previous_target, dict)
        else None
    )

    current_ip = (
        current_target.get("ip_address")
        if isinstance(current_target, dict)
        else None
    )

    if (
        previous_hostname != current_hostname
        or previous_ip != current_ip
    ):
        raise ValueError(
            "Cannot compare scans of different targets."
        )

    previous_ports = _get_open_ports(previous_report)
    current_ports = _get_open_ports(current_report)

    previous_set = set(previous_ports)
    current_set = set(current_ports)

    new_ports = sorted(current_set - previous_set)
    closed_ports = sorted(previous_set - current_set)

    service_changes = []

    for port in sorted(previous_set & current_set):
        old_service = previous_ports[port]["service"]
        new_service = current_ports[port]["service"]

        if old_service != new_service:
            service_changes.append({
                "port": port,
                "previous_service": old_service,
                "current_service": new_service,
            })

    return {
        "target": current_hostname,
        "previous_ip_address": previous_ip,
        "current_ip_address": current_ip,
        "newly_open_ports": [
            {
                "port": port,
                **current_ports[port],
            }
            for port in new_ports
        ],
        "closed_ports": [
            {
                "port": port,
                **previous_ports[port],
            }
            for port in closed_ports
        ],
        "service_changes": service_changes,
        "summary": {
            "new_ports": len(new_ports),
            "closed_ports": len(closed_ports),
            "service_changes": len(service_changes),
        },
    }