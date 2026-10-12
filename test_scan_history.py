from modules.reporting.scan_history import (
    save_scan_history,
    list_scan_history,
    load_scan_history,
    compare_scans,
)

previous_report = {
    "target": {
        "hostname": "127.0.0.1",
        "ip_address": "127.0.0.1",
    },
    "port_scan": {
        "results": [
            {
                "port": 22,
                "status": "open",
                "service": "SSH",
            },
            {
                "port": 80,
                "status": "open",
                "service": "HTTP",
            },
        ],
    },
}

current_report = {
    "target": {
        "hostname": "127.0.0.1",
        "ip_address": "127.0.0.1",
    },
    "port_scan": {
        "results": [
            {
                "port": 22,
                "status": "open",
                "service": "SSH",
            },
            {
                "port": 8080,
                "status": "open",
                "service": "HTTP",
            },
        ],
    },
}

# Save both snapshots
previous_path = save_scan_history(previous_report)
current_path = save_scan_history(current_report)

# Load the saved reports
previous_record = load_scan_history(previous_path)
current_record = load_scan_history(current_path)

# Compare the actual saved snapshots
changes = compare_scans(
    previous_record["report"],
    current_record["report"],
)

print("\nSentinelSec V2 - Scan Comparison")
print("-" * 40)
print("History records:", len(list_scan_history()))
print("Newly opened ports:", changes["newly_open_ports"])
print("Closed ports:", changes["closed_ports"])
print("Service changes:", changes["service_changes"])
print("Summary:", changes["summary"])   