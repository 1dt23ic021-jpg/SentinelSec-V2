from modules.reporting.report_generator import (
    generate_security_report,
    save_security_report,
)

# Sample network scan results
scan_results = [
    {
        "port": 23,
        "status": "open",
        "service": "Telnet",
        "banner": "",
    },
    {
        "port": 5432,
        "status": "open",
        "service": "PostgreSQL",
        "banner": "",
    },
]

# Sample web scan results
web_scan = {
    "requested_url": "http://127.0.0.1",
    "final_url": "http://127.0.0.1",
    "status_code": 200,
    "https": False,
    "security_headers": {
        "Content-Security-Policy": None,
        "Strict-Transport-Security": None,
        "X-Content-Type-Options": None,
        "X-Frame-Options": None,
        "Referrer-Policy": None,
        "Permissions-Policy": None,
    },
    "cookies": [],
    "findings": [],
}

# Generate the combined security report
report = generate_security_report(
    target="127.0.0.1",
    ip_address="127.0.0.1",
    scan_results=scan_results,
    web_scan=web_scan,
)

# Save the report
report_path = save_security_report(report)

print("\nSentinelSec V2 - Report Test")
print("-" * 40)
print("Report saved:", report_path)
print("\nFinding Summary:")

for severity, count in report["findings_summary"].items():
    print(f"{severity}: {count}")

print("\nGenerated Findings:")

for finding in report["findings"]:
    print(
        f"[{finding['severity']}] "
        f"{finding['finding_id']} - "
        f"{finding['title']}"
    )

print("\nTest completed.")