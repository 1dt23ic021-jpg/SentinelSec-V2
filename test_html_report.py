from modules.reporting.report_generator import (
    generate_security_report,
)
from modules.reporting.html_report_generator import (
    save_html_report,
)

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

report = generate_security_report(
    target="127.0.0.1",
    ip_address="127.0.0.1",
    scan_results=scan_results,
    web_scan=web_scan,
)

report_path = save_html_report(report)

print("HTML report generated successfully:")
print(report_path)