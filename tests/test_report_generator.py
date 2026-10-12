from modules.reporting.report_generator import (
    generate_security_report,
    save_security_report
)


scan_results = [
    {
        "port": 8000,
        "status": "open",
        "service": "HTTP - Python SimpleHTTP",
        "banner": "HTTP/1.0 200 OK"
    }
]


packet_analysis = {
    "total_packets": 4,
    "protocols": {
        "TCP": 2,
        "UDP": 1,
        "ICMP": 1
    }
}


password_audit = {
    "length": 14,
    "entropy_bits": 85.2,
    "strength": "Very Strong",
    "score": 6,
    "findings": [
        "No basic password-policy issues detected."
    ]
}


report = generate_security_report(
    target="127.0.0.1",
    ip_address="127.0.0.1",
    scan_results=scan_results,
    packet_analysis=packet_analysis,
    password_audit=password_audit
)


assert report["scanner"] == "SentinelSec"
assert report["target"]["ip_address"] == "127.0.0.1"
assert report["port_scan"]["open_ports_count"] == 1
assert report["packet_analysis"]["total_packets"] == 4
assert report["password_audit"]["strength"] == "Very Strong"


report_path = save_security_report(report)

print("Security reporting test passed.")
print(f"Report saved to: {report_path}")