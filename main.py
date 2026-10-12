from getpass import getpass

from modules.network.port_scanner import resolve_target, scan_ports
from modules.network.banner_grabber import grab_banner
from modules.network.service_detector import detect_service

from modules.traffic.packet_analyzer import (
    analyze_pcap,
    print_summary
)
from modules.authentication.password_auditor import audit_password

from modules.reporting.report_generator import (
    create_scan_result,
    save_json_report,
    generate_security_report,
    save_security_report
)
from modules.web.web_scanner import (
    scan_web_target,
    print_web_summary
)

from modules.reporting.html_report_generator import (
    save_html_report,
)

from modules.reporting.scan_history import (
    save_scan_history,
    list_scan_history,
    load_scan_history,
    compare_scans,
)

def network_scan():
    """
    Perform a TCP network scan with banner grabbing
    and service detection.
    """

    print("\n" + "=" * 50)
    print("              NETWORK SCANNER")
    print("=" * 50)

    target = input("\nEnter target IP or hostname: ").strip()

    try:
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

    except ValueError:
        print("\nError: Ports must be numbers.")
        return None

    if start_port < 1 or end_port > 65535:
        print("\nError: Port range must be between 1 and 65535.")
        return None

    if start_port > end_port:
        print("\nError: Starting port cannot be greater than ending port.")
        return None

    try:
        ip_address = resolve_target(target)

    except ValueError as error:
        print(f"\nError: {error}")
        return None

    print("\nTarget Information")
    print("-" * 30)
    print(f"Hostname : {target}")
    print(f"IP       : {ip_address}")
    print(f"Ports    : {start_port}-{end_port}")

    print("\nScanning...")
    print("-" * 30)

    open_ports = scan_ports(
        ip_address,
        start_port,
        end_port
    )

    print("\nScan Complete")
    print("-" * 30)

    if not open_ports:
        print("No open ports found.")
        return {
            "target": target,
            "ip_address": ip_address,
            "scan_results": []
        }

    print(f"Open ports found: {len(open_ports)}\n")

    scan_results = []

    for port in open_ports:

        print(f"[+] Port {port} is OPEN")

        banner = grab_banner(ip_address, port)

        if banner:
            first_line = banner.splitlines()[0]
            print(f"    Banner: {first_line}")
        else:
            banner = None
            print("    Banner: Not available")

        service = detect_service(port, banner)

        print(f"    Service: {service}")

        result = create_scan_result(
            port,
            banner,
            service
        )

        scan_results.append(result)

        print()

    report_path = save_json_report(
        target,
        ip_address,
        start_port,
        end_port,
        scan_results
    )

    print(f"JSON report saved to: {report_path}")

    return {
        "target": target,
        "ip_address": ip_address,
        "scan_results": scan_results
    }


def packet_analysis():
    """
    Analyze an existing PCAP file.
    """

    print("\n" + "=" * 50)
    print("              PACKET ANALYZER")
    print("=" * 50)

    file_path = input("\nEnter PCAP file path: ").strip()

    try:
        summary = analyze_pcap(file_path)

        print_summary(summary)

        return summary

    except FileNotFoundError:
        print("\nError: PCAP file not found.")

    except Exception as error:
        print(f"\nError while analyzing PCAP: {error}")

    return None


def password_audit():
    """
    Audit a password locally.
    """

    print("\n" + "=" * 50)
    print("              PASSWORD AUDITOR")
    print("=" * 50)

    password = getpass("\nEnter password to audit: ")

    if not password:
        print("\nError: Password cannot be empty.")
        return None

    result = audit_password(password)

    print("\nPassword Audit Result")
    print("-" * 30)
    print(f"Length      : {result['length']}")
    print(f"Entropy     : {result['entropy_bits']} bits")
    print(f"Strength    : {result['strength']}")
    print(f"Score       : {result['score']}")

    print("\nFindings:")

    for finding in result["findings"]:
        print(f"- {finding}")

    return result

def web_security_scan():
    """
    Perform a passive web security assessment.
    """

    print("\n" + "=" * 50)
    print("              WEB SECURITY SCANNER")
    print("=" * 50)

    url = input("\nEnter authorized target URL: ").strip()

    if not url:
        print("\nError: URL cannot be empty.")
        return None

    result = scan_web_target(url)

    print_web_summary(result)

    return result

def generate_complete_report():
    """
    Run the available assessment modules and generate
    JSON and HTML reports with findings and scan history.
    """

    print("\n" + "=" * 50)
    print("          COMPLETE SECURITY ASSESSMENT")
    print("=" * 50)

    network_result = network_scan()

    if network_result is None:
        print("\nAssessment cancelled: network scan failed.")
        return

    packet_result = None
    password_result = None
    web_result = None

    # Optional web security assessment
    run_web = input(
        "\nDo you want to perform a web security scan? (y/n): "
    ).strip().lower()

    if run_web == "y":
        web_result = web_security_scan()

    # Optional packet analysis
    analyze_packet = input(
        "\nDo you want to analyze a PCAP file? (y/n): "
    ).strip().lower()

    if analyze_packet == "y":
        packet_result = packet_analysis()

    # Optional password audit
    audit = input(
        "\nDo you want to perform a password audit? (y/n): "
    ).strip().lower()

    if audit == "y":
        password_result = password_audit()

    # Generate the structured report and findings
    report = generate_security_report(
        target=network_result["target"],
        ip_address=network_result["ip_address"],
        scan_results=network_result["scan_results"],
        packet_analysis=packet_result,
        password_audit=password_result,
        web_scan=web_result,
    )

    # Save JSON report
    json_path = save_security_report(report)

    # Save HTML report
    html_path = save_html_report(report)

    # Save assessment snapshot for future comparisons
    history_path = save_scan_history(report)

    print("\n" + "=" * 50)
    print("       SENTINELSEC V2 ASSESSMENT COMPLETE")
    print("=" * 50)

    print(f"\nTarget       : {network_result['target']}")
    print(f"Open ports   : {len(network_result['scan_results'])}")
    print(f"Total findings: {report['findings_summary']['Total']}")

    print("\nFindings by severity:")

    for severity, count in report["findings_summary"].items():
        if severity != "Total":
            print(f"  {severity}: {count}")

    print("\nReports and history saved:")
    print(f"JSON    : {json_path}")
    print(f"HTML    : {html_path}")
    print(f"History : {history_path}")

def compare_saved_scans():
    """Compare two saved SentinelSec assessment snapshots."""

    history_files = list_scan_history()

    if len(history_files) < 2:
        print(
            "\nAt least two saved assessments are required "
            "for comparison."
        )
        print("Run Complete Security Assessment twice first.")
        return

    print("\n" + "=" * 50)
    print("          SCAN HISTORY & COMPARISON")
    print("=" * 50)

    print("\nSaved assessments:")

    for index, path in enumerate(history_files, start=1):
        print(f"{index}. {path.name}")

    try:
        previous_choice = int(
            input("\nSelect PREVIOUS scan number: ")
        )

        current_choice = int(
            input("Select CURRENT scan number: ")
        )

    except ValueError:
        print("\nError: Enter valid scan numbers.")
        return

    if (
        previous_choice < 1
        or previous_choice > len(history_files)
        or current_choice < 1
        or current_choice > len(history_files)
    ):
        print("\nError: Scan number is out of range.")
        return

    if previous_choice == current_choice:
        print("\nChoose two different assessments.")
        return

    try:
        previous_record = load_scan_history(
            history_files[previous_choice - 1]
        )

        current_record = load_scan_history(
            history_files[current_choice - 1]
        )

        changes = compare_scans(
            previous_record["report"],
            current_record["report"],
        )

    except (ValueError, KeyError, OSError) as error:
        print(f"\nUnable to compare scans: {error}")
        return

    print("\nComparison Results")
    print("-" * 40)
    print(f"Target: {changes['target']}")

    print("\nNewly opened ports:")

    if changes["newly_open_ports"]:
        for item in changes["newly_open_ports"]:
            print(
                f"  + Port {item['port']} "
                f"({item['service']})"
            )
    else:
        print("  None detected.")

    print("\nClosed ports:")

    if changes["closed_ports"]:
        for item in changes["closed_ports"]:
            print(
                f"  - Port {item['port']} "
                f"({item['service']})"
            )
    else:
        print("  None detected.")

    print("\nService changes:")

    if changes["service_changes"]:
        for item in changes["service_changes"]:
            print(
                f"  Port {item['port']}: "
                f"{item['previous_service']} -> "
                f"{item['current_service']}"
            )
    else:
        print("  None detected.")

    print("\nChange Summary:")
    for name, count in changes["summary"].items():
        print(f"  {name.replace('_', ' ').title()}: {count}")


def main():

    while True:

        print("\n")
        print("=" * 50)
        print("                  SENTINELSEC")
        print("        Network & Security Assessment")
        print("=" * 50)

        print("\n1. Network Scan")
        print("2. Packet Analysis")
        print("3. Password Audit")
        print("4. Web Security Scan")
        print("5. Complete Security Assessment")
        print("6. Scan History & Comparison")
        print("7. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            network_scan()

        elif choice == "2":
            packet_analysis()

        elif choice == "3":
            password_audit()

        elif choice == "4":
            web_security_scan()

        elif choice == "5":
            generate_complete_report()

        elif choice == "6":
            compare_saved_scans()

        elif choice == "7":
            print("\nExiting SentinelSec.")
            break

        else:
            print("\nInvalid option. Please select 1-7.")


if __name__ == "__main__":
    main()