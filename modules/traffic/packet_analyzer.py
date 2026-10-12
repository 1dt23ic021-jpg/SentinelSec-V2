from collections import Counter

from scapy.all import ARP, ICMP, IP, TCP, UDP, DNS, rdpcap


def analyze_packets(packets):
    """
    Analyze a collection of packets and return protocol statistics.
    """

    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    dns_packets = 0

    for packet in packets:

        if packet.haslayer(ARP):
            protocols["ARP"] += 1

        elif packet.haslayer(ICMP):
            protocols["ICMP"] += 1

        elif packet.haslayer(TCP):
            protocols["TCP"] += 1

        elif packet.haslayer(UDP):
            protocols["UDP"] += 1

        else:
            protocols["OTHER"] += 1

        if packet.haslayer(IP):

            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

        if packet.haslayer(TCP):
            tcp_ports[packet[TCP].dport] += 1

        if packet.haslayer(UDP):
            udp_ports[packet[UDP].dport] += 1

        if packet.haslayer(DNS):
            dns_packets += 1

    return {
        "total_packets": len(packets),
        "protocols": dict(protocols),
        "top_source_ips": dict(source_ips.most_common(5)),
        "top_destination_ips": dict(destination_ips.most_common(5)),
        "top_tcp_destination_ports": dict(tcp_ports.most_common(10)),
        "top_udp_destination_ports": dict(udp_ports.most_common(10)),
        "dns_packets": dns_packets
    }


def analyze_pcap(file_path):
    """
    Read a PCAP file and analyze its packets.
    """

    packets = rdpcap(file_path)

    return analyze_packets(packets)


def print_summary(summary):
    """
    Display packet-analysis results.
    """

    print("\nPacket Analysis Summary")
    print("-" * 40)

    print(f"Total packets: {summary['total_packets']}")

    print("\nProtocols:")

    for protocol, count in summary["protocols"].items():
        print(f"  {protocol}: {count}")

    print("\nTop source IPs:")

    for ip, count in summary["top_source_ips"].items():
        print(f"  {ip}: {count}")

    print("\nTop destination IPs:")

    for ip, count in summary["top_destination_ips"].items():
        print(f"  {ip}: {count}")

    print("\nTop TCP destination ports:")

    for port, count in summary["top_tcp_destination_ports"].items():
        print(f"  {port}: {count}")

    print("\nTop UDP destination ports:")

    for port, count in summary["top_udp_destination_ports"].items():
        print(f"  {port}: {count}")

    print(f"\nDNS packets: {summary['dns_packets']}")