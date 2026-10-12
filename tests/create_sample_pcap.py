from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap


packets = [
    IP(src="192.168.1.10", dst="192.168.1.1") / TCP(
        sport=50000,
        dport=80,
        flags="S"
    ),

    IP(src="192.168.1.10", dst="8.8.8.8") / UDP(
        sport=50001,
        dport=53
    ) / DNS(
        rd=1,
        qd=DNSQR(qname="example.com")
    ),

    IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(),

    IP(src="192.168.1.10", dst="192.168.1.1") / TCP(
        sport=50002,
        dport=443,
        flags="S"
    )
]


output_file = "tests/sample_traffic.pcap"

wrpcap(output_file, packets)

print(f"Sample PCAP created: {output_file}")