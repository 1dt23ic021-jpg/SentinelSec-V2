from scapy.all import ICMP, IP, TCP, UDP

from modules.traffic.packet_analyzer import analyze_packets


packets = [
    IP(src="192.168.1.10", dst="192.168.1.1") / TCP(dport=80),
    IP(src="192.168.1.10", dst="8.8.8.8") / UDP(dport=53),
    IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(),
    IP(src="192.168.1.10", dst="192.168.1.1") / TCP(dport=443),
]


summary = analyze_packets(packets)


assert summary["total_packets"] == 4
assert summary["protocols"]["TCP"] == 2
assert summary["protocols"]["UDP"] == 1
assert summary["protocols"]["ICMP"] == 1

print("Packet analyzer test passed.")
print(summary)