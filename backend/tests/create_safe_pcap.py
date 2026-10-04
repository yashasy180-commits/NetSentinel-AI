from scapy.all import IP, TCP, UDP, wrpcap

packets = [
    IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=50000, dport=443, flags="S"),

    IP(src="192.168.1.20", dst="192.168.1.10") /
    TCP(sport=443, dport=50000, flags="SA"),

    IP(src="192.168.1.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53),
]

output = r"C:\NetSentinel-AI\backend\tests\safe_test.pcap"

wrpcap(output, packets)

print(f"Created: {output}")
print(f"Packets: {len(packets)}")
