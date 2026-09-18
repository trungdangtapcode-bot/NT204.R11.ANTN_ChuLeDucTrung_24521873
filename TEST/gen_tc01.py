from scapy.all import IP, TCP, wrpcap

def generate_tc01():
    # TCP Handshake
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S", seq=1000)
    pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    pkt3 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)

    wrpcap("tc01_tcp_handshake.pcap", [pkt1, pkt2, pkt3])

if __name__ == "__main__":
    generate_tc01()
