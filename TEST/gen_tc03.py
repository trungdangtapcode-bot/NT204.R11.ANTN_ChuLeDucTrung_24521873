from scapy.all import IP, UDP, wrpcap

def generate_tc03():
    # UDP Packet
    payload = b"UDP Data Payload"
    pkt1 = IP(src="192.168.1.100", dst="192.168.1.1") / UDP(sport=50000, dport=53) / payload

    wrpcap("tc03_udp.pcap", [pkt1])

if __name__ == "__main__":
    generate_tc03()
