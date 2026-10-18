from scapy.all import IP, TCP, wrpcap

def generate_tc02():
    # TCP Data có payload
    payload = b"Hello IDS, this is some TCP payload data!"
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / payload

    wrpcap("tc02_tcp_data.pcap", [pkt1])

if __name__ == "__main__":
    generate_tc02()
