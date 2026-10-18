from scapy.all import IP, TCP, UDP, wrpcap

def generate_sample_pcap():
    # 1. Tạo gói tin TCP Handshake (SYN)
    pkt_syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
    
    # 2. Tạo gói tin UDP (VD: DNS query giả lập)
    pkt_udp = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=54321, dport=53)
    
    # 3. Tạo gói tin TCP có Payload (Giả lập HTTP GET request)
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt_http = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA") / http_payload

    # Danh sách các gói tin
    packets = [pkt_syn, pkt_udp, pkt_http]

    # Lưu ra file pcap
    pcap_path = "sample.pcap"
    wrpcap(pcap_path, packets)
    print(f"[*] Đã tạo thành công file PCAP mẫu tại: {pcap_path}")

if __name__ == "__main__":
    generate_sample_pcap()
