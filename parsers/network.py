from scapy.layers.inet import IP

def parse_ipv4(packet):
    """
    Trích xuất thông tin Network Layer (IPv4).
    Trả về dict chứa src_ip, dst_ip, protocol.
    Nếu không phải IPv4, trả về None để pipeline xử lý (bỏ qua hoặc đánh dấu).
    """
    if IP in packet:
        ip_layer = packet[IP]
        return {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ip_proto": ip_layer.proto,  # 6: TCP, 17: UDP, 1: ICMP
            "ttl": ip_layer.ttl
        }
    return None
