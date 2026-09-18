from scapy.layers.inet import TCP, UDP

def parse_transport(packet):
    """
    Trích xuất thông tin Transport Layer (TCP, UDP).
    Trả về dict chứa src_port, dst_port và các cờ TCP (phục vụ testcase Handshake).
    """
    if TCP in packet:
        tcp_layer = packet[TCP]
        flags = str(tcp_layer.flags)
        
        # Nhận diện TCP Handshake theo yêu cầu Testcase của đề bài
        handshake = ""
        if flags == "S":
            handshake = "SYN"
        elif flags == "SA":
            handshake = "SYN/ACK"
        elif flags == "A":
            handshake = "ACK"

        return {
            "transport_proto": "TCP",
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "tcp_flags": flags,
            "tcp_handshake": handshake,
            "payload_len": len(tcp_layer.payload)
        }
        
    elif UDP in packet:
        udp_layer = packet[UDP]
        return {
            "transport_proto": "UDP",
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "payload_len": len(udp_layer.payload)
        }
        
    return None
