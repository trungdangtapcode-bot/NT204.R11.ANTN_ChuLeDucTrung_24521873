from parsers.network import parse_ipv4

# Biến đếm toàn cục để tạo packet_id duy nhất
packet_counter = 0

def process_packet(packet, capture_time):
    """
    Pipeline chính xử lý gói tin: 
    Raw Packet -> Network -> Transport -> Application -> Normalized IDS Event
    """
    global packet_counter
    packet_counter += 1
    
    # Cấu trúc sự kiện cơ bản
    event = {
        "packet_id": packet_counter,
        "timestamp": capture_time,
        "status": "UNKNOWN"
    }

    # 1. Network Parser
    network_info = parse_ipv4(packet)
    if network_info:
        event.update(network_info)
        event["status"] = "PARSED_NETWORK"
    else:
        # Nếu không phải IPv4, đề bài yêu cầu không crash, đánh dấu là UNKNOWN hoặc bỏ qua
        return None 

    # In ra màn hình để tạm thời theo dõi
    print(f"[Pipeline] Đã parse: {event['src_ip']} -> {event['dst_ip']} (Proto: {event['ip_proto']})")
    
    return event
