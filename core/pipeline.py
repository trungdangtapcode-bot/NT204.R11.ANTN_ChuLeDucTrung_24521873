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
        return None 

    # 2. Transport Parser
    from parsers.transport import parse_transport
    transport_info = parse_transport(packet)
    if transport_info:
        event.update(transport_info)
        event["status"] = "PARSED_TRANSPORT"
        # Định dạng chuỗi log chi tiết hơn
        proto_str = transport_info["transport_proto"]
        port_info = f":{transport_info['src_port']} -> :{transport_info['dst_port']}"
        print(f"[Pipeline] {event['src_ip']}{port_info} ({proto_str}) - Payload: {transport_info['payload_len']} bytes")
    else:
        print(f"[Pipeline] {event['src_ip']} -> {event['dst_ip']} (Proto: {event['ip_proto']}) - No Transport")
    
    # 4. Ghi log JSON Lines
    from utils.logger import log_event
    log_event(event, "TEST/output.jsonl")
    
    return event
