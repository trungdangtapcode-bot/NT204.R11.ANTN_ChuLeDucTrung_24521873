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
    
    # 3. Application Parser
    from parsers.application import parse_application
    app_info = parse_application(packet, transport_info)
    if app_info and app_info.get("app_proto") != "UNKNOWN":
        event.update(app_info)
        event["status"] = "PARSED_APPLICATION"
        app_proto = app_info["app_proto"]
        app_type = app_info.get("http_type") or app_info.get("dns_type") or app_info.get("smtp_type", "")
        print(f"   -> [App] {app_proto} {app_type}")
    
    # 4. Decoder - Giải mã payload (Bài tập 2)
    from core.decoder import decode_payload
    raw_payload = event.get("http_url") or event.get("http_body") or event.get("smtp_command") or ""
    if raw_payload:
        decode_result = decode_payload(raw_payload, event.get("app_proto"))
        event["decoded_payload"] = decode_result["decoded_payload"]
        event["encoding_detected"] = decode_result["encoding_detected"]
        if decode_result["encoding_detected"] != "none":
            print(f"   -> [Decoder] {decode_result['encoding_detected']}: {decode_result['decoded_payload'][:80]}")
    
    # 5. Preprocessor - Chuẩn hóa và trích xuất feature (Bài tập 2)
    from core.preprocessor import preprocess_event
    event = preprocess_event(event)
    if event.get("feature_entropy", 0) > 0:
        print(f"   -> [Preprocessor] Entropy: {event['feature_entropy']}, SpecialChars: {event['feature_special_char_count']}")
    
    # 6. Ghi log JSON Lines
    from utils.logger import log_event
    log_event(event, "TEST/output.jsonl")
    
    return event
