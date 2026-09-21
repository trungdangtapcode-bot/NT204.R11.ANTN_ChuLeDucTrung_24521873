import re
from scapy.layers.dns import DNS

def parse_application(packet, transport_info):
    """
    Nhận diện và trích xuất thông tin Application Layer (HTTP, DNS, SMTP).
    Dựa vào cả Port-based và Payload-based để lấy điểm thưởng.
    """
    app_info = {"app_proto": "UNKNOWN"}
    
    if not transport_info:
        return app_info

    src_port = transport_info.get("src_port")
    dst_port = transport_info.get("dst_port")
    
    # 1. Xử lý DNS (Scapy parse sẵn DNS header)
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        app_info["app_proto"] = "DNS"
        
        # DNS Query
        if dns_layer.qr == 0 and dns_layer.qdcount > 0 and dns_layer.qd:
            app_info["dns_type"] = "Query"
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname)
            app_info["dns_query_domain"] = qname.strip('.')
            app_info["dns_query_type"] = dns_layer.qd.qtype
            
        # DNS Response
        elif dns_layer.qr == 1 and dns_layer.ancount > 0 and dns_layer.an:
            app_info["dns_type"] = "Response"
            answers = []
            for i in range(dns_layer.ancount):
                try:
                    rdata = dns_layer.an[i].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode('utf-8', errors='ignore')
                    answers.append(str(rdata))
                except:
                    pass
            app_info["dns_answers"] = answers
        return app_info

    # Lấy Raw payload để parse HTTP và SMTP
    try:
        payload_bytes = bytes(packet[transport_info["transport_proto"]].payload)
        if not payload_bytes:
            return app_info
        payload_str = payload_bytes.decode('utf-8', errors='ignore')
    except:
        return app_info

    # 2. Xử lý HTTP (Thuần Payload-based, không cần biết chạy port nào)
    http_methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "]
    if any(payload_str.startswith(m) for m in http_methods):
        app_info["app_proto"] = "HTTP"
        app_info["http_type"] = "Request"
        lines = payload_str.split('\r\n')
        if lines:
            parts = lines[0].split(' ')
            if len(parts) >= 2:
                app_info["http_method"] = parts[0]
                app_info["http_url"] = parts[1]
        
        # Trích xuất body nếu là POST
        if app_info.get("http_method") == "POST":
            body_split = payload_str.split('\r\n\r\n', 1)
            if len(body_split) > 1:
                app_info["http_body"] = body_split[1].strip()
        return app_info
        
    elif payload_str.startswith("HTTP/1."):
        app_info["app_proto"] = "HTTP"
        app_info["http_type"] = "Response"
        lines = payload_str.split('\r\n')
        if lines:
            parts = lines[0].split(' ', 2)
            if len(parts) >= 2:
                app_info["http_status_code"] = parts[1]
        
        # Trích xuất header
        headers = {}
        for line in lines[1:]:
            if not line.strip(): break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        app_info["http_headers"] = headers
        return app_info

    # 3. Xử lý SMTP (Kết hợp Port và Payload-based)
    smtp_cmds = ["HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT"]
    if src_port in [25, 587, 465] or dst_port in [25, 587, 465] or any(payload_str.upper().startswith(cmd) for cmd in smtp_cmds):
        app_info["app_proto"] = "SMTP"
        
        # SMTP Command
        if any(payload_str.upper().startswith(cmd) for cmd in smtp_cmds):
            app_info["smtp_type"] = "Command"
            app_info["smtp_command"] = payload_str.split('\r\n')[0]
            
        # SMTP Response (bắt đầu bằng 3 chữ số mã lỗi)
        elif re.match(r'^\d{3}[ -]', payload_str):
            app_info["smtp_type"] = "Response"
            first_line = payload_str.split('\r\n')[0]
            app_info["smtp_status_code"] = first_line[:3]
            app_info["smtp_response_msg"] = first_line[4:]
            
        return app_info

    return app_info
