import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule
from core.flow_tracker import FlowTracker

def test_tc08():
    print("=" * 60)
    print("TEST CASE 08: flow:to_server,established (So khớp với Flow Tracker)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc08_flow_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 1
    rule = valid_rules[0]

    flow_tracker = FlowTracker()

    # 1. Gói 1: SYN (Client -> Server)
    pkt1 = {
        "packet_id": 1,
        "src_ip": "10.0.0.1", "src_port": 12345,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "transport_proto": "TCP",
        "tcp_flags": "S", "payload_len": 0, "timestamp": 100.0
    }
    f1 = flow_tracker.track(pkt1)
    pkt1.update(f1)
    res1 = match_rule(rule, pkt1)
    print(f"\n1. Gói 1 (SYN - Handshake): State={pkt1['flow_tcp_state']}, Dir={pkt1['flow_direction']}")
    print(f"   -> Kết quả: {'MATCH' if res1['matched'] else 'NO_MATCH'} (Lý do: {res1.get('reason')})")
    assert res1["matched"] is False, "SYN packet chưa ESTABLISHED, không được match!"

    # 2. Gói 2: SYN/ACK (Server -> Client)
    pkt2 = {
        "packet_id": 2,
        "src_ip": "10.0.0.2", "src_port": 80,
        "dst_ip": "10.0.0.1", "dst_port": 12345,
        "transport_proto": "TCP",
        "tcp_flags": "SA", "payload_len": 0, "timestamp": 100.1
    }
    f2 = flow_tracker.track(pkt2)
    pkt2.update(f2)

    # 3. Gói 3: ACK (Client -> Server) -> Hoàn tất bắt tay 3 bước
    pkt3 = {
        "packet_id": 3,
        "src_ip": "10.0.0.1", "src_port": 12345,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "transport_proto": "TCP",
        "tcp_flags": "A", "payload_len": 0, "timestamp": 100.2
    }
    f3 = flow_tracker.track(pkt3)
    pkt3.update(f3)

    # 4. Gói 4: HTTP Request (Client -> Server: to_server, ESTABLISHED, content="GET")
    pkt4 = {
        "packet_id": 4,
        "src_ip": "10.0.0.1", "src_port": 12345,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "transport_proto": "TCP",
        "tcp_flags": "PA", "payload_len": 45, "timestamp": 100.3,
        "decoded_payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    }
    f4 = flow_tracker.track(pkt4)
    pkt4.update(f4)
    res4 = match_rule(rule, pkt4)
    print(f"\n2. Gói 4 (HTTP Request): State={pkt4['flow_tcp_state']}, Dir={pkt4['flow_direction']}")
    print(f"   -> Kết quả: {'MATCH' if res4['matched'] else 'NO_MATCH'} | SID: {res4.get('sid')} - {res4.get('msg')}")
    assert res4["matched"] is True, "Gói 4 thỏa mãn flow:to_server,established và content:GET phải MATCH!"

    # 5. Gói 5: HTTP Response (Server -> Client: to_client, ESTABLISHED, content="GET")
    pkt5 = {
        "packet_id": 5,
        "src_ip": "10.0.0.2", "src_port": 80,
        "dst_ip": "10.0.0.1", "dst_port": 12345,
        "transport_proto": "TCP",
        "tcp_flags": "PA", "payload_len": 50, "timestamp": 100.4,
        "decoded_payload": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nGET response"
    }
    f5 = flow_tracker.track(pkt5)
    pkt5.update(f5)
    res5 = match_rule(rule, pkt5)
    print(f"\n3. Gói 5 (HTTP Response): State={pkt5['flow_tcp_state']}, Dir={pkt5['flow_direction']}")
    print(f"   -> Kết quả: {'MATCH' if res5['matched'] else 'NO_MATCH'} (Lý do: {res5.get('reason')})")
    assert res5["matched"] is False, "Gói 5 là to_client nên không được match flow:to_server!"

    result = {
        "test_case": "TC08",
        "description": "flow:to_server,established match chính xác theo trạng thái Flow Tracker",
        "status": "PASS",
        "pkt1_syn_match": res1["matched"],
        "pkt4_request_to_server_match": res4["matched"],
        "pkt5_response_to_client_match": res5["matched"]
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc08_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 08: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc08()
