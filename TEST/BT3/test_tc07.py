import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule, match_header

def test_tc07():
    print("=" * 60)
    print("TEST CASE 07: Header không match -> Rule bị loại trước content matching")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc07_header_mismatch_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 1
    rule = valid_rules[0]

    # Gói tin có payload chứa đúng content "password", NHƯNG header không khớp:
    # Rule yêu cầu: dst_ip 192.168.1.99, dst_port 8080
    # Packet thực tế: dst_ip 10.0.0.1, dst_port 80
    event = {
        "transport_proto": "TCP",
        "src_ip": "172.16.0.5",
        "src_port": 54321,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "payload_len": 25,
        "decoded_payload": "user=admin&password=secret123"
    }

    print(f"[*] Rule yêu cầu:")
    print(f"    - Dst: {rule.dst_ip}:{rule.dst_port}")
    print(f"    - Content: \"{rule.contents[0].pattern}\"")

    print(f"\n[*] Gói tin kiểm thử:")
    print(f"    - Dst: {event['dst_ip']}:{event['dst_port']}")
    print(f"    - Payload: \"{event['decoded_payload']}\" (Chứa content 'password')")

    # 1. Kiểm tra header matching
    header_ok = match_header(rule, event)
    print(f"\n[*] Bước 1: Kiểm tra Header: {'KHỚP' if header_ok else 'KHÔNG KHỚP (BỊ LOẠI)'}")
    assert header_ok is False, "Header phải KHÔNG khớp!"

    # 2. Kiểm tra kết quả match_rule
    match_result = match_rule(rule, event)
    print(f"[*] Bước 2: Kết quả đánh giá Rule: {'MATCH' if match_result['matched'] else 'NO_MATCH'}")
    print(f"    - Lý do loại: {match_result.get('reason')}")
    assert match_result["matched"] is False
    assert match_result.get("reason") == "Header mismatch"

    result = {
        "test_case": "TC07",
        "description": "Header không match thì rule bị loại ngay trước khi xét content",
        "status": "PASS",
        "header_matched": header_ok,
        "rule_matched": match_result["matched"],
        "rejection_reason": match_result.get("reason")
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc07_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 07: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc07()
