import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule

def test_tc10():
    print("=" * 60)
    print("TEST CASE 10: Giới hạn vị trí tuyệt đối (offset và depth)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc10_offset_depth_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 2

    rule_start = valid_rules[0]   # offset:0, depth:4 (USER)
    rule_window = valid_rules[1]  # offset:10, depth:10 (admin)

    # 1. Payload thỏa mãn cả 2 rule:
    # "USER xxxx admin" -> "USER" o index 0..4, "admin" o index 10..15 (trong khoang 10..20)
    payload_valid = "USER xxxx admin"
    event_valid = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 21,
        "payload_len": len(payload_valid),
        "decoded_payload": payload_valid
    }

    print(f"\n1. Kiểm tra Payload hợp lệ: '{payload_valid}'")
    res_v1 = match_rule(rule_start, event_valid)
    res_v2 = match_rule(rule_window, event_valid)
    print(f"   - Rule offset:0, depth:4: {'MATCH' if res_v1['matched'] else 'NO_MATCH'}")
    print(f"   - Rule offset:10, depth:10: {'MATCH' if res_v2['matched'] else 'NO_MATCH'}")
    assert res_v1["matched"] is True, "Phải MATCH khi USER ở đầu (index 0..4)"
    assert res_v2["matched"] is True, "Phải MATCH khi admin ở index 10..15"

    # 2. Payload mà "USER" không nằm ở đầu (bị dịch chuyển sang index 7):
    # "PREFIX USER admin"
    payload_shifted = "PREFIX USER admin"
    event_shifted = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 21,
        "payload_len": len(payload_shifted),
        "decoded_payload": payload_shifted
    }

    print(f"\n2. Kiểm tra Payload bị lệch vị trí: '{payload_shifted}'")
    res_s1 = match_rule(rule_start, event_shifted)
    print(f"   - Rule offset:0, depth:4: {'MATCH' if res_s1['matched'] else 'NO_MATCH'} (Lý do: {res_s1.get('reason')})")
    assert res_s1["matched"] is False, "KHÔNG ĐƯỢC MATCH khi USER không nằm trong vùng offset 0 depth 4"

    # 3. Payload mà "admin" nằm ngoài window [10..20] (ví dụ ở index 25):
    payload_outside = "USER                   admin"
    event_outside = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 21,
        "payload_len": len(payload_outside),
        "decoded_payload": payload_outside
    }
    print(f"\n3. Kiểm tra Payload có 'admin' ngoài window [10..20]: '{payload_outside}'")
    res_o2 = match_rule(rule_window, event_outside)
    print(f"   - Rule offset:10, depth:10: {'MATCH' if res_o2['matched'] else 'NO_MATCH'} (Lý do: {res_o2.get('reason')})")
    assert res_o2["matched"] is False, "KHÔNG ĐƯỢC MATCH khi admin nằm ngoài window depth"

    result = {
        "test_case": "TC10",
        "description": "offset/depth chỉ match trong vùng được chỉ định",
        "status": "PASS",
        "valid_payload_matches": {"rule_start": res_v1["matched"], "rule_window": res_v2["matched"]},
        "shifted_payload_match": res_s1["matched"],
        "outside_window_match": res_o2["matched"]
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc10_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 10: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc10()
