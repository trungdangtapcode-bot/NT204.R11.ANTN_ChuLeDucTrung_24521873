import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule

def test_tc11():
    print("=" * 60)
    print("TEST CASE 11: Hai content với distance và within (Relative Matching)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc11_relative_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 1
    rule = valid_rules[0]

    # 1. Payload thỏa mãn: "login" kết thúc ở vị trí 5, distance 1 -> tìm từ vị trí 6, within 15 -> trong khoảng [6..21]
    # "login?password=123" -> "password" ở vị trí 6
    payload_valid = "login?password=123"
    event_valid = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "payload_len": len(payload_valid),
        "decoded_payload": payload_valid
    }
    print(f"\n1. Payload thỏa mãn khoảng cách tương đối: '{payload_valid}'")
    res_v = match_rule(rule, event_valid)
    print(f"   -> Kết quả: {'MATCH' if res_v['matched'] else 'NO_MATCH'} | SID: {res_v.get('sid')} | {res_v.get('matched_info')}")
    assert res_v["matched"] is True, "Phải MATCH khi password nằm trong khoảng distance 1, within 15 sau login"

    # 2. Payload bị quá xa (nằm ngoài within 15):
    payload_far = "login?padding_qua_dai_lam_vuot_qua_gioi_han_within_password=123"
    event_far = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "payload_len": len(payload_far),
        "decoded_payload": payload_far
    }
    print(f"\n2. Payload có 'password' quá xa sau 'login' (> within 15): '{payload_far[:40]}...'")
    res_f = match_rule(rule, event_far)
    print(f"   -> Kết quả: {'MATCH' if res_f['matched'] else 'NO_MATCH'} (Lý do: {res_f.get('reason')})")
    assert res_f["matched"] is False, "KHÔNG ĐƯỢC MATCH khi khoảng cách vượt quá within"

    # 3. Payload có thứ tự ngược: "password" xuất hiện trước "login"
    payload_rev = "password before login"
    event_rev = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "payload_len": len(payload_rev),
        "decoded_payload": payload_rev
    }
    print(f"\n3. Payload có thứ tự ngược ('password' trước 'login'): '{payload_rev}'")
    res_r = match_rule(rule, event_rev)
    print(f"   -> Kết quả: {'MATCH' if res_r['matched'] else 'NO_MATCH'} (Lý do: {res_r.get('reason')})")
    assert res_r["matched"] is False, "KHÔNG ĐƯỢC MATCH khi thứ tự relative bị ngược"

    result = {
        "test_case": "TC11",
        "description": "Hai content với distance/within relative matching đúng",
        "status": "PASS",
        "valid_match": res_v["matched"],
        "too_far_match": res_f["matched"],
        "reversed_order_match": res_r["matched"]
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc11_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 11: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc11()
