import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule

def test_tc05():
    print("=" * 60)
    print("TEST CASE 05: So khớp chiều gói tin (Direction -> và <>)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc05_direction_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 2

    rule_forward = valid_rules[0]  # ->
    rule_bi = valid_rules[1]       # <>

    # Gói tin chiều xuôi (Forward: 10.0.0.1:1234 -> 192.168.1.1:80)
    event_forward = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "192.168.1.1",
        "dst_port": 80
    }

    # Gói tin chiều ngược (Backward: 192.168.1.1:80 -> 10.0.0.1:1234)
    event_backward = {
        "transport_proto": "TCP",
        "src_ip": "192.168.1.1",
        "src_port": 80,
        "dst_ip": "10.0.0.1",
        "dst_port": 1234
    }

    print("\n1. Đánh giá gói tin CHIỀU XUÔI (10.0.0.1:1234 -> 192.168.1.1:80):")
    res_f1 = match_rule(rule_forward, event_forward)
    res_f2 = match_rule(rule_bi, event_forward)
    print(f"   - Rule '->' (SID 500001): {'MATCH' if res_f1['matched'] else 'NO_MATCH'}")
    print(f"   - Rule '<>' (SID 500002): {'MATCH' if res_f2['matched'] else 'NO_MATCH'}")
    assert res_f1["matched"] is True, "Rule -> phải MATCH gói chiều xuôi"
    assert res_f2["matched"] is True, "Rule <> phải MATCH gói chiều xuôi"

    print("\n2. Đánh giá gói tin CHIỀU NGƯỢC (192.168.1.1:80 -> 10.0.0.1:1234):")
    res_b1 = match_rule(rule_forward, event_backward)
    res_b2 = match_rule(rule_bi, event_backward)
    print(f"   - Rule '->' (SID 500001): {'MATCH' if res_b1['matched'] else 'NO_MATCH'} (Lý do: {res_b1.get('reason')})")
    print(f"   - Rule '<>' (SID 500002): {'MATCH' if res_b2['matched'] else 'NO_MATCH'}")
    assert res_b1["matched"] is False, "Rule -> KHÔNG ĐƯỢC MATCH gói chiều ngược"
    assert res_b2["matched"] is True, "Rule <> PHẢI MATCH gói chiều ngược"

    result = {
        "test_case": "TC05",
        "description": "Direction -> và <> so khớp đúng chiều / bidirectional",
        "status": "PASS",
        "details": {
            "forward_packet": {
                "rule_forward_match": res_f1["matched"],
                "rule_bidirectional_match": res_f2["matched"]
            },
            "backward_packet": {
                "rule_forward_match": res_b1["matched"],
                "rule_bidirectional_match": res_b2["matched"]
            }
        }
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc05_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 05: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc05()
