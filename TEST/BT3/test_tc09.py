import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule

def test_tc09():
    print("=" * 60)
    print("TEST CASE 09: content có / không có nocase")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc09_nocase_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 2

    rule_nocase = valid_rules[0]   # có nocase
    rule_casesens = valid_rules[1] # không có nocase

    # 1. Payload chữ hoa-thường lẫn lộn: "cMd.EXE"
    event_mixed = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "payload_len": 30,
        "decoded_payload": "GET /scripts/cMd.EXE?/c+dir HTTP/1.1"
    }

    print("\n1. Đánh giá payload hỗn hợp hoa-thường ('cMd.EXE'):")
    res_m1 = match_rule(rule_nocase, event_mixed)
    res_m2 = match_rule(rule_casesens, event_mixed)
    print(f"   - Rule có nocase (SID 900001): {'MATCH' if res_m1['matched'] else 'NO_MATCH'}")
    print(f"   - Rule không nocase (SID 900002): {'MATCH' if res_m2['matched'] else 'NO_MATCH'} (Lý do: {res_m2.get('reason')})")
    assert res_m1["matched"] is True, "Rule nocase PHẢI MATCH chuỗi 'cMd.EXE'"
    assert res_m2["matched"] is False, "Rule case-sensitive KHÔNG ĐƯỢC MATCH 'cMd.EXE'"

    # 2. Payload chữ thường chính xác: "cmd.exe"
    event_lower = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "payload_len": 30,
        "decoded_payload": "GET /scripts/cmd.exe?/c+dir HTTP/1.1"
    }

    print("\n2. Đánh giá payload chữ thường chính xác ('cmd.exe'):")
    res_l1 = match_rule(rule_nocase, event_lower)
    res_l2 = match_rule(rule_casesens, event_lower)
    print(f"   - Rule có nocase (SID 900001): {'MATCH' if res_l1['matched'] else 'NO_MATCH'}")
    print(f"   - Rule không nocase (SID 900002): {'MATCH' if res_l2['matched'] else 'NO_MATCH'}")
    assert res_l1["matched"] is True, "Rule nocase PHẢI MATCH 'cmd.exe'"
    assert res_l2["matched"] is True, "Rule case-sensitive PHẢI MATCH 'cmd.exe'"

    result = {
        "test_case": "TC09",
        "description": "content có/không có nocase phân biệt hoặc không phân biệt hoa thường đúng",
        "status": "PASS",
        "mixed_case_result": {
            "nocase_rule_matched": res_m1["matched"],
            "case_sensitive_rule_matched": res_m2["matched"]
        },
        "exact_case_result": {
            "nocase_rule_matched": res_l1["matched"],
            "case_sensitive_rule_matched": res_l2["matched"]
        }
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc09_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 09: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc09()
