import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file

def test_tc02():
    print("=" * 60)
    print("TEST CASE 02: Rule sai cú pháp (Invalid Syntax)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc02_invalid_rules.rules")
    valid_rules, invalid_rules, unsupported_rules, stats = load_rules_from_file(rules_file)

    print(f"[*] Thống kê:")
    print(f"    - Hợp lệ (valid): {len(valid_rules)}")
    print(f"    - Sai cú pháp (invalid): {len(invalid_rules)}")

    print("\n[*] Chi tiết các rule bị đánh dấu invalid và lý do:")
    for idx, r in enumerate(invalid_rules, 1):
        print(f"    {idx}. Text: {r.raw_text[:50]}...")
        print(f"       -> Status: {r.status} | Reason: {r.status_reason}")

    print("\n[*] Rule hợp lệ vẫn nạp thành công (engine không dừng):")
    for r in valid_rules:
        print(f"    + SID: {r.sid} | Msg: \"{r.msg}\"")

    # Kiểm tra điều kiện PASS
    assert len(invalid_rules) == 4, f"Kỳ vọng 4 invalid rules, nhận được {len(invalid_rules)}"
    assert len(valid_rules) == 1, f"Kỳ vọng 1 valid rule, nhận được {len(valid_rules)}"
    for r in invalid_rules:
        assert r.status == "invalid", "Trạng thái phải là invalid"
        assert len(r.status_reason) > 0, "Phải có lý do cụ thể"

    result = {
        "test_case": "TC02",
        "description": "Rule sai cú pháp được đánh dấu invalid có lý do, engine không dừng",
        "status": "PASS",
        "invalid_count": len(invalid_rules),
        "invalid_details": [{"rule": r.raw_text, "reason": r.status_reason} for r in invalid_rules],
        "valid_count": len(valid_rules)
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc02_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 02: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc02()
