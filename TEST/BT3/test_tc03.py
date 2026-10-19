import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file

def test_tc03():
    print("=" * 60)
    print("TEST CASE 03: Rule dùng keyword ngoài phạm vi (Unsupported)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc03_unsupported_rules.rules")
    valid_rules, invalid_rules, unsupported_rules, stats = load_rules_from_file(rules_file)

    print(f"[*] Thống kê:")
    print(f"    - Hợp lệ (valid): {len(valid_rules)}")
    print(f"    - Chưa hỗ trợ (unsupported): {len(unsupported_rules)}")
    print(f"    - Không hợp lệ (invalid): {len(invalid_rules)}")

    print("\n[*] Chi tiết các rule bị đánh dấu unsupported (không crash chương trình):")
    for idx, r in enumerate(unsupported_rules, 1):
        print(f"    {idx}. Text: {r.raw_text}")
        print(f"       -> Status: {r.status} | Reason: {r.status_reason}")

    print("\n[*] Rule hợp lệ vẫn chạy bình thường:")
    for r in valid_rules:
        print(f"    + SID: {r.sid} | Msg: \"{r.msg}\"")

    # Kiểm tra điều kiện PASS
    assert len(unsupported_rules) == 3, f"Kỳ vọng 3 unsupported rules, nhận được {len(unsupported_rules)}"
    assert len(valid_rules) == 1, f"Kỳ vọng 1 valid rule, nhận được {len(valid_rules)}"
    for r in unsupported_rules:
        assert r.status == "unsupported", "Trạng thái phải là unsupported"
        assert len(r.status_reason) > 0, "Phải có lý do cụ thể"

    result = {
        "test_case": "TC03",
        "description": "Rule dùng keyword ngoài phạm vi được đánh dấu unsupported, không crash",
        "status": "PASS",
        "unsupported_count": len(unsupported_rules),
        "unsupported_details": [{"rule": r.raw_text, "reason": r.status_reason} for r in unsupported_rules],
        "valid_count": len(valid_rules)
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc03_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 03: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc03()
