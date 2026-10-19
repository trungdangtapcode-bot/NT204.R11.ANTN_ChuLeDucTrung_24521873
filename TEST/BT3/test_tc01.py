import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file

def test_tc01():
    print("=" * 60)
    print("TEST CASE 01: Nạp file có rule hợp lệ, comment và dòng trống")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc01_rules.rules")
    valid_rules, invalid_rules, unsupported_rules, stats = load_rules_from_file(rules_file)

    print(f"[*] Thống kê nạp file:")
    print(f"    - Tổng số dòng: {stats['total_lines']}")
    print(f"    - Dòng trống: {stats['blank_lines']}")
    print(f"    - Dòng comment: {stats['comment_lines']}")
    print(f"    - Rule bị disable (# alert...): {stats['disabled']}")
    print(f"    - Rule hợp lệ (valid): {stats['valid']}")
    print(f"    - Rule không hợp lệ (invalid): {stats['invalid']}")
    print(f"    - Rule chưa hỗ trợ (unsupported): {stats['unsupported']}")

    print("\n[*] Danh sách rule hợp lệ được đưa sang parser:")
    for r in valid_rules:
        print(f"    + SID: {r.sid} | Proto: {r.protocol} | Action: {r.action} | Msg: \"{r.msg}\"")

    # Kiểm tra điều kiện PASS
    assert stats["valid"] == 3, f"Kỳ vọng 3 rule hợp lệ, nhận được {stats['valid']}"
    assert stats["invalid"] == 0, f"Kỳ vọng 0 invalid rule, nhận được {stats['invalid']}"
    assert stats["blank_lines"] > 0, "Kỳ vọng có dòng trống"
    assert stats["comment_lines"] > 0, "Kỳ vọng có comment"

    # Ghi log kết quả
    result = {
        "test_case": "TC01",
        "description": "Nạp file có rule hợp lệ, comment và dòng trống",
        "status": "PASS",
        "stats": stats,
        "valid_sids": [r.sid for r in valid_rules]
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc01_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 01: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc01()
