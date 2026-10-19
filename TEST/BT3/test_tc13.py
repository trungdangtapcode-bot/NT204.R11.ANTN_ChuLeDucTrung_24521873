import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_indexer import RuleRepository
from core.rule_evaluator import RuleEvaluationEngine

def test_tc13():
    print("=" * 60)
    print("TEST CASE 13: Một event match đồng thời >= 2 rule (Multi-match)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc13_multimatch_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 4

    repo = RuleRepository()
    repo.add_rules(valid_rules)

    evaluator = RuleEvaluationEngine(repo)

    # Event tấn công SQL Injection chứa: "' UNION SELECT username, password"
    # Sẽ match đồng thời Rule 1 (UNION SELECT), Rule 2 (' UNION), Rule 3 (password)
    # KHÔNG match Rule 4 (/etc/shadow)
    event = {
        "timestamp": 1729340000.123,
        "transport_proto": "TCP",
        "app_proto": "HTTP",
        "src_ip": "10.0.0.5", "src_port": 52133,
        "dst_ip": "192.168.1.20", "dst_port": 80,
        "payload_len": 65,
        "flow_id": "('10.0.0.5', '192.168.1.20', 52133, 80, 'TCP')",
        "decoded_payload": "GET /login.php?user=admin' UNION SELECT username, password FROM users--"
    }

    print(f"[*] Payload kiểm thử: \"{event['decoded_payload']}\"")
    print(f"[*] Đang thực hiện đánh giá (Evaluation Engine)...")

    alerts = evaluator.evaluate(event)

    print(f"\n[*] Kết quả sinh Alert (Tổng cộng: {len(alerts)} alerts):")
    for idx, alert in enumerate(alerts, 1):
        print(f"    {idx}. [SID: {alert['sid']}] Msg: \"{alert['msg']}\" (Priority: {alert['priority']})")
        print(f"       -> Match info: {alert['matched_information']}")

    # Kiểm tra điều kiện PASS
    assert len(alerts) >= 2, f"Kỳ vọng ít nhất 2 alerts match, nhưng chỉ có {len(alerts)}"
    assert len(alerts) == 3, f"Kỳ vọng đúng 3 rules match, nhận được {len(alerts)}"
    matched_sids = [a["sid"] for a in alerts]
    assert 1300001 in matched_sids
    assert 1300002 in matched_sids
    assert 1300003 in matched_sids
    assert 1300004 not in matched_sids, "Rule 4 không được match"

    stats = evaluator.get_stats()
    print(f"\n[*] Thống kê evaluator: Events={stats['events_evaluated']}, Candidates={stats['candidates_checked']}, Matches={stats['total_matches']}")

    result = {
        "test_case": "TC13",
        "description": "Một event match đồng thời >= 2 rule sinh đầy đủ tất cả kết quả match",
        "status": "PASS",
        "matched_count": len(alerts),
        "matched_sids": matched_sids,
        "stats": stats
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc13_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 13: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc13()
