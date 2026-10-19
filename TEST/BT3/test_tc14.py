import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_indexer import RuleRepository
from core.rule_evaluator import RuleEvaluationEngine

def test_tc14():
    print("=" * 60)
    print("TEST CASE 14: Chuẩn hóa Detection Event (Đủ tất cả các trường)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc14_detection_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 1

    repo = RuleRepository()
    repo.add_rules(valid_rules)
    evaluator = RuleEvaluationEngine(repo)

    # Event tấn công Directory Traversal
    event = {
        "timestamp": 1729345678.999,
        "src_ip": "10.0.0.5",
        "src_port": 52133,
        "dst_ip": "192.168.1.20",
        "dst_port": 80,
        "transport_proto": "TCP",
        "app_proto": "HTTP",
        "flow_id": "('10.0.0.5', '192.168.1.20', 52133, 80, 'TCP')",
        "payload_len": 40,
        "decoded_payload": "GET /../../../../etc/passwd HTTP/1.1\r\n\r\n"
    }

    alerts = evaluator.evaluate(event)
    assert len(alerts) == 1, "Kỳ vọng sinh 1 Detection Event"

    det = alerts[0]

    print("\n[*] Chi tiết các trường trong Detection Event sinh ra:")
    print(f"    - sid / rev: {det['sid']} / {det['rev']}")
    print(f"    - msg / priority: {det['msg']} / {det['priority']}")
    print(f"    - classtype: {det['classtype']}")
    print(f"    - 5-tuple: {det['5-tuple']}")
    print(f"    - protocol: {det['protocol']}")
    print(f"    - application_protocol: {det['application_protocol']}")
    print(f"    - flow_id: {det['flow_id']}")
    print(f"    - matched_information: {det['matched_information']}")

    # Kiểm tra đầy đủ các trường tối thiểu theo đề bài:
    required_fields = [
        "timestamp", "sid", "rev", "msg", "priority", "classtype",
        "5-tuple", "protocol", "application_protocol", "flow_id", "matched_information"
    ]
    for field in required_fields:
        assert field in det, f"Thiếu trường bắt buộc: {field}"
        assert det[field] is not None and str(det[field]) != "", f"Trường {field} không được rỗng"

    assert det["sid"] == 1400001
    assert det["msg"] == "Directory traversal detected"
    assert det["application_protocol"] == "HTTP"
    assert "content=" in det["matched_information"]

    result = {
        "test_case": "TC14",
        "description": "Detection Event có đủ sid/msg/flow/5-tuple/protocol/match info",
        "status": "PASS",
        "detection_event": det
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc14_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 14: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc14()
