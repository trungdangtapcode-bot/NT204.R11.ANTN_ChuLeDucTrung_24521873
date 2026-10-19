import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_indexer import RuleRepository

def test_tc06():
    print("=" * 60)
    print("TEST CASE 06: Indexer với IP, TCP, UDP và any (Candidate Rules)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc06_indexer_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)

    repo = RuleRepository()
    repo.add_rules(valid_rules)
    print(f"[*] Đã nạp và lập chỉ mục {repo.count()} rules vào Repository.")

    # 1. Truy vấn Candidate cho gói TCP port 80
    event_tcp_80 = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_ip": "192.168.1.1",
        "dst_port": 80
    }
    candidates_tcp_80 = repo.get_candidate_rules(event_tcp_80)
    cand_sids_tcp_80 = sorted([r.sid for r in candidates_tcp_80])
    print(f"\n1. Gói tin TCP port 80:")
    print(f"   - Candidate SIDs: {cand_sids_tcp_80}")
    # Kỳ vọng: 600001 (ip any), 600002 (tcp 80), 600004 (tcp any). KHÔNG có 600003 (tcp 443), KHÔNG có UDP
    expected_tcp_80 = [600001, 600002, 600004]
    print(f"   - Kỳ vọng: {expected_tcp_80}")
    assert cand_sids_tcp_80 == expected_tcp_80, f"Lỗi candidate TCP 80: {cand_sids_tcp_80}"

    # 2. Truy vấn Candidate cho gói UDP port 53
    event_udp_53 = {
        "transport_proto": "UDP",
        "src_ip": "10.0.0.1",
        "src_port": 50001,
        "dst_ip": "8.8.8.8",
        "dst_port": 53
    }
    candidates_udp_53 = repo.get_candidate_rules(event_udp_53)
    cand_sids_udp_53 = sorted([r.sid for r in candidates_udp_53])
    print(f"\n2. Gói tin UDP port 53:")
    print(f"   - Candidate SIDs: {cand_sids_udp_53}")
    # Kỳ vọng: 600001 (ip any), 600005 (udp 53), 600006 (udp any). KHÔNG có TCP rules
    expected_udp_53 = [600001, 600005, 600006]
    print(f"   - Kỳ vọng: {expected_udp_53}")
    assert cand_sids_udp_53 == expected_udp_53, f"Lỗi candidate UDP 53: {cand_sids_udp_53}"

    result = {
        "test_case": "TC06",
        "description": "Indexer với IP, TCP, UDP và any trả đúng tập candidate rules",
        "status": "PASS",
        "tcp_80_candidates": cand_sids_tcp_80,
        "udp_53_candidates": cand_sids_udp_53
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc06_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 06: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc06()
