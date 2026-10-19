import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file
from core.rule_matcher import match_rule

def test_tc12():
    print("=" * 60)
    print("TEST CASE 12: So khớp TCP flags và kích thước payload (dsize)")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc12_flags_dsize_rules.rules")
    valid_rules, _, _, _ = load_rules_from_file(rules_file)
    assert len(valid_rules) == 2

    rule_syn = valid_rules[0]   # flags:S; dsize:0;
    rule_pa = valid_rules[1]    # flags:PA; dsize:>50;

    # 1. Gói tin 1: SYN thuần túy, payload = 0
    event_syn_0 = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "tcp_flags": "S",
        "payload_len": 0
    }
    print("\n1. Gói tin 1: flags='S', payload_len=0:")
    res_s1 = match_rule(rule_syn, event_syn_0)
    print(f"   - Rule 1 (flags:S, dsize:0): {'MATCH' if res_s1['matched'] else 'NO_MATCH'}")
    assert res_s1["matched"] is True, "Phải MATCH khi flags='S' và dsize=0"

    # 2. Gói tin 2: SYN nhưng có payload rác (payload_len = 20) -> không thỏa dsize:0
    event_syn_payload = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "tcp_flags": "S",
        "payload_len": 20
    }
    print("\n2. Gói tin 2: flags='S', payload_len=20 (> 0):")
    res_s2 = match_rule(rule_syn, event_syn_payload)
    print(f"   - Rule 1 (flags:S, dsize:0): {'MATCH' if res_s2['matched'] else 'NO_MATCH'} (Lý do: {res_s2.get('reason')})")
    assert res_s2["matched"] is False, "KHÔNG ĐƯỢC MATCH khi dsize != 0"

    # 3. Gói tin 3: PSH+ACK, payload = 100 bytes (> 50)
    event_pa_100 = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "tcp_flags": "PA",
        "payload_len": 100
    }
    print("\n3. Gói tin 3: flags='PA', payload_len=100 (> 50):")
    res_pa1 = match_rule(rule_pa, event_pa_100)
    print(f"   - Rule 2 (flags:PA, dsize:>50): {'MATCH' if res_pa1['matched'] else 'NO_MATCH'}")
    assert res_pa1["matched"] is True, "Phải MATCH khi flags='PA' và payload_len > 50"

    # 4. Gói tin 4: Cờ chỉ có ACK (thiếu P), payload = 100 -> không thỏa flags:PA
    event_a_100 = {
        "transport_proto": "TCP",
        "src_ip": "10.0.0.1", "src_port": 1234,
        "dst_ip": "10.0.0.2", "dst_port": 80,
        "tcp_flags": "A",
        "payload_len": 100
    }
    print("\n4. Gói tin 4: flags='A' (thiếu P), payload_len=100:")
    res_pa2 = match_rule(rule_pa, event_a_100)
    print(f"   - Rule 2 (flags:PA, dsize:>50): {'MATCH' if res_pa2['matched'] else 'NO_MATCH'} (Lý do: {res_pa2.get('reason')})")
    assert res_pa2["matched"] is False, "KHÔNG ĐƯỢC MATCH khi thiếu cờ P"

    result = {
        "test_case": "TC12",
        "description": "flags và dsize match/không match đúng theo event",
        "status": "PASS",
        "results": {
            "syn_empty_match": res_s1["matched"],
            "syn_with_data_match": res_s2["matched"],
            "psh_ack_large_match": res_pa1["matched"],
            "ack_only_match": res_pa2["matched"]
        }
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc12_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 12: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc12()
