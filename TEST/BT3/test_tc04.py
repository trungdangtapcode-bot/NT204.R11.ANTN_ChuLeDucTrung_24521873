import sys, os, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.rule_loader import load_rules_from_file

def test_tc04():
    print("=" * 60)
    print("TEST CASE 04: Parse header TCP + any/single IP/CIDR + port/range")
    print("=" * 60)

    rules_file = os.path.join(os.path.dirname(__file__), "tc04_header_rules.rules")
    valid_rules, invalid_rules, unsupported_rules, stats = load_rules_from_file(rules_file)

    assert len(valid_rules) == 3, f"Kỳ vọng 3 rule hợp lệ, nhận được {len(valid_rules)}"

    r1, r2, r3 = valid_rules

    print("\n[*] Kiểm tra Rule 1 (Single IP, Single Port):")
    print(f"    - Protocol: {r1.protocol} (Kỳ vọng: tcp)")
    print(f"    - Src IP: {r1.src_ip} (Kỳ vọng: any)")
    print(f"    - Src Port: {r1.src_port} (Kỳ vọng: any)")
    print(f"    - Direction: {r1.direction} (Kỳ vọng: ->)")
    print(f"    - Dst IP: {r1.dst_ip} (Kỳ vọng: 192.168.1.100)")
    print(f"    - Dst Port: {r1.dst_port} (Kỳ vọng: 80)")
    assert r1.protocol == "tcp" and r1.src_ip == "any" and r1.src_port == "any"
    assert r1.dst_ip == "192.168.1.100" and r1.dst_port == "80" and r1.direction == "->"

    print("\n[*] Kiểm tra Rule 2 (CIDR IP, Port Range):")
    print(f"    - Protocol: {r2.protocol} (Kỳ vọng: tcp)")
    print(f"    - Src IP: {r2.src_ip} (Kỳ vọng: 10.0.0.0/24)")
    print(f"    - Src Port: {r2.src_port} (Kỳ vọng: 1024:65535)")
    print(f"    - Direction: {r2.direction} (Kỳ vọng: ->)")
    print(f"    - Dst IP: {r2.dst_ip} (Kỳ vọng: any)")
    print(f"    - Dst Port: {r2.dst_port} (Kỳ vọng: :1024)")
    assert r2.protocol == "tcp" and r2.src_ip == "10.0.0.0/24" and r2.src_port == "1024:65535"
    assert r2.dst_ip == "any" and r2.dst_port == ":1024"

    print("\n[*] Kiểm tra Rule 3 (UDP any all):")
    print(f"    - Protocol: {r3.protocol} (Kỳ vọng: udp)")
    print(f"    - Src IP: {r3.src_ip}, Dst IP: {r3.dst_ip} (Kỳ vọng: any)")
    print(f"    - Src Port: {r3.src_port}, Dst Port: {r3.dst_port} (Kỳ vọng: any)")
    assert r3.protocol == "udp" and r3.src_ip == "any" and r3.dst_ip == "any"

    result = {
        "test_case": "TC04",
        "description": "Parse header TCP + any/single IP/CIDR + port/range thành Internal Rule Object đúng",
        "status": "PASS",
        "rules_parsed": [
            {
                "sid": r.sid,
                "msg": r.msg,
                "protocol": r.protocol,
                "src_ip": r.src_ip,
                "src_port": r.src_port,
                "direction": r.direction,
                "dst_ip": r.dst_ip,
                "dst_port": r.dst_port
            }
            for r in valid_rules
        ]
    }
    result_path = os.path.join(os.path.dirname(__file__), "tc04_result.jsonl")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print("\n" + "=" * 60)
    print(">> KẾT QUẢ TEST CASE 04: [PASS]")
    print(f">> Log kết quả: {result_path}")
    print("=" * 60)

if __name__ == "__main__":
    test_tc04()
