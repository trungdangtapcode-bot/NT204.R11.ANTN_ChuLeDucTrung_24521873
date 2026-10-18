"""
Module Rule Repository & Indexer - Bài tập 3
Lưu trữ các rule đã được validate và tạo chỉ mục (index) để chọn lọc candidate rules
nhanh chóng theo protocol, port và IP thay vì phải duyệt toàn bộ rules.
"""

from collections import defaultdict


class RuleRepository:
    """Lưu trữ và đánh chỉ mục các rule Snort đã được validate."""

    def __init__(self):
        self.rules = []  # Danh sách toàn bộ valid rules
        self.rules_by_sid = {}  # Tra cứu theo sid

        # Chỉ mục theo protocol (tcp, udp, icmp, ip)
        self.proto_index = defaultdict(list)

        # Chỉ mục theo destination port cho TCP và UDP
        # key: (proto, dport_str) -> list[rule]
        self.dport_index = defaultdict(list)
        # Các rule có dst_port là "any" hoặc port range phức tạp
        self.any_dport_index = defaultdict(list)

    def add_rule(self, rule_obj):
        """Thêm một rule hợp lệ vào repository và tạo index."""
        if rule_obj.status != "valid":
            return False

        self.rules.append(rule_obj)
        self.rules_by_sid[rule_obj.sid] = rule_obj

        proto = rule_obj.protocol.lower()
        self.proto_index[proto].append(rule_obj)

        # Index theo dst_port
        dport = rule_obj.dst_port
        if dport == "any" or ":" in dport or dport.startswith("[") or dport.startswith("!"):
            self.any_dport_index[proto].append(rule_obj)
        else:
            self.dport_index[(proto, dport)].append(rule_obj)

        return True

    def add_rules(self, rule_list):
        """Thêm danh sách rules vào repository."""
        added_count = 0
        for r in rule_list:
            if self.add_rule(r):
                added_count += 1
        return added_count

    def get_candidate_rules(self, event):
        """
        Lấy tập candidate rules phù hợp với event dựa vào protocol và port.
        Loại bỏ sớm các rule không khớp ở tầng header trước khi matching sâu.
        """
        transport_proto = event.get("transport_proto", "").lower()
        if not transport_proto:
            ip_proto = event.get("ip_proto", 0)
            if ip_proto == 1:
                transport_proto = "icmp"
            elif ip_proto == 6:
                transport_proto = "tcp"
            elif ip_proto == 17:
                transport_proto = "udp"
            else:
                transport_proto = "ip"

        candidates = set()

        # 1. Rules quy định giao thức "ip" khớp với mọi traffic IP
        for r in self.proto_index.get("ip", []):
            candidates.add(r)

        # 2. Rules cho protocol cụ thể (tcp/udp/icmp)
        proto_rules = self.proto_index.get(transport_proto, [])
        if not proto_rules:
            return list(candidates)

        dst_port = str(event.get("dst_port", ""))
        src_port = str(event.get("src_port", ""))

        # Thêm các rule có dst_port khớp trực tiếp
        if dst_port:
            for r in self.dport_index.get((transport_proto, dst_port), []):
                candidates.add(r)

        # Thêm các rule có dst_port là any hoặc port range
        for r in self.any_dport_index.get(transport_proto, []):
            candidates.add(r)

        # Nếu rule có direction <> (hai chiều), traffic chiều ngược lại cũng cần xét
        if src_port:
            for r in self.dport_index.get((transport_proto, src_port), []):
                if r.direction == "<>":
                    candidates.add(r)

        return list(candidates)

    def get_all_rules(self):
        """Trả về toàn bộ rules trong repository."""
        return list(self.rules)

    def count(self):
        """Số lượng rules đang lưu trữ."""
        return len(self.rules)
