"""
Module Rule Evaluation Engine & Detection Event Generator - Bài tập 3
- Nhận normalized event và flow context từ Pipeline.
- Truy vấn Rule Repository / Indexer để lấy danh sách candidate rules.
- Đánh giá từng candidate rule thông qua Rule Matching Engine.
- Cho phép nhiều rule cùng match 1 event (multi-match).
- Sinh Detection Event chuẩn hóa và theo dõi thống kê hiệu năng.
"""

from core.rule_matcher import match_rule


def generate_detection_event(rule_match, event):
    """
    Detection Event Generator:
    Sinh Detection Event có cấu trúc chuẩn hóa khi một rule match.
    Đầy đủ các trường: timestamp, sid, rev, msg, priority, classtype,
    5-tuple, protocol, application_protocol, flow_id, matched_information.
    """
    proto = event.get("transport_proto", "IP")
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    src_port = event.get("src_port", "")
    dst_port = event.get("dst_port", "")

    five_tuple = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} / {proto}"

    detection_event = {
        "timestamp": event.get("timestamp", 0),
        "sid": rule_match.get("sid", 0),
        "rev": rule_match.get("rev", 1),
        "msg": rule_match.get("msg", ""),
        "priority": rule_match.get("priority", 3),
        "classtype": rule_match.get("classtype", ""),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "application_protocol": event.get("app_proto", "UNKNOWN"),
        "flow_id": event.get("flow_id", "N/A"),
        "5-tuple": five_tuple,
        "matched_information": rule_match.get("matched_info", "")
    }
    return detection_event


class RuleEvaluationEngine:
    """
    Engine điều phối việc đánh giá rules cho mỗi event:
    Event + Flow Context -> Query Indexer -> Matcher -> Generator -> Alerts
    """

    def __init__(self, repository=None):
        self.repository = repository
        # Thống kê theo dõi
        self.total_events_evaluated = 0
        self.total_candidates_checked = 0
        self.total_matches = 0

    def set_repository(self, repository):
        """Gán hoặc cập nhật repository."""
        self.repository = repository

    def evaluate(self, event):
        """
        Đánh giá một event với tập rules trong repository.
        Trả về danh sách các Detection Events đã match.
        """
        self.total_events_evaluated += 1
        alerts = []

        if not self.repository or self.repository.count() == 0:
            return alerts

        # 1. Lấy candidate rules từ Indexer
        candidates = self.repository.get_candidate_rules(event)
        self.total_candidates_checked += len(candidates)

        # 2. Duyệt qua từng candidate rule (không dừng ở match đầu tiên)
        for rule in candidates:
            match_res = match_rule(rule, event)
            if match_res.get("matched", False):
                self.total_matches += 1
                det_event = generate_detection_event(match_res, event)
                alerts.append(det_event)

        return alerts

    def get_stats(self):
        """Lấy thông tin thống kê hiệu năng đánh giá."""
        return {
            "events_evaluated": self.total_events_evaluated,
            "candidates_checked": self.total_candidates_checked,
            "total_matches": self.total_matches
        }

    def reset_stats(self):
        """Đặt lại bộ đếm thống kê."""
        self.total_events_evaluated = 0
        self.total_candidates_checked = 0
        self.total_matches = 0
