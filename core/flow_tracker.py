"""
Module Flow Tracker - Bài tập 2
Theo dõi và nhóm các gói tin thành luồng kết nối (Flow/Session):
- Nhóm gói tin theo 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
- Theo dõi trạng thái TCP (SYN -> ESTABLISHED -> FIN)
- Tính thống kê cho mỗi flow (packet count, byte count, duration)
- Phát hiện timeout (flow hết hạn)
"""

import time
from collections import defaultdict


# Timeout mặc định cho flow (giây)
FLOW_TIMEOUT = 120  # 2 phút


class Flow:
    """Đại diện cho một luồng kết nối (Connection/Session)."""

    def __init__(self, flow_key, first_packet_time):
        self.flow_key = flow_key
        self.src_ip = flow_key[0]
        self.dst_ip = flow_key[1]
        self.src_port = flow_key[2]
        self.dst_port = flow_key[3]
        self.protocol = flow_key[4]

        # Thống kê
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = first_packet_time
        self.last_seen = first_packet_time

        # Trạng thái TCP
        self.tcp_state = "INIT"  # INIT -> SYN_SENT -> ESTABLISHED -> FIN_WAIT -> CLOSED
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0

        # Danh sách packet_id thuộc flow này
        self.packet_ids = []

        # Application protocol đã nhận diện
        self.app_proto = "UNKNOWN"

    def update(self, event):
        """Cập nhật flow với thông tin từ packet mới."""
        self.packet_count += 1
        self.total_bytes += event.get("payload_len", 0)
        self.last_seen = event.get("timestamp", time.time())
        self.packet_ids.append(event.get("packet_id", 0))

        # Cập nhật application protocol
        app = event.get("app_proto", "UNKNOWN")
        if app != "UNKNOWN":
            self.app_proto = app

        # Cập nhật trạng thái TCP
        if self.protocol == "TCP":
            flags = event.get("tcp_flags", "")
            self._update_tcp_state(flags)

    def _update_tcp_state(self, flags):
        """Máy trạng thái TCP đơn giản."""
        if "S" in flags and "A" not in flags:
            self.syn_count += 1
            if self.tcp_state == "INIT":
                self.tcp_state = "SYN_SENT"
        elif "S" in flags and "A" in flags:
            self.tcp_state = "SYN_ACK_RECEIVED"
        elif "A" in flags and self.tcp_state == "SYN_ACK_RECEIVED":
            self.tcp_state = "ESTABLISHED"
        elif "F" in flags:
            self.fin_count += 1
            self.tcp_state = "FIN_WAIT"
            if self.fin_count >= 2:
                self.tcp_state = "CLOSED"
        elif "R" in flags:
            self.rst_count += 1
            self.tcp_state = "RESET"

        # Nếu đã qua SYN_ACK nhưng nhận thêm gói ACK/PA thì vẫn là ESTABLISHED
        if self.tcp_state == "SYN_ACK_RECEIVED" and "A" in flags and "S" not in flags:
            self.tcp_state = "ESTABLISHED"

    def is_expired(self, current_time, timeout=FLOW_TIMEOUT):
        """Kiểm tra flow đã hết hạn (timeout) chưa."""
        return (current_time - self.last_seen) > timeout

    @property
    def duration(self):
        """Thời gian kéo dài của flow."""
        return round(self.last_seen - self.start_time, 4)

    def to_dict(self):
        """Chuyển flow thành dict để ghi log."""
        return {
            "flow_key": f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}({self.protocol})",
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration": self.duration,
            "tcp_state": self.tcp_state if self.protocol == "TCP" else "N/A",
            "app_proto": self.app_proto,
            "packet_ids": self.packet_ids,
            "start_time": self.start_time,
            "last_seen": self.last_seen
        }


class FlowTracker:
    """Quản lý toàn bộ các flow đang hoạt động."""

    def __init__(self, timeout=FLOW_TIMEOUT):
        self.flows = {}  # flow_key -> Flow
        self.completed_flows = []  # Danh sách flow đã hoàn thành/timeout
        self.timeout = timeout

    def _make_flow_key(self, event):
        """
        Tạo flow key từ 5-tuple. 
        Chiều đi và chiều về cùng 1 flow (bidirectional).
        """
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        src_port = event.get("src_port", 0)
        dst_port = event.get("dst_port", 0)
        proto = event.get("transport_proto", "UNKNOWN")

        # Sắp xếp để đảm bảo chiều đi và chiều về cùng flow_key
        key1 = (src_ip, dst_ip, src_port, dst_port, proto)
        key2 = (dst_ip, src_ip, dst_port, src_port, proto)
        return min(key1, key2)

    def track(self, event):
        """
        Nhận event đã parse, gán nó vào flow tương ứng.
        Trả về flow_id để gắn vào event.
        """
        flow_key = self._make_flow_key(event)
        current_time = event.get("timestamp", time.time())

        # Kiểm tra timeout cho flow hiện tại
        if flow_key in self.flows:
            flow = self.flows[flow_key]
            if flow.is_expired(current_time, self.timeout):
                # Flow cũ đã timeout, đưa vào completed và tạo flow mới
                self.completed_flows.append(flow.to_dict())
                del self.flows[flow_key]

        # Tạo flow mới nếu chưa có
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(flow_key, current_time)

        # Cập nhật flow
        self.flows[flow_key].update(event)

        # Trả về thông tin flow
        flow = self.flows[flow_key]
        return {
            "flow_id": str(flow_key),
            "flow_packet_count": flow.packet_count,
            "flow_total_bytes": flow.total_bytes,
            "flow_duration": flow.duration,
            "flow_tcp_state": flow.tcp_state if flow.protocol == "TCP" else "N/A"
        }

    def get_all_flows(self):
        """Lấy toàn bộ flow (đang active + completed)."""
        all_flows = list(self.completed_flows)
        for flow in self.flows.values():
            all_flows.append(flow.to_dict())
        return all_flows

    def get_active_flows(self):
        """Lấy các flow đang active."""
        return [f.to_dict() for f in self.flows.values()]

    def cleanup_expired(self, current_time):
        """Dọn dẹp flow hết hạn."""
        expired_keys = [
            k for k, f in self.flows.items()
            if f.is_expired(current_time, self.timeout)
        ]
        for key in expired_keys:
            self.completed_flows.append(self.flows[key].to_dict())
            del self.flows[key]
        return len(expired_keys)


# Instance toàn cục để dùng xuyên suốt pipeline
flow_tracker = FlowTracker()
