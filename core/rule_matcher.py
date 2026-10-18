"""
Module Rule Matching Engine - Bài tập 3
Đánh giá một rule Snort với normalized event và flow context:
- Header matching: protocol, src/dst IP (any, single IPv4, CIDR, negation),
  src/dst port (any, single, range, negation), direction (->, <>).
- Flow matching: to_server, to_client, established, not_established.
- Packet/TCP matching: flags, dsize.
- Content matching: content, nocase, offset, depth, distance, within, negation.
"""

import ipaddress
import re


def _match_single_ip(rule_ip, pkt_ip):
    """So khớp một IP đơn lẻ, any hoặc CIDR."""
    if not pkt_ip or rule_ip == "any":
        return True
    if "/" in rule_ip:
        try:
            return ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(rule_ip, strict=False)
        except ValueError:
            return False
    return rule_ip == pkt_ip


def match_ip(rule_ip_pattern, pkt_ip):
    """So khớp IP hỗ trợ any, CIDR, negation !, và group []."""
    if not rule_ip_pattern or rule_ip_pattern in ("any", "$HOME_NET", "$EXTERNAL_NET"):
        return True
    if not pkt_ip:
        return False

    pattern = rule_ip_pattern.strip()
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:].strip()

    # Nhóm [ip1, ip2, ...]
    if pattern.startswith("[") and pattern.endswith("]"):
        items = [i.strip() for i in pattern[1:-1].split(",") if i.strip()]
        matched = any(_match_single_ip(i, pkt_ip) for i in items)
    else:
        matched = _match_single_ip(pattern, pkt_ip)

    return not matched if negated else matched


def _match_single_port(rule_port, pkt_port):
    """So khớp một port đơn lẻ, any hoặc port range."""
    if rule_port == "any":
        return True
    try:
        p = int(pkt_port)
    except (ValueError, TypeError):
        return False

    # Port range
    if ":" in rule_port:
        parts = rule_port.split(":")
        low = int(parts[0]) if parts[0] else 0
        high = int(parts[1]) if parts[1] else 65535
        return low <= p <= high

    try:
        return int(rule_port) == p
    except ValueError:
        return False


def match_port(rule_port_pattern, pkt_port):
    """So khớp port hỗ trợ any, single, range (:1024, 1024:, 1024:2048), negation, group."""
    if not rule_port_pattern or rule_port_pattern == "any":
        return True
    if pkt_port is None:
        return False

    pattern = str(rule_port_pattern).strip()
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:].strip()

    if pattern.startswith("[") and pattern.endswith("]"):
        items = [i.strip() for i in pattern[1:-1].split(",") if i.strip()]
        matched = any(_match_single_port(i, pkt_port) for i in items)
    else:
        matched = _match_single_port(pattern, pkt_port)

    return not matched if negated else matched


def match_header(rule, event):
    """
    So khớp header: protocol, src/dst IP, src/dst port, direction (->, <>).
    """
    # 1. Protocol
    pkt_proto = event.get("transport_proto", "").lower()
    if not pkt_proto:
        ip_proto = event.get("ip_proto", 0)
        if ip_proto == 1:
            pkt_proto = "icmp"
        elif ip_proto == 6:
            pkt_proto = "tcp"
        elif ip_proto == 17:
            pkt_proto = "udp"
        else:
            pkt_proto = "ip"

    if rule.protocol != "ip" and rule.protocol != pkt_proto:
        return False

    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    src_port = event.get("src_port")
    dst_port = event.get("dst_port")

    # 2. Direction và IPs/Ports
    if rule.direction == "->":
        if not match_ip(rule.src_ip, src_ip):
            return False
        if not match_port(rule.src_port, src_port):
            return False
        if not match_ip(rule.dst_ip, dst_ip):
            return False
        if not match_port(rule.dst_port, dst_port):
            return False
        return True

    elif rule.direction == "<>":
        forward = (
            match_ip(rule.src_ip, src_ip) and
            match_port(rule.src_port, src_port) and
            match_ip(rule.dst_ip, dst_ip) and
            match_port(rule.dst_port, dst_port)
        )
        if forward:
            return True
        backward = (
            match_ip(rule.src_ip, dst_ip) and
            match_port(rule.src_port, dst_port) and
            match_ip(rule.dst_ip, src_ip) and
            match_port(rule.dst_port, src_port)
        )
        return backward

    return False


def match_flags(rule_flags, event_flags):
    """So khớp cờ TCP (ví dụ flags:S, flags:FA, flags:!A)."""
    if not rule_flags:
        return True
    if not event_flags:
        return False

    rf = rule_flags.strip()
    negated = rf.startswith("!")
    if negated:
        rf = rf[1:].strip()

    # Trong Snort, flags kiểm tra xem các cờ chỉ định có được set không
    # Ví dụ: S -> kiểm tra cờ S có trong event_flags không
    # Nếu rf có nhiều ký tự như 'SA' -> kiểm tra cả S và A
    matched = all(flag in event_flags for flag in rf)
    return not matched if negated else matched


def match_dsize(rule_dsize, payload_len):
    """So khớp kích thước payload (dsize: >100, <50, 100<>200, 100)."""
    if not rule_dsize:
        return True
    ds = rule_dsize.strip()

    if "<>" in ds:
        # Range dsize: 100<>200
        parts = ds.split("<>")
        low = int(parts[0])
        high = int(parts[1])
        return low < payload_len < high
    elif ds.startswith(">"):
        val = int(ds[1:])
        return payload_len > val
    elif ds.startswith("<"):
        val = int(ds[1:])
        return payload_len < val
    elif ds.isdigit():
        return payload_len == int(ds)

    return True


def match_flow(rule_flow_list, event):
    """
    So khớp flow options: to_server, to_client, established, not_established.
    """
    if not rule_flow_list:
        return True

    tcp_state = event.get("flow_tcp_state", "")
    flow_dir = event.get("flow_direction", "to_server")

    for opt in rule_flow_list:
        opt = opt.strip()
        if opt == "to_server":
            if flow_dir != "to_server":
                return False
        elif opt == "to_client":
            if flow_dir != "to_client":
                return False
        elif opt == "established":
            if tcp_state != "ESTABLISHED":
                return False
        elif opt == "not_established":
            if tcp_state == "ESTABLISHED":
                return False

    return True


def _get_search_targets(event):
    """Thu thập toàn bộ chuỗi payload / application data cần kiểm tra."""
    targets = []
    # 1. Payload đã decode & chuẩn hóa
    if event.get("decoded_payload"):
        targets.append(str(event["decoded_payload"]))
    if event.get("normalized_payload"):
        targets.append(str(event["normalized_payload"]))

    # 2. Các trường application data cụ thể
    if event.get("http_url"):
        targets.append(str(event["http_url"]))
    if event.get("http_body"):
        targets.append(str(event["http_body"]))
    if event.get("smtp_command"):
        targets.append(str(event["smtp_command"]))
    if event.get("dns_query_domain"):
        targets.append(str(event["dns_query_domain"]))

    # Loại bỏ rỗng và trùng lặp nhưng giữ thứ tự
    seen = set()
    unique_targets = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            unique_targets.append(t)

    return unique_targets


def _match_contents_in_text(contents, text):
    """
    So khớp chuỗi các content (với offset, depth, distance, within) trong một text payload.
    Trả về (matched: bool, matched_strs: list).
    """
    prev_end = None
    matched_strs = []

    for idx, c in enumerate(contents):
        pattern = c.pattern
        search_space = text

        # Xử lý nocase
        if c.nocase:
            search_pattern = pattern.lower()
            effective_text = search_space.lower()
        else:
            search_pattern = pattern
            effective_text = search_space

        text_len = len(effective_text)

        # Xác định khoảng tìm kiếm (start_idx, end_idx)
        if idx == 0 or (c.distance is None and c.within is None):
            # Tuyệt đối (Absolute modifiers: offset, depth)
            start_idx = c.offset if c.offset is not None else 0
            if start_idx >= text_len:
                if c.negated:
                    continue
                return False, []

            if c.depth is not None:
                end_idx = min(start_idx + c.depth, text_len)
            else:
                end_idx = text_len
        else:
            # Tương đối (Relative modifiers: distance, within)
            if prev_end is None:
                prev_end = 0

            start_idx = prev_end + (c.distance if c.distance is not None else 0)
            if start_idx >= text_len:
                if c.negated:
                    continue
                return False, []

            if c.within is not None:
                end_idx = min(start_idx + c.within, text_len)
            else:
                end_idx = text_len

        if start_idx > end_idx or start_idx >= text_len:
            if c.negated:
                continue
            return False, []

        window = effective_text[start_idx:end_idx]
        pos_in_window = window.find(search_pattern)

        if pos_in_window != -1:
            # Tìm thấy
            if c.negated:
                return False, []
            found_pos = start_idx + pos_in_window
            prev_end = found_pos + len(search_pattern)
            matched_strs.append(pattern)
        else:
            # Không tìm thấy
            if not c.negated:
                return False, []
            # Nếu negated và không tìm thấy thì là PASS

    return True, matched_strs


def match_contents(contents, event):
    """
    So khớp danh sách content với tất cả payload targets trong event.
    """
    if not contents:
        return True, []

    targets = _get_search_targets(event)
    if not targets:
        # Nếu không có payload mà tất cả content đều là negated thì PASS
        if all(c.negated for c in contents):
            return True, ["negated_content_passed"]
        return False, []

    # Thử match trên từng target (hoặc trên toàn bộ target gộp lại)
    for target in targets:
        matched, matched_strs = _match_contents_in_text(contents, target)
        if matched:
            return True, matched_strs

    # Nếu có nhiều target (vd url và body riêng lẻ), thử nối lại thành 1 chuỗi lớn
    if len(targets) > 1:
        combined = " ".join(targets)
        matched, matched_strs = _match_contents_in_text(contents, combined)
        if matched:
            return True, matched_strs

    return False, []


def match_rule(rule, event):
    """
    Đánh giá toàn diện một rule đối với một event:
    1. Header (protocol, IP, port, direction)
    2. TCP Flags & dsize
    3. Flow options
    4. Content options
    Trả về dict {matched: bool, ...}
    """
    if rule.status != "valid":
        return {"matched": False, "reason": f"Rule not valid ({rule.status_reason})"}

    # 1. Header matching
    if not match_header(rule, event):
        return {"matched": False, "reason": "Header mismatch"}

    # 2. TCP flags
    if rule.flags:
        if not match_flags(rule.flags, event.get("tcp_flags", "")):
            return {"matched": False, "reason": "TCP flags mismatch"}

    # 3. Payload dsize
    if rule.dsize:
        payload_len = event.get("payload_len", 0)
        if not match_dsize(rule.dsize, payload_len):
            return {"matched": False, "reason": "dsize mismatch"}

    # 4. Flow state
    if rule.flow:
        if not match_flow(rule.flow, event):
            return {"matched": False, "reason": "Flow state mismatch"}

    # 5. Content matching
    if rule.contents:
        content_matched, matched_items = match_contents(rule.contents, event)
        if not content_matched:
            return {"matched": False, "reason": "Content mismatch"}
        match_info = f"content='{', '.join(matched_items)}'"
    else:
        match_info = "header/flow match"

    return {
        "matched": True,
        "sid": rule.sid,
        "rev": rule.rev,
        "msg": rule.msg,
        "priority": rule.priority,
        "classtype": rule.classtype,
        "matched_info": match_info
    }
