"""
Module Rule Parser & Validator - Bài tập 3
Phân tích cú pháp Snort rule text thành Internal Rule Object.
Kiểm tra cú pháp, keyword được hỗ trợ, và các trường bắt buộc.
Phân loại: valid / invalid / unsupported với lý do.
"""

import re
import ipaddress


# Các keyword được hỗ trợ
SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev",
    "content", "nocase", "offset", "depth", "distance", "within",
    "flags", "dsize",
    "flow",
    "classtype", "priority",
    "reference", "metadata"
}

# Các protocol được hỗ trợ
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}

# Các action được hỗ trợ
SUPPORTED_ACTIONS = {"alert", "log", "pass", "drop", "reject", "sdrop"}


class RuleObject:
    """Internal Rule Object - đại diện cho một Snort rule đã parse."""

    def __init__(self):
        # Header fields
        self.action = ""
        self.protocol = ""
        self.src_ip = ""
        self.src_port = ""
        self.direction = ""
        self.dst_ip = ""
        self.dst_port = ""

        # Identification
        self.msg = ""
        self.sid = 0
        self.rev = 0

        # Content matches - danh sách các content check
        self.contents = []  # List of ContentMatch objects

        # Packet/TCP
        self.flags = ""
        self.dsize = ""  # ">100", "<200", "100<>200", "100"

        # Flow
        self.flow = []  # ["to_server", "established", ...]

        # Classification
        self.classtype = ""
        self.priority = 0

        # Metadata
        self.raw_text = ""
        self.status = "valid"  # valid / invalid / unsupported
        self.status_reason = ""

    def __repr__(self):
        return f"RuleObject(sid={self.sid}, msg='{self.msg}', status={self.status})"


class ContentMatch:
    """Đại diện cho một content match với các modifier."""

    def __init__(self, pattern, negated=False):
        self.pattern = pattern       # Nội dung cần tìm (string)
        self.negated = negated       # content:!"xxx"
        self.nocase = False          # Không phân biệt hoa thường
        self.offset = None           # Vị trí bắt đầu tuyệt đối
        self.depth = None            # Độ sâu tuyệt đối
        self.distance = None         # Khoảng cách tương đối từ match trước
        self.within = None           # Giới hạn tương đối từ match trước

    def __repr__(self):
        mods = []
        if self.nocase: mods.append("nocase")
        if self.offset is not None: mods.append(f"offset:{self.offset}")
        if self.depth is not None: mods.append(f"depth:{self.depth}")
        if self.distance is not None: mods.append(f"distance:{self.distance}")
        if self.within is not None: mods.append(f"within:{self.within}")
        mod_str = ", ".join(mods)
        return f"ContentMatch('{self.pattern}'{', ' + mod_str if mod_str else ''})"


def _convert_hex_content(raw):
    """Chuyển đổi hex escape |XX XX| trong content thành ký tự."""
    result = ""
    i = 0
    while i < len(raw):
        if raw[i] == '|':
            # Tìm closing |
            end = raw.index('|', i + 1)
            hex_str = raw[i + 1:end].strip()
            if hex_str:
                for h in hex_str.split():
                    result += chr(int(h, 16))
            i = end + 1
        else:
            result += raw[i]
            i += 1
    return result


def _parse_port(port_str):
    """Validate và trả về port string (any, single, range, negation)."""
    port_str = port_str.strip()
    if port_str == "any":
        return port_str
    # Negation
    if port_str.startswith("!"):
        inner = port_str[1:]
        _parse_port(inner)  # Validate inner
        return port_str
    # Group [port1,port2,...]
    if port_str.startswith("[") and port_str.endswith("]"):
        return port_str
    # Range
    if ":" in port_str:
        parts = port_str.split(":")
        if len(parts) == 2:
            if parts[0] and not parts[0].isdigit():
                raise ValueError(f"Invalid port range: {port_str}")
            if parts[1] and not parts[1].isdigit():
                raise ValueError(f"Invalid port range: {port_str}")
            return port_str
        raise ValueError(f"Invalid port range: {port_str}")
    # Single port
    if port_str.isdigit():
        return port_str
    raise ValueError(f"Invalid port: {port_str}")


def _validate_ip(ip_str):
    """Validate IP address (any, single IPv4, CIDR, negation, group)."""
    ip_str = ip_str.strip()
    if ip_str in ("any", "$HOME_NET", "$EXTERNAL_NET"):
        return ip_str
    # Variable
    if ip_str.startswith("$"):
        return ip_str
    # Negation
    if ip_str.startswith("!"):
        return ip_str
    # Group [ip1,ip2,...]
    if ip_str.startswith("[") and ip_str.endswith("]"):
        return ip_str
    # CIDR
    if "/" in ip_str:
        try:
            ipaddress.ip_network(ip_str, strict=False)
            return ip_str
        except ValueError:
            raise ValueError(f"Invalid CIDR: {ip_str}")
    # Single IPv4
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        raise ValueError(f"Invalid IP: {ip_str}")


def _parse_options(options_str, rule_obj):
    """Parse phần options của rule (trong ngoặc đơn)."""
    # Tách các option bằng dấu ;
    # Cần xử lý content chứa dấu ; bên trong quotes
    options = []
    current = ""
    in_quotes = False
    for ch in options_str:
        if ch == '"' and (not current or current[-1] != '\\'):
            in_quotes = not in_quotes
            current += ch
        elif ch == ';' and not in_quotes:
            current = current.strip()
            if current:
                options.append(current)
            current = ""
        else:
            current += ch
    current = current.strip()
    if current:
        options.append(current)

    current_content = None  # ContentMatch hiện tại để gắn modifier

    for opt in options:
        if ':' in opt:
            # Tìm dấu : đầu tiên
            colon_idx = opt.index(':')
            keyword = opt[:colon_idx].strip().lower()
            value = opt[colon_idx + 1:].strip()
        else:
            keyword = opt.strip().lower()
            value = ""

        # Kiểm tra keyword có được hỗ trợ không
        if keyword not in SUPPORTED_KEYWORDS:
            rule_obj.status = "unsupported"
            rule_obj.status_reason = f"Unsupported keyword: {keyword}"
            # Vẫn tiếp tục parse các keyword khác
            continue

        # Parse từng keyword
        if keyword == "msg":
            rule_obj.msg = value.strip('"')

        elif keyword == "sid":
            try:
                rule_obj.sid = int(value)
            except ValueError:
                rule_obj.status = "invalid"
                rule_obj.status_reason = f"Invalid sid: {value}"

        elif keyword == "rev":
            try:
                rule_obj.rev = int(value)
            except ValueError:
                rule_obj.status = "invalid"
                rule_obj.status_reason = f"Invalid rev: {value}"

        elif keyword == "content":
            # Xử lý negation
            negated = False
            content_val = value.strip()
            if content_val.startswith("!"):
                negated = True
                content_val = content_val[1:].strip()

            # Bỏ quotes
            content_val = content_val.strip('"')

            # Chuyển hex
            try:
                pattern = _convert_hex_content(content_val)
            except (ValueError, IndexError):
                pattern = content_val

            current_content = ContentMatch(pattern, negated)
            rule_obj.contents.append(current_content)

        elif keyword == "nocase":
            if current_content:
                current_content.nocase = True

        elif keyword == "offset":
            if current_content:
                try:
                    current_content.offset = int(value)
                except ValueError:
                    rule_obj.status = "invalid"
                    rule_obj.status_reason = f"Invalid offset: {value}"

        elif keyword == "depth":
            if current_content:
                try:
                    current_content.depth = int(value)
                except ValueError:
                    rule_obj.status = "invalid"
                    rule_obj.status_reason = f"Invalid depth: {value}"

        elif keyword == "distance":
            if current_content:
                try:
                    current_content.distance = int(value)
                except ValueError:
                    rule_obj.status = "invalid"
                    rule_obj.status_reason = f"Invalid distance: {value}"

        elif keyword == "within":
            if current_content:
                try:
                    current_content.within = int(value)
                except ValueError:
                    rule_obj.status = "invalid"
                    rule_obj.status_reason = f"Invalid within: {value}"

        elif keyword == "flags":
            rule_obj.flags = value.strip()

        elif keyword == "dsize":
            rule_obj.dsize = value.strip()

        elif keyword == "flow":
            rule_obj.flow = [f.strip() for f in value.split(",")]

        elif keyword == "classtype":
            rule_obj.classtype = value.strip()

        elif keyword == "priority":
            try:
                rule_obj.priority = int(value)
            except ValueError:
                rule_obj.status = "invalid"
                rule_obj.status_reason = f"Invalid priority: {value}"

        elif keyword in ("reference", "metadata"):
            # Cho phép nhưng không xử lý
            pass


def parse_rule(rule_text):
    """
    Parse một dòng Snort rule text thành RuleObject.
    Trả về RuleObject với status = valid / invalid / unsupported.
    """
    rule_obj = RuleObject()
    rule_obj.raw_text = rule_text.strip()

    try:
        text = rule_obj.raw_text

        # Tách header và options
        # Format: action proto src_ip src_port direction dst_ip dst_port (options)
        paren_idx = text.index('(')
        header_str = text[:paren_idx].strip()
        options_str = text[paren_idx + 1:].rstrip(')')

        # Parse header
        header_parts = header_str.split()
        if len(header_parts) != 7:
            rule_obj.status = "invalid"
            rule_obj.status_reason = f"Invalid header: expected 7 parts, got {len(header_parts)}"
            return rule_obj

        action, proto, src_ip, src_port, direction, dst_ip, dst_port = header_parts

        # Validate action
        if action.lower() not in SUPPORTED_ACTIONS:
            rule_obj.status = "invalid"
            rule_obj.status_reason = f"Unknown action: {action}"
            return rule_obj
        rule_obj.action = action.lower()

        # Validate protocol
        if proto.lower() not in SUPPORTED_PROTOCOLS:
            rule_obj.status = "unsupported"
            rule_obj.status_reason = f"Unsupported protocol: {proto}"
            return rule_obj
        rule_obj.protocol = proto.lower()

        # Validate direction
        if direction not in ("->", "<>"):
            rule_obj.status = "invalid"
            rule_obj.status_reason = f"Invalid direction: {direction}"
            return rule_obj
        rule_obj.direction = direction

        # Validate IPs
        rule_obj.src_ip = _validate_ip(src_ip)
        rule_obj.dst_ip = _validate_ip(dst_ip)

        # Validate ports
        rule_obj.src_port = _parse_port(src_port)
        rule_obj.dst_port = _parse_port(dst_port)

        # Parse options
        _parse_options(options_str, rule_obj)

        # Validate bắt buộc: sid
        if rule_obj.status == "valid" and rule_obj.sid == 0:
            rule_obj.status = "invalid"
            rule_obj.status_reason = "Missing required field: sid"

    except ValueError as e:
        rule_obj.status = "invalid"
        rule_obj.status_reason = str(e)
    except Exception as e:
        rule_obj.status = "invalid"
        rule_obj.status_reason = f"Parse error: {str(e)}"

    return rule_obj
