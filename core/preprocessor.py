"""
Module Preprocessor - Bài tập 2
Chuẩn hóa dữ liệu sau khi decode:
- Loại bỏ ký tự null (\\x00), whitespace thừa
- Chuẩn hóa case (lowercase) cho các trường cần so sánh
- Loại bỏ các ký tự điều khiển không in được
- Trích xuất feature cơ bản (payload_entropy, payload_length_normalized)
"""

import math
import re
from collections import Counter


def remove_null_bytes(data: str) -> str:
    """Loại bỏ ký tự null \\x00."""
    return data.replace('\x00', '')


def remove_control_chars(data: str) -> str:
    """Loại bỏ ký tự điều khiển không in được (trừ \\r\\n\\t)."""
    return re.sub(r'[^\x09\x0a\x0d\x20-\x7e\x80-\xff]', '', data)


def normalize_whitespace(data: str) -> str:
    """Chuẩn hóa whitespace thừa thành 1 khoảng trắng."""
    return re.sub(r'[ \t]+', ' ', data).strip()


def normalize_case(data: str) -> str:
    """Chuyển về lowercase để phục vụ so sánh/phát hiện."""
    return data.lower()


def calculate_entropy(data: str) -> float:
    """
    Tính Shannon Entropy của chuỗi.
    Giá trị cao (~7-8) gợi ý dữ liệu mã hóa/nén/mã độc.
    Giá trị thấp (~1-3) gợi ý text bình thường.
    """
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(event: dict) -> dict:
    """
    Trích xuất feature từ event đã parse.
    Trả về dict bổ sung các trường feature.
    """
    features = {}

    # Feature 1: Payload length
    payload_len = event.get("payload_len", 0)
    features["feature_payload_len"] = payload_len

    # Feature 2: Entropy của decoded payload
    decoded = event.get("decoded_payload", "")
    if decoded and isinstance(decoded, str):
        features["feature_entropy"] = calculate_entropy(decoded)
    else:
        features["feature_entropy"] = 0.0

    # Feature 3: Số lượng ký tự đặc biệt (gợi ý tấn công injection)
    if decoded and isinstance(decoded, str):
        special_chars = re.findall(r'[<>\'";(){}|&$`\\]', decoded)
        features["feature_special_char_count"] = len(special_chars)
    else:
        features["feature_special_char_count"] = 0

    # Feature 4: Tỷ lệ ký tự không phải ASCII
    if decoded and isinstance(decoded, str) and len(decoded) > 0:
        non_ascii = sum(1 for c in decoded if ord(c) > 127)
        features["feature_non_ascii_ratio"] = round(non_ascii / len(decoded), 4)
    else:
        features["feature_non_ascii_ratio"] = 0.0

    # Feature 5: Có chứa IP/domain dạng số hay không
    features["feature_has_ip_in_payload"] = bool(
        re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(decoded))
    )

    return features


def preprocess_event(event: dict) -> dict:
    """
    Hàm tổng hợp: Chuẩn hóa và trích xuất feature cho event.
    """
    # Chuẩn hóa decoded_payload
    decoded = event.get("decoded_payload", "")
    if decoded and isinstance(decoded, str):
        cleaned = remove_null_bytes(decoded)
        cleaned = remove_control_chars(cleaned)
        cleaned = normalize_whitespace(cleaned)
        event["cleaned_payload"] = cleaned
        event["normalized_payload"] = normalize_case(cleaned)

    # Trích xuất features
    features = extract_features(event)
    event.update(features)

    event["preprocessed"] = True
    return event
