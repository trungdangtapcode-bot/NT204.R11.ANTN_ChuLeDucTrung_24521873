"""
Module Decoder - Bài tập 2
Giải mã các dạng mã hóa phổ biến trong giao thức mạng:
- HTTP: URL encoding (%20, %3C...) 
- HTTP: HTML entities (&lt; &amp; &#60;...)
- SMTP: Base64
- SMTP: Quoted-Printable
- Hỗ trợ UTF-8 và ASCII, không crash khi gặp byte lỗi.
"""

import urllib.parse
import html
import base64
import quopri
import re


def decode_url(data: str) -> str:
    """
    Giải mã URL encoding (Percent-encoding).
    VD: "Hello%20World%21" -> "Hello World!"
        "/search?q=%3Cscript%3E" -> "/search?q=<script>"
    """
    try:
        return urllib.parse.unquote(data, encoding='utf-8', errors='replace')
    except Exception:
        return data


def decode_html_entities(data: str) -> str:
    """
    Giải mã HTML entities.
    VD: "&lt;script&gt;" -> "<script>"
        "&#60;b&#62;" -> "<b>"
        "&amp;" -> "&"
    """
    try:
        return html.unescape(data)
    except Exception:
        return data


def decode_base64(data: str) -> str:
    """
    Giải mã Base64 (thường dùng trong SMTP để mã hóa nội dung email).
    VD: "SGVsbG8gV29ybGQ=" -> "Hello World"
    """
    try:
        decoded_bytes = base64.b64decode(data, validate=True)
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception:
        return data


def decode_quoted_printable(data: str) -> str:
    """
    Giải mã Quoted-Printable (mã hóa ký tự đặc biệt trong email).
    VD: "Hello=20World=21" -> "Hello World!"
        "=C3=A9" -> "é"
    """
    try:
        decoded_bytes = quopri.decodestring(data.encode('ascii', errors='replace'))
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception:
        return data


def is_base64(data: str) -> bool:
    """
    Kiểm tra chuỗi có phải Base64 hợp lệ hay không.
    """
    if not data or len(data) < 4:
        return False
    # Base64 chỉ chứa A-Z, a-z, 0-9, +, /, = và độ dài chia hết cho 4
    pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    if not pattern.match(data.strip()):
        return False
    if len(data.strip()) % 4 != 0:
        return False
    return True


def is_quoted_printable(data: str) -> bool:
    """
    Kiểm tra chuỗi có chứa dấu hiệu Quoted-Printable hay không.
    VD: "=20", "=3D", soft line break "=\\n"
    """
    return bool(re.search(r'=[0-9A-Fa-f]{2}', data))


def decode_payload(payload: str, app_proto: str = None) -> dict:
    """
    Hàm tổng hợp: Tự động nhận diện loại mã hóa và giải mã payload.
    Trả về dict chứa:
    - decoded_payload: Chuỗi đã giải mã
    - encoding_detected: Loại mã hóa đã phát hiện (url, html_entity, base64, quoted_printable, none)
    """
    if not payload or not isinstance(payload, str):
        return {"decoded_payload": payload, "encoding_detected": "none"}

    result = {
        "decoded_payload": payload,
        "encoding_detected": "none"
    }

    # HTTP: Ưu tiên URL encoding
    if app_proto == "HTTP":
        if '%' in payload:
            decoded = decode_url(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                result["encoding_detected"] = "url_encoding"
                payload = decoded  # Tiếp tục decode HTML entity nếu có

        if '&' in payload and ';' in payload:
            decoded = decode_html_entities(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                if result["encoding_detected"] == "url_encoding":
                    result["encoding_detected"] = "url_encoding+html_entity"
                else:
                    result["encoding_detected"] = "html_entity"

    # SMTP: Kiểm tra Base64 hoặc Quoted-Printable
    elif app_proto == "SMTP":
        if is_base64(payload):
            decoded = decode_base64(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                result["encoding_detected"] = "base64"
        elif is_quoted_printable(payload):
            decoded = decode_quoted_printable(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                result["encoding_detected"] = "quoted_printable"

    # Fallback: Thử tự phát hiện nếu chưa biết protocol
    else:
        if '%' in payload:
            decoded = decode_url(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                result["encoding_detected"] = "url_encoding"
        elif is_base64(payload):
            decoded = decode_base64(payload)
            if decoded != payload:
                result["decoded_payload"] = decoded
                result["encoding_detected"] = "base64"

    return result
