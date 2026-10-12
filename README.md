---
title: 'BÁO CÁO BÀI TẬP 2: Decoder – Preprocessor – Flow Tracker'

---

# BÁO CÁO BÀI TẬP 2: Decoder – Preprocessor – Flow Tracker

**Môn học:** Hệ thống tìm kiếm, phát hiện và ngăn ngừa xâm nhập  
**Sinh viên:** Chu Lê Đức Trung  
**MSSV:** 24521873  
**Lớp:** NT204.R11.ANTN  
**GitHub:** [NT204.R11.ANTN_ChuLeDucTrung_24521873](https://github.com/trungdangtapcode-bot/NT204.R11.ANTN_ChuLeDucTrung_24521873)

---

## 1. Tổng quan kiến trúc hệ thống

Bài tập 2 mở rộng pipeline IDS từ Bài tập 1 bằng cách thêm 3 module mới vào giữa luồng xử lý. Luồng xử lý tổng thể sau khi hoàn thành:

```
Raw Packet
  │
  ├─ 1. capture.py         → Bắt gói tin (live / file pcap)
  ├─ 2. network.py          → Parse tầng Network (IPv4: IP nguồn, IP đích)
  ├─ 3. transport.py         → Parse tầng Transport (TCP/UDP: Port, Flags)
  ├─ 4. application.py       → Parse tầng Application (HTTP, DNS, SMTP)
  ├─ 5. decoder.py           → [MỚI] Giải mã payload (URL, HTML, Base64, QP)
  ├─ 6. preprocessor.py      → [MỚI] Chuẩn hóa + trích xuất feature
  ├─ 7. flow_tracker.py      → [MỚI] Theo dõi luồng kết nối (Flow)
  └─ 8. logger.py            → Ghi log JSON Lines
```

Toàn bộ quá trình được điều phối bởi file `core/pipeline.py` — mỗi gói tin đi tuần tự qua tất cả các bước trên.

---

## 2. Module 1: Decoder (`core/decoder.py`)

### 2.1. Mục tiêu
Giải mã các dạng mã hóa phổ biến trong giao thức mạng, giúp IDS nhìn thấy nội dung thực sự mà attacker có thể cố giấu sau các lớp encoding.

### 2.2. Các loại mã hóa được hỗ trợ

| Loại mã hóa | Giao thức | Ví dụ | Kết quả |
|---|---|---|---|
| URL Encoding | HTTP | `%3Cscript%3E` | `<script>` |
| HTML Entities | HTTP | `&lt;script&gt;` | `<script>` |
| Base64 | SMTP | `SGVsbG8gV29ybGQ=` | `Hello World` |
| Quoted-Printable | SMTP | `Hello=20World=21` | `Hello World!` |

### 2.3. Cách hoạt động

Hàm chính `decode_payload(payload, app_proto)` hoạt động theo logic:

1. **Nếu app_proto là HTTP:** Ưu tiên kiểm tra URL encoding (tìm ký tự `%`), sau đó kiểm tra HTML entities (tìm `&...;`). Có thể decode cả 2 lớp liên tiếp nếu payload bị mã hóa kép.
2. **Nếu app_proto là SMTP:** Kiểm tra payload có phải Base64 hợp lệ không (dùng regex kiểm tra bộ ký tự và chia hết cho 4). Nếu không thì kiểm tra Quoted-Printable (tìm pattern `=XX`).
3. **Fallback:** Nếu chưa biết protocol, thử tự nhận diện URL encoding hoặc Base64.

### 2.4. Xử lý lỗi
- Mọi hàm decode đều bọc trong `try...except`, nếu xảy ra lỗi thì trả về dữ liệu gốc thay vì crash.
- Sử dụng `errors='replace'` khi decode UTF-8 để thay thế byte lỗi bằng ký tự `�`.

### 2.5. Thư viện sử dụng
- `urllib.parse.unquote()` — giải mã URL encoding.
- `html.unescape()` — giải mã HTML entities.
- `base64.b64decode()` — giải mã Base64.
- `quopri.decodestring()` — giải mã Quoted-Printable.

---

## 3. Module 2: Preprocessor (`core/preprocessor.py`)

### 3.1. Mục tiêu
Chuẩn hóa dữ liệu sau khi decode và trích xuất các tính năng đặc trưng phục vụ cho việc phát hiện xâm nhập.

### 3.2. Các bước chuẩn hóa 
| Bước | Hàm | Mô tả |
|---|---|---|
| 1 | `remove_null_bytes()` | Loại bỏ ký tự null `\x00` |
| 2 | `remove_control_chars()` | Loại bỏ ký tự điều khiển không in được (giữ lại `\r\n\t`) |
| 3 | `normalize_whitespace()` | Gộp nhiều khoảng trắng liên tiếp thành 1 |
| 4 | `normalize_case()` | Chuyển toàn bộ sang lowercase để so sánh thống nhất |

Kết quả: Event được bổ sung 2 trường mới:
- `cleaned_payload`: Payload đã được làm sạch.
- `normalized_payload`: Payload đã lowercase (dùng cho rule matching sau này).

### 3.3. Các feature được trích xuất

| Feature | Ý nghĩa | Ứng dụng trong IDS |
|---|---|---|
| `feature_payload_len` | Kích thước payload (bytes) | Phát hiện gói tin bất thường (quá lớn/quá nhỏ) |
| `feature_entropy` | Shannon Entropy của payload | Giá trị cao (~7-8) gợi ý dữ liệu mã hóa/nén/mã độc |
| `feature_special_char_count` | Số ký tự đặc biệt `< > ' " ; ( ) { }` | Phát hiện tấn công injection (SQL, XSS) |
| `feature_non_ascii_ratio` | Tỷ lệ ký tự không phải ASCII | Phát hiện dữ liệu nhị phân trong text protocol |
| `feature_has_ip_in_payload` | Có chứa địa chỉ IP trong payload | Phát hiện C2 callback, data exfiltration |

### 3.4. Công thức tính Shannon Entropy

$$H = -\sum_{i=1}^{n} p_i \cdot \log_2(p_i)$$

Trong đó $p_i$ là xác suất xuất hiện của ký tự thứ $i$ trong chuỗi. Entropy càng cao thì dữ liệu càng hỗn loạn (ngẫu nhiên), gợi ý nội dung bị mã hóa hoặc nén.

---

## 4. Module 3: Flow Tracker (`core/flow_tracker.py`)

### 4.1. Mục tiêu
Nhóm các gói tin rời rạc thành các luồng kết nối, theo dõi trạng thái TCP, và tính thống kê cho từng flow.

### 4.2. Kiến trúc

Module gồm 2 class chính:

**Class `Flow`:** Đại diện cho một kết nối, lưu trữ:
- 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Thống kê: `packet_count`, `total_bytes`, `duration`
- Trạng thái TCP: Máy trạng thái đơn giản
- Danh sách `packet_ids` thuộc flow

**Class `FlowTracker`:** Quản lý toàn bộ flow đang hoạt động:
- Tạo flow key từ 5-tuple (bidirectional: chiều đi và chiều về cùng 1 flow)
- Gán gói tin vào flow tương ứng
- Phát hiện flow timeout (mặc định 120 giây)

### 4.3. Bidirectional Flow Key

Để gom chiều đi (`A → B`) và chiều về (`B → A`) vào cùng 1 flow, em sử dụng kỹ thuật sắp xếp:

```python
key1 = (src_ip, dst_ip, src_port, dst_port, proto)
key2 = (dst_ip, src_ip, dst_port, src_port, proto)
return min(key1, key2)  # Luôn chọn key nhỏ hơn
```

Nhờ vậy, dù gói tin đi từ `10.0.0.1:5000 → 10.0.0.2:80` hay ngược lại `10.0.0.2:80 → 10.0.0.1:5000`, chúng đều cùng chung 1 flow_key.

### 4.4. Máy trạng thái TCP

```
INIT → SYN_SENT → SYN_ACK_RECEIVED → ESTABLISHED → FIN_WAIT → CLOSED
                                                   ↘ RESET (nếu nhận RST)
```

| Cờ TCP nhận được | Trạng thái chuyển sang |
|---|---|
| SYN (không ACK) | `INIT → SYN_SENT` |
| SYN + ACK | `SYN_SENT → SYN_ACK_RECEIVED` |
| ACK (sau SYN-ACK) | `SYN_ACK_RECEIVED → ESTABLISHED` |
| FIN | `ESTABLISHED → FIN_WAIT` |
| FIN (lần 2) | `FIN_WAIT → CLOSED` |
| RST | `→ RESET` |

### 4.5. Flow Timeout
- Mỗi flow có trường `last_seen` ghi lại thời điểm gói tin cuối cùng.
- Nếu `current_time - last_seen > 120 giây`, flow được đánh dấu hết hạn và chuyển vào `completed_flows`.
- Flow mới sẽ được tạo nếu có gói tin tiếp theo cùng 5-tuple.

---

## 5. Tích hợp vào Pipeline (`core/pipeline.py`)

Pipeline xử lý tuần tự 7 bước cho mỗi gói tin:

```python
def process_packet(packet, capture_time):
    # 1. Network Parser    → Lấy IP nguồn, IP đích
    # 2. Transport Parser   → Lấy Port, TCP Flags
    # 3. Application Parser → Nhận diện HTTP/DNS/SMTP
    # 4. Decoder            → Giải mã URL/Base64/HTML...
    # 5. Preprocessor       → Chuẩn hóa + trích xuất feature
    # 6. Flow Tracker       → Gán vào flow, theo dõi TCP state
    # 7. Logger             → Ghi ra file JSON Lines
```

Mỗi bước bổ sung thêm thông tin vào object `event`. Cuối pipeline, `event` chứa đầy đủ: IP, Port, Protocol, decoded payload, features, flow info - sẵn sàng cho Detection Engine ở bài sau.

---

## 6. Kết quả kiểm thử (14 Test Case)

### 6.1. Nhóm Decoder (T01–T04)

| TC | Mô tả | Input | Output | Kết quả |
|---|---|---|---|---|
| T01 | URL encoding | `%3Cscript%3Ealert(...)` | `<script>alert('XSS')` | ✅ PASS |
| T02 | HTML entities | `&lt;script&gt;` | `<script>` | ✅ PASS |
| T03 | Base64 (SMTP) | Chuỗi Base64 mã hóa email | Giải mã ra plaintext | ✅ PASS |
| T04 | Quoted-Printable | `Hello=20World=21` | `Hello World!` | ✅ PASS |

### 6.2. Nhóm Preprocessor (T05–T06, T10–T11)

| TC | Mô tả | Kết quả nổi bật | Kết quả |
|---|---|---|---|
| T05 | Null byte injection | Ký tự `\x00` bị loại bỏ hoàn toàn | ✅ PASS |
| T06 | High entropy data | Entropy rất cao (~7-8), gợi ý encrypted | ✅ PASS |
| T10 | SQL injection chars | `feature_special_char_count = 2` (phát hiện `'` và `;`) | ✅ PASS |
| T11 | Non-ASCII (tiếng Việt) | Xử lý UTF-8 bình thường, không crash | ✅ PASS |

### 6.3. Nhóm Flow Tracker (T07–T09, T12–T14)

| TC | Mô tả | Kết quả nổi bật | Kết quả |
|---|---|---|---|
| T07 | TCP full session | 7 gói tin cùng 1 flow, trạng thái: `SYN_SENT → ESTABLISHED → CLOSED` | ✅ PASS |
| T08 | UDP DNS flows | 2 flow DNS riêng biệt (google.com, facebook.com) | ✅ PASS |
| T09 | Mixed flows | DNS (UDP) và HTTP (TCP) tách đúng thành 2 flow khác nhau | ✅ PASS |
| T12 | Multiple destinations | 5 flow SYN riêng biệt đến 5 IP khác nhau | ✅ PASS |
| T13 | TCP RST | Trạng thái chuyển sang `RESET` khi nhận cờ RST | ✅ PASS |
| T14 | Empty payload | Gói tin rỗng xử lý bình thường, không crash | ✅ PASS |

**Tổng kết: 14/14 test case PASS.**

---

## 7. Cấu trúc thư mục dự án

```
NT204.R11.ANTN_ChuLeDucTrung_24521873/
│
├── main.py                    # Điểm khởi chạy (CLI: --interface / --pcap)
├── requirements.txt           # Thư viện: scapy
├── .gitignore
├── README.md
│
├── core/                      # Logic xử lý chính
│   ├── capture.py             # Bắt gói tin (Bài 1)
│   ├── pipeline.py            # Pipeline điều phối (Bài 1 + 2)
│   ├── decoder.py             # Giải mã payload (Bài 2) ★
│   ├── preprocessor.py        # Chuẩn hóa + feature extraction (Bài 2) ★
│   └── flow_tracker.py        # Theo dõi luồng kết nối (Bài 2) ★
│
├── parsers/                   # Parser theo từng tầng (Bài 1)
│   ├── network.py             # Tầng Network (IPv4)
│   ├── transport.py           # Tầng Transport (TCP, UDP)
│   └── application.py         # Tầng Application (HTTP, DNS, SMTP)
│
├── utils/
│   └── logger.py              # Ghi log JSON Lines
│
└── TEST/                      # Kết quả kiểm thử
    ├── gen_bt2_testcases.py   # Script sinh 14 file PCAP mẫu
    ├── t01_url_encoding.pcap  # ... đến t14_empty_payload.pcap
    └── t01_result.jsonl       # ... đến t14_result.jsonl
```

---

## 8. Lịch sử Git (Commit History cho Bài tập 2)

Mỗi task và mỗi test case được commit riêng biệt, đúng theo yêu cầu nộp bài:

| # | Commit Message | Loại |
|---|---|---|
| 1 | `Implement Decoder module (URL encoding, HTML entities, Base64, Quoted-Printable)` | Task |
| 2 | `Implement Preprocessor module (normalization, feature extraction)` | Task |
| 3 | `Implement Flow/Connection Tracker (5-tuple, TCP state machine, bidirectional)` | Task |
| 4 | `BT2 - Testcase 01: Decode URL encoding in HTTP` | Test |
| 5 | `BT2 - Testcase 02: Decode HTML entities in HTTP body` | Test |
| 6 | `BT2 - Testcase 03: Decode Base64 in SMTP` | Test |
| 7 | `BT2 - Testcase 04: Decode Quoted-Printable in SMTP` | Test |
| 8 | `BT2 - Testcase 05: Null byte removal in preprocessor` | Test |
| 9 | `BT2 - Testcase 06: High entropy detection (encrypted data)` | Test |
| 10 | `BT2 - Testcase 07: TCP full session flow tracking (SYN to FIN)` | Test |
| 11 | `BT2 - Testcase 08: UDP DNS flow tracking` | Test |
| 12 | `BT2 - Testcase 09: Mixed protocol flows (DNS + HTTP)` | Test |
| 13 | `BT2 - Testcase 10: SQL injection special chars detection` | Test |
| 14 | `BT2 - Testcase 11: Non-ASCII payload handling` | Test |
| 15 | `BT2 - Testcase 12: Multiple destination flows from same source` | Test |
| 16 | `BT2 - Testcase 13: TCP RST state tracking` | Test |
| 17 | `BT2 - Testcase 14: Empty payload packet handling` | Test |

---

## 9. Ghi chú sử dụng công cụ AI

Dự án này có sử dụng công cụ AI (Google Gemini) để hỗ trợ:
- Tư vấn kiến trúc pipeline và cách chia module.
- Hướng dẫn sử dụng thư viện Python chuẩn (`urllib.parse`, `html`, `base64`, `quopri`).
- Sinh test case PCAP mẫu bằng Scapy.
- Tối ưu hóa code và xử lý edge case.

Mọi đoạn code đều được sinh viên đọc hiểu và kiểm soát.
