from scapy.all import sniff
import time

def start_capture(interface=None, pcap_file=None, packet_callback=None):
    """
    Bắt gói tin từ interface hoặc đọc từ file PCAP.
    Tất cả các gói tin đều đi qua chung một hàm packet_callback (pipeline).
    """
    if not packet_callback:
        raise ValueError("Cần cung cấp hàm callback để xử lý packet (pipeline).")

    # Hàm wrapper để thêm thời gian thu nhận theo yêu cầu đề bài
    def _sniff_callback(packet):
        capture_time = time.time()
        packet_callback(packet, capture_time)

    if pcap_file:
        print(f"[*] Đang đọc file PCAP: {pcap_file}...")
        sniff(offline=pcap_file, prn=_sniff_callback, store=False)
        print("[*] Đã đọc xong file PCAP.")
    elif interface:
        print(f"[*] Đang bắt Live traffic trên interface: {interface}...")
        print("[*] Nhấn Ctrl+C để dừng.")
        sniff(iface=interface, prn=_sniff_callback, store=False)
    else:
        raise ValueError("Phải cung cấp interface hoặc file pcap.")
