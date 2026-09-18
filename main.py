import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import argparse
from core.capture import start_capture

from core.pipeline import process_packet

def main():
    parser = argparse.ArgumentParser(description="Packet Capture & Parser cho hệ thống IDS")
    
    # Bắt buộc phải chọn 1 trong 2: --interface hoặc --pcap
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface", type=str, help="Tên network interface (vd: eth0, Wi-Fi)")
    group.add_argument("--pcap", type=str, help="Đường dẫn tới file PCAP")

    args = parser.parse_args()

    try:
        start_capture(
            interface=args.interface,
            pcap_file=args.pcap,
            packet_callback=process_packet
        )
    except KeyboardInterrupt:
        print("\n[*] Đã dừng bắt gói tin.")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

if __name__ == "__main__":
    main()
