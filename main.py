import argparse
from core.capture import start_capture

def dummy_pipeline(packet, capture_time):
    """
    Hàm pipeline tạm thời để kiểm tra việc bắt gói tin.
    Sẽ được thay thế bằng pipeline thật ở Task sau.
    """
    print(f"[{capture_time}] Đã bắt được packet dài {len(packet)} bytes")

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
            packet_callback=dummy_pipeline
        )
    except KeyboardInterrupt:
        print("\n[*] Đã dừng bắt gói tin.")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

if __name__ == "__main__":
    main()
