#!/opt/miniconda3/envs/network/bin/python
import os
import json
import time
from datetime import datetime

WIDS_LOG = "/var/log/virtual-wips/wips-alerts.json"
NET_LOG = "/var/log/virtual-network/network-events.json"

LOG_DIR = "/var/log/virtual-wips"
AR_LOG = os.path.join(LOG_DIR, "active-response.log")
BLACKLIST = os.path.join(LOG_DIR, "simulated_blacklist.txt")

# Đảm bảo thư mục log tồn tại
os.makedirs(LOG_DIR, exist_ok=True)

def get_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_action(message):
    try:
        with open(AR_LOG, "a") as f:
            f.write(f"[{get_time()}] {message}\n")
        print(f"[*] WIPS Active Response: {message}")
    except IOError as e:
        print(f"[!] Error writing to {AR_LOG}: {e}")

def blacklist_item(item_type, val):
    # Kiểm tra xem đã bị chặn chưa
    already_blocked = False
    if os.path.exists(BLACKLIST):
        try:
            with open(BLACKLIST, "r") as f:
                if val in f.read():
                    already_blocked = True
        except IOError:
            pass
                
    if not already_blocked:
        try:
            with open(BLACKLIST, "a") as f:
                f.write(f"[{get_time()}] [CONTAINMENT - BLOCK {item_type}] -> {val}\n")
            log_action(f"Đã đưa {item_type} {val} vào danh sách chặn (BLACKLIST). Cách ly thiết bị thành công!")
        except IOError as e:
            log_action(f"Không thể ghi vào BLACKLIST {BLACKLIST}: {e}")
    else:
        log_action(f"Thiết bị {val} đã nằm trong BLACKLIST từ trước. Tiếp tục cách ly.")

def monitor_logs():
    print("[+] Khởi chạy WIPS Active Response Engine (ELK Compatible)...")
    print(f"[+] Giám sát log cảnh báo: {WIDS_LOG}")
    print(f"[+] Nhật ký phản ứng ghi tại: {AR_LOG}")
    print(f"[+] Danh sách chặn tại: {BLACKLIST}")

    # Đảm bảo các file log tồn tại để tail không bị lỗi
    for path in [WIDS_LOG, NET_LOG]:
        if not os.path.exists(path):
            try:
                with open(path, "w") as f:
                    pass
            except IOError as e:
                print(f"[!] Warning: Could not pre-create {path}: {e}")
    
    # Mở và di chuyển con trỏ về cuối file (tail)
    wids_file = None
    net_file = None
    
    try:
        wids_file = open(WIDS_LOG, "r")
        wids_file.seek(0, os.SEEK_END)
    except IOError as e:
        print(f"[!] Error opening {WIDS_LOG}: {e}. Make sure the detector has run once or permissions are correct.")
        
    try:
        net_file = open(NET_LOG, "r")
        net_file.seek(0, os.SEEK_END)
    except IOError as e:
        print(f"[!] Error opening {NET_LOG}: {e}. Make sure the network generator has run once or permissions are correct.")
    
    while True:
        # Check WIDS logs
        if wids_file:
            wids_line = wids_file.readline()
            if wids_line:
                try:
                    alert = json.loads(wids_line)
                    etype = alert.get("event_type")
                    if etype == "evil_twin_detected":
                        bssid = alert.get("bssid", "N/A")
                        log_action(f"CẢNH BÁO NGUY CẤP: Evil Twin phát hiện với BSSID: {bssid}!")
                        blacklist_item("BSSID_AP", bssid)
                    elif etype == "deauth_flood":
                        client = alert.get("client_mac", "N/A")
                        log_action(f"CẢNH BÁO: Deauthentication Flood ảnh hưởng client {client}!")
                        blacklist_item("ATTACKER_MAC", client)
                except Exception:
                    pass
                    
        # Check Network logs
        if net_file:
            net_line = net_file.readline()
            if net_line:
                try:
                    event = json.loads(net_line)
                    etype = event.get("event_type")
                    if etype == "port_scan_detected":
                        ip = event.get("src_ip", "N/A")
                        log_action(f"CẢNH BÁO LIÊN KẾT: Phát hiện quét cổng (Port Scan) từ IP nội bộ {ip}!")
                        blacklist_item("IP_ADDRESS", ip)
                    elif etype == "suspicious_dns_query":
                        ip = event.get("src_ip", "N/A")
                        domain = event.get("query", "N/A")
                        log_action(f"CẢNH BÁO NGUY CẤP: Thiết bị {ip} kết nối C2 tới domain: {domain}!")
                        blacklist_item("IP_ADDRESS", ip)
                except Exception:
                    pass
                    
        time.sleep(0.2)

if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\n[+] Đang tắt WIPS Active Response Engine...")
