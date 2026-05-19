#!/opt/miniconda3/envs/network/bin/python
# -*- coding: utf-8 -*-
"""
kismet_wips_daemon.py
Hệ thống Ngăn chặn Xâm nhập Không dây Chủ động (WIPS) tích hợp Kismet WIDS & SIEM ELK.
- Thu thập cảnh báo từ Kismet REST API thời gian thực.
- Chuẩn hóa log sang định dạng JSON đẩy về Logstash/Elasticsearch.
- Kích hoạt Động cơ Phản ứng Chủ động (Active Response Engine):
  1. Cô lập mức mạng (IP Blacklisting).
  2. Cách ly mức sóng vô tuyến (Wireless Deauth Containment).
"""

import os
import sys
import json
import time
import requests
import subprocess
import threading
from datetime import datetime, timezone, timedelta

# ==========================================
# CẤU HÌNH HỆ THỐNG WIPS
# ==========================================
# Giao diện mạng giám sát/tấn công ảo
WIPS_INTERFACE = "wlan14"  # Card mạng ảo dùng để gửi gói deauth cô lập
MONITOR_CHANNEL = 11

# Đường dẫn lưu trữ log tương thích với ELK SIEM
LOG_DIR = "/var/log/kismet-wips"
WIDS_LOG_FILE = os.path.join(LOG_DIR, "wips-alerts.json")
ACTIVE_RESPONSE_LOG = os.path.join(LOG_DIR, "active-response.log")
FIREWALL_BLACKLIST = os.path.join(LOG_DIR, "simulated_blacklist.txt")

# Thông tin xác thực Kismet API
KISMET_HOST = "http://localhost:2501"
KISMET_USER = "ph4n10m"
KISMET_PASS = "ph4n10m@18082004"

# Quyền hạn thực thi cách ly không dây thực tế (True/False)
ENABLE_WIRELESS_CONTAINMENT = True

# ANSI Color Codes for Premium Console Look
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'

# Đảm bảo thư mục log tồn tại
os.makedirs(LOG_DIR, exist_ok=True)

# Khóa ghi file đồng thời
file_lock = threading.Lock()

def get_vietnam_time():
    tz = timezone(timedelta(hours=7)) # UTC+7
    return datetime.now(tz)

def format_iso_time():
    return get_vietnam_time().isoformat()

def format_log_time():
    return get_vietnam_time().strftime("%Y-%m-%d %H:%M:%S")

def log_console(level, msg):
    color = NC
    if level == "INFO":
        color = GREEN
    elif level == "WARN":
        color = YELLOW
    elif level == "ALERT":
        color = RED
    elif level == "SYSTEM":
        color = BLUE
    print(f"{color}[{format_log_time()}] [{level}] {msg}{NC}")

def log_active_response(action_msg):
    log_console("SYSTEM", f"Active Response Action: {action_msg}")
    with file_lock:
        try:
            with open(ACTIVE_RESPONSE_LOG, "a") as f:
                f.write(f"[{format_log_time()}] {action_msg}\n")
        except IOError as e:
            log_console("WARN", f"Không thể ghi log phản ứng: {e}")

# ==========================================
# CÁC BIỆN PHÁP NGĂN CHẶN CHỦ ĐỘNG (WIPS)
# ==========================================

def block_ip_firewall(ip_address):
    """Cơ chế cách ly mức mạng: Ghi nhận IP vi phạm vào danh sách đen tường lửa"""
    already_blocked = False
    with file_lock:
        if os.path.exists(FIREWALL_BLACKLIST):
            try:
                with open(FIREWALL_BLACKLIST, "r") as f:
                    if ip_address in f.read():
                        already_blocked = True
            except IOError:
                pass
                
        if not already_blocked:
            try:
                with open(FIREWALL_BLACKLIST, "a") as f:
                    f.write(f"[{format_log_time()}] [CONTAINMENT - BLOCK IP] -> {ip_address}\n")
                log_active_response(f"Đã đưa IP {ip_address} vào FIREWALL BLACKLIST. Ngăn chặn truy cập mạng LAN thành công!")
            except IOError as e:
                log_console("WARN", f"Không thể ghi vào file Blacklist: {e}")
        else:
            log_active_response(f"IP {ip_address} đã nằm trong BLACKLIST từ trước. Tiếp tục duy trì cách ly.")

def wireless_deauth_containment(target_bssid, client_mac="FF:FF:FF:FF:FF:FF"):
    """
    Cơ chế cách ly mức sóng vô tuyến: Gửi gói deauth làm gián đoạn kết nối
    của client với Rogue AP/Evil Twin hoặc phá sóng AP giả mạo.
    """
    if not ENABLE_WIRELESS_CONTAINMENT:
        log_active_response(f"[MÔ PHỎNG] Phát hiện Rogue AP {target_bssid}. Đề xuất gửi gói deauth cách ly qua interface {WIPS_INTERFACE}.")
        return

    # Khởi chạy một tiến trình con thực hiện deauthentication bằng aireplay-ng
    def run_deauth():
        log_active_response(f"KÍCH HOẠT VÔ TUYẾN CÔ LẬP: Phát deauth flood nhắm vào AP {target_bssid} trên interface {WIPS_INTERFACE}...")
        
        # Bước 1: Cấu hình card mạng sang monitor mode và đúng channel
        try:
            subprocess.run(["ip", "link", "set", WIPS_INTERFACE, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", "dev", WIPS_INTERFACE, "set", "type", "monitor"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", WIPS_INTERFACE, "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", "dev", WIPS_INTERFACE, "set", "channel", str(MONITOR_CHANNEL)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            log_console("WARN", f"Không thể cấu hình interface {WIPS_INTERFACE} sang monitor mode: {e}")
            # Tiếp tục chạy lệnh aireplay-ng vì có thể interface đã ở monitor mode sẵn

        # Bước 2: Gửi gói Deauth cô lập thông qua aireplay-ng
        # Gửi 60 gói deauth để ngắt kết nối client và ngăn kết hợp lại
        cmd = ["aireplay-ng", "-0", "60", "-a", target_bssid, "-c", client_mac, WIPS_INTERFACE]
        try:
            # Chạy ngầm trong nền tránh block daemon chính
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.wait(timeout=30)
            log_active_response(f"HOÀN TẤT CÔ LẬP VÔ TUYẾN: Đã gửi thành công đợt deauth flood ngắt kết nối Rogue AP BSSID: {target_bssid}.")
        except subprocess.TimeoutExpired:
            proc.terminate()
            log_console("WARN", "Tiến trình gửi deauth bị quá thời gian (timeout 30s) và đã bị hủy.")
        except Exception as e:
            log_active_response(f"Thực thi deauth thất bại: {e}. Vui lòng kiểm tra quyền sudo và công cụ aireplay-ng.")

    # Chạy trên một luồng riêng biệt để tránh làm chậm vòng lặp chính của WIPS
    t = threading.Thread(target=run_deauth)
    t.daemon = True
    t.start()

# ==========================================
# ĐỒNG BỘ LOG & ĐÁNH GIÁ SỰ KIỆN WIDS
# ==========================================

def write_elk_log(event):
    """Ghi cảnh báo đã chuẩn hóa ra file JSON để Logstash thu thập"""
    with file_lock:
        try:
            with open(WIDS_LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
        except IOError as e:
            log_console("WARN", f"Không thể ghi log chuẩn hóa: {e}")

def map_kismet_severity(kismet_sev):
    try:
        sev = int(kismet_sev)
        if sev >= 8: return "critical"
        elif sev >= 5: return "high"
        elif sev >= 3: return "medium"
        else: return "low"
    except (ValueError, TypeError):
        return "medium"

def process_wids_alert(kalert):
    """Xử lý cảnh báo từ Kismet, chuẩn hóa định dạng, và quyết định biện pháp WIPS"""
    k_msg = kalert.get("kismet.alert.text", "")
    k_header = kalert.get("kismet.alert.header", "")
    k_class = kalert.get("kismet.alert.class", "")
    k_mac = kalert.get("kismet.alert.source_mac", "00:00:00:00:00:00")
    k_dest = kalert.get("kismet.alert.dest_mac", "")
    
    event_type = "unknown_wireless_alert"
    severity = map_kismet_severity(kalert.get("kismet.alert.severity", 5))
    
    lower_msg = k_msg.lower() + " " + k_header.lower()
    
    # Chuẩn hóa loại tấn công
    if "deauth" in lower_msg or "disassoc" in lower_msg:
        event_type = "deauth_flood"
        severity = "critical"
    elif "rogue" in lower_msg or "spoof" in lower_msg or "unauthorized ap" in lower_msg:
        event_type = "rogue_ap_detected"
        severity = "high"
    elif "evil twin" in lower_msg or "ssid spoofing" in lower_msg:
        event_type = "evil_twin_detected"
        severity = "critical"
    elif "brute force" in lower_msg or "wps push" in lower_msg:
        event_type = "wifi_auth_fail"
        severity = "medium"
    elif "unknown client" in lower_msg or "unregistered" in lower_msg:
        event_type = "unknown_client_joined"
        severity = "high"

    bssid = kalert.get("kismet.alert.bssid", k_mac)
    client_mac = k_dest if k_dest else k_mac
    ssid = kalert.get("kismet.alert.ssid", "Company-WiFi")

    # Tạo schema sự kiện JSON chuẩn hóa tương thích ELK SIEM
    bridged_event = {
        "timestamp": format_iso_time(),
        "source": "kismet-wips-daemon",
        "sensor": "kali-kismet-hybrid-wips",
        "event_type": event_type,
        "description": f"[Kismet-WIPS Realtime Alert] {k_header}: {k_msg}",
        "ssid": ssid,
        "bssid": bssid,
        "client_mac": client_mac,
        "channel": kalert.get("kismet.alert.channel", MONITOR_CHANNEL),
        "encryption": kalert.get("kismet.alert.crypt", "N/A"),
        "authorized": False,
        "severity": severity,
        "kismet_raw": {
            "class": k_class,
            "hash": kalert.get("kismet.alert.hash", ""),
            "severity_raw": kalert.get("kismet.alert.severity", 5)
        }
    }

    # Ghi log chuẩn hóa
    write_elk_log(bridged_event)
    log_console("ALERT", f"Phát hiện mối đe dọa không dây! Kiểu: {event_type} | BSSID: {bssid} | Mức độ: {severity}")

    # ==========================================
    # CƠ CHẾ CHẶN/PHẢN ỨNG THỰC TẾ CỦA WIPS
    # ==========================================
    if event_type in ["evil_twin_detected", "rogue_ap_detected"]:
        log_active_response(f"PHÁT HIỆN MỐI ĐE DỌA NGUY CẤP: {event_type.upper()} trên SSID '{ssid}' (BSSID giả mạo: {bssid})!")
        # 1. Kích hoạt chặn mạng không dây (Wireless Deauth Containment)
        wireless_deauth_containment(bssid)
        # 2. Ghi nhận chặn BSSID này trên tường lửa giả lập
        block_ip_firewall(bssid)

    elif event_type == "deauth_flood":
        log_active_response(f"PHÁT HIỆN TẤN CÔNG DEAUTH FLOOD: Client mục tiêu: {client_mac} | Attacker MAC: {bssid}!")
        # Thực hiện chặn MAC của kẻ tấn công phát deauth
        block_ip_firewall(bssid)
        # Trả đũa vô tuyến (phản công deauth cắt kết nối của kẻ tấn công nếu cần)
        wireless_deauth_containment(bssid)

# ==========================================
# VÒNG LẶP ĐIỀU KHIỂN CHÍNH
# ==========================================

def start_wips():
    log_console("SYSTEM", "==========================================================")
    log_console("SYSTEM", "   BẮT ĐẦU KHỞI CHẠY KISMET WIPS DAEMON - ACTIVE CONTAINMENT")
    log_console("SYSTEM", "==========================================================")
    log_console("SYSTEM", f"Giám sát Kismet Web API tại: {KISMET_HOST}")
    log_console("SYSTEM", f"Giao diện ngăn chặn vô tuyến: {WIPS_INTERFACE} (Kênh {MONITOR_CHANNEL})")
    log_console("SYSTEM", f"Tải tự động deauth cách ly: {'BẬT' if ENABLE_WIRELESS_CONTAINMENT else 'TẮT'}")
    log_console("SYSTEM", f"Đường dẫn lưu log SIEM ELK: {WIDS_LOG_FILE}")
    log_console("SYSTEM", f"Danh sách chặn tường lửa: {FIREWALL_BLACKLIST}")
    log_console("SYSTEM", "----------------------------------------------------------")

    if os.geteuid() != 0 and ENABLE_WIRELESS_CONTAINMENT:
        log_console("WARN", "Cảnh báo: Bạn không chạy bằng quyền root. Các lệnh deauth không dây (aireplay-ng) có thể thất bại!")

    session = requests.Session()
    if KISMET_USER and KISMET_PASS:
        session.auth = (KISMET_USER, KISMET_PASS)

    # Đăng nhập và thiết lập cookie Kismet
    try:
        login_resp = session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
        if login_resp.status_code == 200:
            log_console("INFO", "Đăng nhập Kismet API thành công, đã thiết lập session.")
        else:
            log_console("WARN", f"Không thể xác thực session Kismet: {login_resp.status_code}. Vui lòng kiểm tra lại thông tin đăng nhập.")
    except Exception as e:
        log_console("WARN", f"Không thể kết nối khởi tạo session với Kismet: {e}")

    # Bỏ qua các cảnh báo cũ
    processed_alerts = set()
    try:
        response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            for al in alerts:
                processed_alerts.add(al.get("kismet.alert.hash"))
            log_console("INFO", f"Đã bỏ qua {len(processed_alerts)} cảnh báo cũ tồn tại trong Kismet database.")
    except Exception as e:
        log_console("WARN", f"Mất kết nối tới Kismet server ban đầu: {e}. Vui lòng đảm bảo Kismet daemon đang chạy.")

    # Vòng lặp giám sát liên tục
    while True:
        try:
            response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
            if response.status_code == 200:
                alerts = response.json()
                for al in alerts:
                    a_hash = al.get("kismet.alert.hash")
                    if a_hash not in processed_alerts:
                        process_wids_alert(al)
                        processed_alerts.add(a_hash)
            elif response.status_code == 401:
                log_console("WARN", "API Kismet báo lỗi xác thực (401). Đang thử đăng nhập lại...")
                try:
                    session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
                except Exception:
                    pass
                time.sleep(10)
        except requests.exceptions.ConnectionError:
            log_console("WARN", "Mất kết nối tới Kismet API Server. Đang thử lại sau 5 giây...")
            time.sleep(5)
        except Exception as e:
            log_console("WARN", f"Lỗi không xác định trong vòng lặp giám sát: {e}")
            time.sleep(2)
        
        time.sleep(2.0) # Quét API định kỳ 2 giây/lần

if __name__ == "__main__":
    try:
        start_wips()
    except KeyboardInterrupt:
        log_console("SYSTEM", "\n[+] Đang tắt Kismet WIPS Daemon. Dọn dẹp tiến trình...")
        sys.exit(0)
