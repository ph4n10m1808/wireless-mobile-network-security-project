#!/opt/miniconda3/envs/network/bin/python
import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta

# Cấu hình đường dẫn lưu log đồng bộ cho Logstash
LOG_DIR = "/var/log/virtual-wips"
LOG_FILE = os.path.join(LOG_DIR, "wips-alerts.json")

# Cấu hình API Kismet
KISMET_HOST = "http://localhost:2501"
KISMET_USER = "ph4n10m"       # Thay đổi nếu Kismet có bật basic auth
KISMET_PASS = "ph4n10m@18082004"    # Mật khẩu quản trị Kismet của bạn

# Đảm bảo thư mục log tồn tại
os.makedirs(LOG_DIR, exist_ok=True)

def now():
    tz = timezone(timedelta(hours=7)) # Múi giờ Việt Nam (UTC+7)
    return datetime.now(tz).isoformat()

def write_to_elk_log(event):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"[Kismet Alert Bridged]: {event['event_type']} | Severity: {event['severity']} | {event['description']}")
    except IOError as e:
        print(f"[!] Error writing to {LOG_FILE}: {e}")

def map_kismet_severity(kismet_sev):
    # Kismet severity: 0 (info) đến 10 (critical)
    try:
        sev = int(kismet_sev)
        if sev >= 8:
            return "critical"
        elif sev >= 5:
            return "high"
        elif sev >= 3:
            return "medium"
        else:
            return "low"
    except (ValueError, TypeError):
        return "medium"

def parse_and_bridge_alert(kalert):
    """
    Chuyển đổi cấu trúc Alert thô của Kismet sang định dạng chuẩn 
    tương thích hoàn hảo với Logstash & Dashboard Kibana hiện tại.
    """
    k_msg = kalert.get("kismet.alert.text", "")
    k_header = kalert.get("kismet.alert.header", "")
    k_class = kalert.get("kismet.alert.class", "")
    k_mac = kalert.get("kismet.alert.source_mac", "00:00:00:00:00:00")
    k_dest = kalert.get("kismet.alert.dest_mac", "")
    
    # Xác định loại sự kiện và ánh xạ về các tag trong hệ thống SIEM
    event_type = "unknown_wireless_alert"
    severity = map_kismet_severity(kalert.get("kismet.alert.severity", 5))
    
    # Chuẩn hóa các case tấn công phổ biến
    lower_msg = k_msg.lower() + " " + k_header.lower()
    
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

    # Xây dựng schema JSON chuẩn
    bridged_event = {
        "timestamp": now(),
        "source": "kismet-wids",
        "sensor": "kali-kismet-virtual-sensor",
        "event_type": event_type,
        "description": f"[Kismet Real Alert] {k_header}: {k_msg}",
        "ssid": kalert.get("kismet.alert.ssid", "Company-WiFi"),
        "bssid": kalert.get("kismet.alert.bssid", k_mac),
        "client_mac": k_dest if k_dest else k_mac,
        "channel": kalert.get("kismet.alert.channel", 11),
        "encryption": kalert.get("kismet.alert.crypt", "N/A"),
        "authorized": False,
        "severity": severity,
        "kismet_raw": {
            "class": k_class,
            "hash": kalert.get("kismet.alert.hash", ""),
            "severity_raw": kalert.get("kismet.alert.severity", 5)
        }
    }
    
    write_to_elk_log(bridged_event)

def main():
    print("[+] Bắt đầu chạy Kismet to ELK Bridge Script...")
    print(f"[+] Giám sát Kismet API tại: {KISMET_HOST}")
    print(f"[+] Nhật ký đầu ra được ghi vào: {LOG_FILE}")
    
    # Khởi tạo session để lưu cookie đăng nhập Kismet (yêu cầu bắt buộc ở các phiên bản mới)
    session = requests.Session()
    if KISMET_USER and KISMET_PASS:
        session.auth = (KISMET_USER, KISMET_PASS)
        
    # Thực hiện check_session.json để đăng nhập và thiết lập cookie KISMET
    try:
        login_resp = session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
        if login_resp.status_code == 200:
            print("[+] Đăng nhập Kismet API thành công, đã thiết lập session.")
        else:
            print(f"[!] Không thể xác thực session: {login_resp.status_code}. Vui lòng kiểm tra lại KISMET_USER và KISMET_PASS.")
    except Exception as e:
        print(f"[!] Lỗi kết nối khởi tạo session: {e}")
    
    # Lưu danh sách hash các alert đã xử lý để tránh trùng lặp
    processed_alerts = set()
    
    # Đầu tiên, fetch thử một lần để bỏ qua các alert cũ trước khi script chạy
    try:
        response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            for al in alerts:
                processed_alerts.add(al.get("kismet.alert.hash"))
            print(f"[+] Đã bỏ qua {len(processed_alerts)} cảnh báo cũ tồn tại trong Kismet database.")
    except Exception as e:
        print(f"[!] Không thể kết nối tới Kismet API: {e}. Vui lòng đảm bảo Kismet đang chạy (`sudo kismet`).")
    
    while True:
        try:
            # Truy vấn API lấy toàn bộ alert mới (tự động sử dụng cookie KISMET đã lưu trong session)
            response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
            if response.status_code == 200:
                alerts = response.json()
                for al in alerts:
                    a_hash = al.get("kismet.alert.hash")
                    if a_hash not in processed_alerts:
                        parse_and_bridge_alert(al)
                        processed_alerts.add(a_hash)
            elif response.status_code == 401:
                print("[!] Lỗi xác thực API Kismet. Vui lòng cấu hình KISMET_USER và KISMET_PASS.")
                # Thử thiết lập lại session đăng nhập
                try:
                    session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
                except Exception:
                    pass
                time.sleep(10)
        except requests.exceptions.ConnectionError:
            print("[!] Mất kết nối tới Kismet server. Thử lại sau 5 giây...")
        except Exception as e:
            print(f"[!] Lỗi không xác định: {e}")
            
        time.sleep(2) # Quét API Kismet định kỳ 2 giây/lần

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] Đang tắt Kismet to ELK Bridge...")
