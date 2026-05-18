#!/opt/miniconda3/envs/network/bin/python
import os
import json
import time
import random
from datetime import datetime, timezone, timedelta

LOG_DIR = "/var/log/virtual-wips"
LOG_FILE = os.path.join(LOG_DIR, "wips-alerts.json")

# Tạo thư mục log nếu chưa có
os.makedirs(LOG_DIR, exist_ok=True)

# Danh sách AP hợp lệ làm Baseline whitelist
AUTHORIZED_APS = [
    {
        "name": "ap1",
        "ssid": "Company-WiFi",
        "bssid": "00:00:00:00:01:00",
        "channel": 1,
        "encryption": "WPA2-Enterprise"
    },
    {
        "name": "ap2",
        "ssid": "Company-WiFi",
        "bssid": "00:00:00:00:02:00",
        "channel": 6,
        "encryption": "WPA2-Enterprise"
    },
    {
        "name": "ap3",
        "ssid": "Company-Guest",
        "bssid": "00:00:00:00:03:00",
        "channel": 11,
        "encryption": "WPA2-Personal"
    }
]

# Danh sách AP dò quét được (bao gồm cả AP giả mạo)
DETECTED_APS = [
    {
        "name": "ap1",
        "ssid": "Company-WiFi",
        "bssid": "00:00:00:00:01:00",
        "channel": 1,
        "encryption": "WPA2-Enterprise"
    },
    {
        "name": "ap2",
        "ssid": "Company-WiFi",
        "bssid": "00:00:00:00:02:00",
        "channel": 6,
        "encryption": "WPA2-Enterprise"
    },
    {
        "name": "rogueap",
        "ssid": "Company-WiFi",
        "bssid": "AA:BB:CC:11:22:33",
        "channel": 11,
        "encryption": "open" # Cố tình cấu hình Open để tạo kịch bản Evil Twin dụ client
    }
]

CLIENTS = [
    "DE:AD:BE:EF:00:01",
    "DE:AD:BE:EF:00:02",
    "DE:AD:BE:EF:00:03",
    "DE:AD:BE:EF:00:04"
]

def now():
    tz = timezone(timedelta(hours=7)) # Múi giờ Việt Nam (UTC+7)
    return datetime.now(tz).isoformat()

def write_event(event):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"[WIDS Alert Created]: {event['event_type']} | SSID: {event.get('ssid')} | Severity: {event['severity']}")
    except IOError as e:
        print(f"[!] Error writing to {LOG_FILE}: {e}. Make sure to set permissions (chmod 666 /var/log/virtual-wips/wips-alerts.json)")

def is_authorized_bssid(bssid):
    return any(ap["bssid"] == bssid for ap in AUTHORIZED_APS)

def get_authorized_ssids():
    return set(ap["ssid"] for ap in AUTHORIZED_APS)

def generate_rogue_or_evil_twin_events():
    authorized_ssids = get_authorized_ssids()
    for ap in DETECTED_APS:
        authorized = is_authorized_bssid(ap["bssid"])
        if ap["ssid"] in authorized_ssids and not authorized:
            if ap["encryption"].lower() == "open":
                event_type = "evil_twin_detected"
                severity = "critical"
                desc = "CẢNH BÁO NGUY HIỂM - Phát hiện Evil Twin giả mạo SSID của công ty với mã hóa open"
            else:
                event_type = "rogue_ap_detected"
                severity = "high"
                desc = "Phát hiện Rogue AP hoạt động trái phép phát sóng SSID của công ty"
            
            event = {
                "timestamp": now(),
                "source": "virtual-wips",
                "sensor": "kali-mininet-wifi-sensor-01",
                "event_type": event_type,
                "description": desc,
                "ssid": ap["ssid"],
                "bssid": ap["bssid"],
                "channel": ap["channel"],
                "encryption": ap["encryption"],
                "authorized": False,
                "severity": severity
            }
            write_event(event)

def generate_deauth_flood_event():
    event = {
        "timestamp": now(),
        "source": "virtual-wips",
        "sensor": "kali-mininet-wifi-sensor-01",
        "event_type": "deauth_flood",
        "description": "Phát hiện tấn công Deauthentication Flood làm gián đoạn kết nối của nhiều client",
        "ssid": "Company-WiFi",
        "bssid": random.choice(["00:00:00:00:01:00", "00:00:00:00:02:00"]),
        "client_mac": random.choice(CLIENTS),
        "channel": random.choice([1, 6]),
        "deauth_count": random.randint(80, 250),
        "affected_clients": random.randint(4, 20),
        "severity": "critical"
    }
    write_event(event)

def generate_wifi_auth_fail_event():
    event = {
        "timestamp": now(),
        "source": "virtual-wips",
        "sensor": "kali-mininet-wifi-sensor-01",
        "event_type": "wifi_auth_fail",
        "description": "Phát hiện nhiều lần xác thực Wi-Fi thất bại từ một địa chỉ MAC",
        "ssid": "Company-WiFi",
        "bssid": random.choice(["00:00:00:00:01:00", "00:00:00:00:02:00"]),
        "client_mac": random.choice(CLIENTS),
        "auth_fail_count": random.randint(10, 40),
        "window_seconds": 300,
        "severity": "medium"
    }
    write_event(event)

def generate_unknown_client_event():
    event = {
        "timestamp": now(),
        "source": "virtual-wips",
        "sensor": "kali-mininet-wifi-sensor-01",
        "event_type": "unknown_client_joined",
        "description": "Thiết bị lạ (chưa đăng ký trong asset inventory) kết nối thành công vào SSID nội bộ",
        "ssid": "Company-WiFi",
        "bssid": random.choice(["00:00:00:00:01:00", "00:00:00:00:02:00"]),
        "client_mac": "FA:KE:CL:IE:NT:01",
        "severity": "high"
    }
    write_event(event)

def main():
    print("[+] Khởi chạy WIDS Detector...")
    print(f"[+] Nhật ký cảnh báo ghi vào: {LOG_FILE}")
    while True:
        generate_rogue_or_evil_twin_events()
        
        # Chọn ngẫu nhiên kịch bản tấn công Wi-Fi khác để sinh log demo
        random_event = random.choice([
            generate_deauth_flood_event,
            generate_wifi_auth_fail_event,
            generate_unknown_client_event
        ])
        random_event()
        
        time.sleep(10) # Quét và ghi log sau mỗi 10 giây

if __name__ == "__main__":
    main()
