#!/bin/bash
# test_wids_attacks.sh
# Script kiểm thử hệ thống WIDS bằng cách mô phỏng các cuộc tấn công thông qua việc tiêm log.
# Yêu cầu: Quyền root để chạy (ví dụ: sudo ./test_wids_attacks.sh)

LOG_FILE="/var/log/virtual-wips/wips-alerts.json"

echo "=========================================================="
echo "    BẮT ĐẦU KIỂM THỬ WIDS (WIRELESS INTRUSION DETECTION)  "
echo "=========================================================="
echo "[+] File log đích: $LOG_FILE"
echo ""

# Hàm tiêm log vào file JSON
inject_log() {
    local attack_type="$1"
    local json_data="$2"
    echo -e "\n[*] Đang thực hiện: $attack_type..."
    echo "$json_data" >> "$LOG_FILE"
    echo "[+] Đã ghi log thành công."
    sleep 2
}

# Lấy thời gian hiện tại chuẩn ISO-8601
current_time=$(date --iso-8601=seconds)

# ---------------------------------------------------------
# KỊCH BẢN 1: Tấn công Deauthentication Flood (Deauth)
# ---------------------------------------------------------
deauth_json='{
    "timestamp": "'$current_time'",
    "source": "wids-test-script",
    "sensor": "kali-mininet-wifi-sensor-01",
    "event_type": "deauth_flood",
    "description": "Phát hiện tấn công Deauthentication Flood làm gián đoạn kết nối của nhiều client",
    "ssid": "Company-WiFi",
    "bssid": "00:00:00:00:01:00",
    "client_mac": "DE:AD:BE:EF:00:01",
    "channel": 1,
    "deauth_count": 150,
    "affected_clients": 5,
    "severity": "critical"
}'
inject_log "Tấn công Deauthentication Flood" "$deauth_json"

# ---------------------------------------------------------
# KỊCH BẢN 2: Tấn công Evil Twin (AP Giả mạo)
# ---------------------------------------------------------
current_time=$(date --iso-8601=seconds)
evil_twin_json='{
    "timestamp": "'$current_time'",
    "source": "wids-test-script",
    "sensor": "kali-mininet-wifi-sensor-01",
    "event_type": "evil_twin_detected",
    "description": "CẢNH BÁO NGUY HIỂM - Phát hiện Evil Twin giả mạo SSID của công ty với mã hóa open",
    "ssid": "Company-WiFi",
    "bssid": "02:00:00:00:1f:00",
    "channel": 11,
    "encryption": "open",
    "authorized": false,
    "severity": "critical"
}'
inject_log "Tấn công Evil Twin (AP giả mạo Company-WiFi)" "$evil_twin_json"


# ---------------------------------------------------------
# KỊCH BẢN 3: Thiết bị lạ kết nối (Unknown Client)
# ---------------------------------------------------------
current_time=$(date --iso-8601=seconds)
unknown_client_json='{
    "timestamp": "'$current_time'",
    "source": "wids-test-script",
    "sensor": "kali-mininet-wifi-sensor-01",
    "event_type": "unknown_client_joined",
    "description": "Thiết bị lạ (chưa đăng ký trong asset inventory) kết nối thành công vào SSID nội bộ",
    "ssid": "Company-WiFi",
    "bssid": "00:00:00:00:02:00",
    "client_mac": "MA:CA:DD:RE:SS:01",
    "severity": "high"
}'
inject_log "Thiết bị lạ kết nối vào mạng (Unknown Client)" "$unknown_client_json"


# ---------------------------------------------------------
# KỊCH BẢN 4: Lỗi xác thực Wi-Fi liên tục (Brute-force)
# ---------------------------------------------------------
current_time=$(date --iso-8601=seconds)
auth_fail_json='{
    "timestamp": "'$current_time'",
    "source": "wids-test-script",
    "sensor": "kali-mininet-wifi-sensor-01",
    "event_type": "wifi_auth_fail",
    "description": "Phát hiện nhiều lần xác thực Wi-Fi thất bại từ một địa chỉ MAC",
    "ssid": "Company-WiFi",
    "bssid": "00:00:00:00:01:00",
    "client_mac": "AT:TA:CK:ER:00:99",
    "auth_fail_count": 35,
    "window_seconds": 300,
    "severity": "medium"
}'
inject_log "Tấn công dò mật khẩu (Brute-force/Auth fail)" "$auth_fail_json"


echo -e "\n=========================================================="
echo "    HOÀN TẤT KIỂM THỬ"
echo "    Bạn có thể kiểm tra file log: $LOG_FILE"
echo "    hoặc kiểm tra dữ liệu trên Kibana (nếu đã tích hợp Logstash)."
echo "=========================================================="
