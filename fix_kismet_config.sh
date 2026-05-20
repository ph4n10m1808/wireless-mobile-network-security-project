#!/bin/bash
# fix_kismet_config.sh
# Cập nhật kismet_site.conf để sửa APSPOOF false positives và tăng alert rate.
# Chạy: sudo ./fix_kismet_config.sh

if [ "$EUID" -ne 0 ]; then
  echo "[!] Cần quyền root: sudo ./fix_kismet_config.sh"
  exit 1
fi

cat > /etc/kismet/kismet_site.conf << 'KISMET_CONF'
# =========================================================================
# Whitelist bảo vệ mạng nội bộ giả lập (Dense Dual-Band Topology)
# =========================================================================
# QUAN TRỌNG: Dùng regex anchors (^...$) để tránh false positive do substring matching.
# Ví dụ: "Company-WiFi" sẽ match "Company-WiFi-5G" nếu không dùng anchors.

# 1. Bảo vệ SSID "Company-WiFi" (2.4 GHz - AP1, AP3, AP5)
apspoof=CompanyWiFiRule:ssid="(?:^Company-WiFi$)",validmacs="02:00:00:00:A1:00,02:00:00:00:A2:00,02:00:00:00:A3:00"

# 2. Bảo vệ SSID "Company-WiFi-5G" (5 GHz - AP2, AP4, AP6)
apspoof=CompanyWiFi5GRule:ssid="(?:^Company-WiFi-5G$)",validmacs="02:00:00:00:A1:50,02:00:00:00:A2:50,02:00:00:00:A3:50"

# 3. Bảo vệ SSID "Company-Guest" (2.4 GHz - AP7)
apspoof=CompanyGuestRule:ssid="(?:^Company-Guest$)",validmacs="02:00:00:00:A4:00"

# 4. Bảo vệ SSID "Company-Guest-5G" (5 GHz - AP8)
apspoof=CompanyGuest5GRule:ssid="(?:^Company-Guest-5G$)",validmacs="02:00:00:00:A4:50"

# Tăng alert rate để phát hiện tốt hơn khi test tấn công
alert=DEAUTHFLOOD,10/min,5/sec
alert=BCASTDISCON,10/min,5/sec
alert=APSPOOF,20/min,5/sec
KISMET_CONF

echo "[+] Đã cập nhật /etc/kismet/kismet_site.conf"
echo "[!] Cần restart Kismet để áp dụng APSPOOF rules mới."
echo "    Hoặc chạy lại: sudo ./run_project.sh"
