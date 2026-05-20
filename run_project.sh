#!/bin/bash
# run_project.sh
# Script khởi chạy tự động toàn bộ dự án WIDS/WIPS Security & SIEM
# Hỗ trợ CLI options: start (bật), stop (tắt), có/không có SIEM (--with-siem)
# Nếu chạy không đối số, sẽ hiển thị Menu tương tác chuyên nghiệp.

# ANSI Color Codes for Premium Look
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Vui lòng chạy bằng quyền root: sudo ./run_project.sh${NC}"
  exit 1
fi

# Đường dẫn môi trường
PYTHON_BIN="/opt/miniconda3/envs/network/bin/python"
PROJ_DIR="/home/ph4n10m/Code/wireless-mobile-network-security-project"
cd "$PROJ_DIR" || exit

# Đảm bảo thư mục log tồn tại và phân quyền đầy đủ trước
mkdir -p /var/log/kismet-wips
chmod -R 777 /var/log/kismet-wips 2>/dev/null || true
rm -rf /var/log/virtual-wips /var/log/virtual-network /var/log/kismet

# Biến lưu trữ lệnh docker compose khả dụng
DOCKER_COMPOSE=""

detect_docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
  elif docker-compose --version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
  else
    DOCKER_COMPOSE=""
  fi
}

cleanup_processes() {
  echo -e "${YELLOW}[*] Đang dừng WIDS/WIPS và các tiến trình mạng ảo...${NC}"
  killall -9 kismet >/dev/null 2>&1
  killall -9 mdk4 aireplay-ng >/dev/null 2>&1
  pkill -f kismet_wips_daemon.py >/dev/null 2>&1

  # Biện pháp chống timing-race: Reset wlan30/wlan31 về managed mode ngay sau khi kill kismet.
  # Topology mới (21 nodes) chiếm wlan1–wlan21; host giữ wlan22–wlan32.
  # wlan30 = WIPS deauth, wlan31 = Kismet monitor.
  for iface in wlan30 wlan31; do
    if ip link show "$iface" >/dev/null 2>&1; then
      ip link set "$iface" down 2>/dev/null || true
      iw dev "$iface" set type managed 2>/dev/null || true
      ip link set "$iface" up 2>/dev/null || true
    fi
  done

  # Dọn dẹp Mininet-WiFi
  mn -c >/dev/null 2>&1

  # Xóa/Làm rỗng log alerts để chuẩn bị cho lượt chạy mới
  > /var/log/kismet-wips/wips-alerts.json 2>/dev/null || true
  chmod 777 /var/log/kismet-wips/wips-alerts.json 2>/dev/null || true

  echo -e "${GREEN}[+] Đã dọn dẹp sạch sẽ tiến trình cũ.${NC}"
}

start_siem() {
  echo -e "\n${BLUE}[SIEM] Đang khởi động hạ tầng SIEM (ELK Stack)...${NC}"
  detect_docker_compose
  if [ -z "$DOCKER_COMPOSE" ]; then
    echo -e "${RED}[!] Không tìm thấy 'docker compose' hoặc 'docker-compose'. Vui lòng cài đặt Docker để sử dụng SIEM!${NC}"
    return 1
  fi
  
  cd "$PROJ_DIR/SIEM" || exit
  if [ ! -f ".env" ]; then
    echo -e "${RED}[!] Không tìm thấy file SIEM/.env. Vui lòng kiểm tra lại cấu hình SIEM!${NC}"
    cd "$PROJ_DIR" || exit
    return 1
  fi

  echo -e "${BLUE}[SIEM] Thực thi: $DOCKER_COMPOSE up --build -d${NC}"
  $DOCKER_COMPOSE up -d
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Đã khởi động cụm SIEM thành công!${NC}"
    echo -e "      => Dashboard Kibana: ${CYAN}https://localhost:5601${NC}"
    echo -e "      => Thông tin đăng nhập: ${YELLOW}elastic / (xem SIEM/.env để biết mật khẩu)${NC}"
  else
    echo -e "${RED}[!] Lỗi khi khởi động các container ELK Stack!${NC}"
  fi
  cd "$PROJ_DIR" || exit
}

stop_siem() {
  echo -e "\n${BLUE}[SIEM] Đang tắt và dọn dẹp cụm SIEM (ELK Stack)...${NC}"
  detect_docker_compose
  if [ -z "$DOCKER_COMPOSE" ]; then
    echo -e "${RED}[!] Không tìm thấy docker compose / docker-compose.${NC}"
    return 1
  fi
  
  cd "$PROJ_DIR/SIEM" || exit
  $DOCKER_COMPOSE down
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Đã tắt và giải phóng tài nguyên cụm SIEM thành công.${NC}"
  else
    echo -e "${RED}[!] Lỗi xảy ra khi dừng Docker Compose.${NC}"
  fi
  cd "$PROJ_DIR" || exit
}

# ---------------------------------------------------------------------------
# Chờ Elasticsearch sẵn sàng (tối đa MAX_WAIT giây, poll mỗi 5s)
# ---------------------------------------------------------------------------
wait_for_siem_ready() {
  local max_wait=180
  local elapsed=0
  local es_url="https://localhost:9200"
  local cred="elastic"
  local pass
  pass=$(grep '^ELASTIC_PASSWORD=' "$PROJ_DIR/SIEM/.env" | cut -d= -f2)

  echo -e "${BLUE}[SIEM] Đang chờ Elasticsearch sẵn sàng (tối đa ${max_wait}s)...${NC}"
  while [ $elapsed -lt $max_wait ]; do
    if curl -sk -u "${cred}:${pass}" "${es_url}/_cluster/health" \
         | grep -qE '"status":"(green|yellow)"'; then
      echo -e "${GREEN}[SIEM] ✔ Elasticsearch đã sẵn sàng nhận log! (${elapsed}s)${NC}"
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo -e "${YELLOW}[SIEM] ... chờ Elasticsearch (${elapsed}/${max_wait}s)${NC}"
  done

  echo -e "${RED}[SIEM] ✘ Elasticsearch chưa sẵn sàng sau ${max_wait}s — tiếp tục nhưng log có thể bị mất.${NC}"
  return 1
}

# ---------------------------------------------------------------------------
# Chờ WIPS daemon ghi được ít nhất 1 dòng log
# ---------------------------------------------------------------------------
wait_for_wips_ready() {
  local daemon_log="/var/log/kismet-wips/kismet_wips_daemon.log"
  local max_wait=30
  local elapsed=0

  echo -e "${BLUE}[WIPS] Đang chờ WIPS Daemon khởi động...${NC}"
  while [ $elapsed -lt $max_wait ]; do
    if [ -s "$daemon_log" ]; then
      echo -e "${GREEN}[WIPS] ✔ WIPS Daemon đang chạy và ghi log! (${elapsed}s)${NC}"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo -e "${YELLOW}[WIPS] ⚠ WIPS Daemon chưa ghi log sau ${max_wait}s — kiểm tra ${daemon_log}.${NC}"
  return 1
}

start_project() {
  local with_siem=$1

  echo -e "\n${CYAN}===================================================================${NC}"
  echo -e "${GREEN}   BẮT ĐẦU KHỞI CHẠY HỆ THỐNG MÔ PHỎNG WIDS/WIPS & MININET-WIFI${NC}"
  echo -e "${CYAN}===================================================================${NC}"

  # ── Bước 1: Dọn dẹp môi trường cũ ────────────────────────────────────────
  echo -e "\n${YELLOW}[1/5] Dọn dẹp môi trường mạng và tiến trình cũ...${NC}"
  cleanup_processes

  # ── Bước 2: Khởi động SONG SONG — SIEM + WIPS Daemon ─────────────────────
  echo -e "\n${YELLOW}[2/5] Khởi động SONG SONG: SIEM (ELK) & WIPS Daemon thu thập log...${NC}"

  # 2a. Khởi động SIEM (docker compose up -d — chạy ngầm ngay)
  if [ "$with_siem" = "true" ]; then
    echo -e "${BLUE}  [→] Đang phát lệnh khởi động ELK Stack (nền)...${NC}"
    start_siem
  fi

  # 2b. Khởi động WIPS Daemon ngầm (song song với ELK đang spin-up)
  echo -e "${BLUE}  [→] Đang khởi động Kismet WIPS Daemon (nền)...${NC}"
  # Nạp biến môi trường Kismet từ .env
  export $(grep -v '^#' "$PROJ_DIR/.env" | grep -E '^KISMET_' | xargs) 2>/dev/null || true
  $PYTHON_BIN src/kismet_wips_daemon.py \
    > /var/log/kismet-wips/kismet_wips_daemon.log 2>&1 &
  WIPS_PID=$!
  echo -e "${GREEN}  [+] WIPS Daemon PID=$WIPS_PID${NC}"
  echo -e "      └─ Log daemon : ${CYAN}/var/log/kismet-wips/kismet_wips_daemon.log${NC}"
  echo -e "      └─ Alerts JSON: ${CYAN}/var/log/kismet-wips/wips-alerts.json${NC}"

  # ── Bước 3: Chờ cả hai sẵn sàng trước khi tiếp tục ──────────────────────
  echo -e "\n${YELLOW}[3/5] Xác nhận hạ tầng thu thập log sẵn sàng...${NC}"

  # 3a. Chờ WIPS daemon ghi log (nhanh, ~vài giây)
  wait_for_wips_ready

  # 3b. Chờ Elasticsearch healthy (chậm hơn, chạy song song bên trên)
  if [ "$with_siem" = "true" ]; then
    wait_for_siem_ready
    echo -e "${GREEN}  [+] Pipeline thu thập: WIPS Daemon → Logstash → Elasticsearch đã thông!${NC}"
  fi

  # ── Bước 4: Kích hoạt Kismet WIDS khi topology sẵn sàng ──────────────────
  echo -e "\n${YELLOW}[4/5] Đăng ký trigger tự động bật Kismet WIDS...${NC}"
  (
    # FIX TIMING-RACE: Chờ tối thiểu 25 giây trước khi bắt đầu kiểm tra wlan31.
    # Mục đích: đảm bảo dense_wifi_topology.py đã kịp chạy reload_hwsim()
    # và đưa tất cả wlan* về managed mode trước khi trigger bắt đầu poll.
    # Nếu không có bước chờ này, wlan31 có thể vẫn mang trạng thái monitor
    # từ lần chạy trước (cleanup chưa kịp reset) và trigger sẽ khởi động
    # Kismet QUÁ SỚM — khiến Kismet mất interface khi reload_hwsim() chạy.
    echo -e "${BLUE}[Kismet-Trigger] Chờ 25s cho Mininet-WiFi khởi động và reload_hwsim()...${NC}"
    sleep 25
    # Chờ wlan31 vào đúng monitor mode (setup_monitor_interface phải xong)
    for i in {1..45}; do
      if iw dev wlan31 info 2>/dev/null | grep -q "type monitor"; then
        echo -e "\n${GREEN}[Kismet-Trigger] wlan31 ở monitor mode! Đang bật Kismet WIDS...${NC}"
        # hop=false,channel=11 — lock channel để tránh bắt gói deauth từ channel khác
        # --log-prefix: ghi pcap + .kismet db vào /var/log/kismet-wips/ (bỏ --no-logging)
        kismet -c wlan31 \
          --no-sqlite \
          --log-prefix /var/log/kismet-wips/Kismet \
          --homedir /home/ph4n10m \
          >/var/log/kismet-wips/kismet.log 2>&1 &
        echo -e "${GREEN}[Kismet-Trigger] Kismet WIDS đã khởi động (CH 11, no-hop). Log: /var/log/kismet-wips/${NC}"
        break
      fi
      sleep 2
    done
  ) &
  KISMET_TRIGGER_PID=$!

  # ── Bước 5: Khởi chạy Mininet-WiFi Topology (Foreground) ─────────────────
  echo -e "\n${YELLOW}[5/5] Khởi động Mininet-WiFi Topology (Foreground)...${NC}"
  echo -e "${CYAN}-------------------------------------------------------------------${NC}"
  echo -e "${WHITE}[*] Đang khởi tạo topo mạng ảo. Vui lòng đợi trong giây lát...${NC}"
  echo -e "${WHITE}[*] Khi xuất hiện prompt ${GREEN}'mininet-wifi>'${WHITE}, hệ thống đã sẵn sàng!${NC}"
  echo -e "  • Tấn công giả lập: ${GREEN}sudo ./src/kali_wids_attacks.sh${NC}"
  echo -e "  • Kismet Web UI   : ${GREEN}http://localhost:2501${NC}"
  if [ "$with_siem" = "true" ]; then
    echo -e "  • Kibana Dashboard: ${CYAN}https://localhost:5601${NC}"
  fi
  echo -e "  • Gõ ${RED}'exit'${NC} tại console 'mininet-wifi>' để dừng hệ thống."
  echo -e "${CYAN}-------------------------------------------------------------------${NC}"

  $PYTHON_BIN src/dense_wifi_topology.py

  # ── Dọn dẹp sau khi thoát ────────────────────────────────────────────────
  echo -e "\n${CYAN}===================================================================${NC}"
  echo -e "${YELLOW}[*] Đang dọn dẹp các dịch vụ ngầm...${NC}"
  kill $WIPS_PID 2>/dev/null || true
  kill $KISMET_TRIGGER_PID 2>/dev/null || true
  cleanup_processes

  if [ "$with_siem" = "true" ]; then
    echo -e -n "${YELLOW}[SIEM] Tắt cụm SIEM (ELK Stack) ngay bây giờ không? (y/n) [Mặc định: y]: ${NC}"
    read -t 15 stop_siem_choice
    stop_siem_choice=${stop_siem_choice:-y}
    if [[ "$stop_siem_choice" =~ ^[Yy]$ ]]; then
      stop_siem
    else
      echo -e "${GREEN}[*] Giữ SIEM chạy nền. Tắt thủ công: sudo ./run_project.sh stop --with-siem${NC}"
    fi
  fi
  echo -e "${GREEN}[+] Hoàn tất. Cảm ơn bạn đã sử dụng hệ thống!${NC}"
  echo -e "${CYAN}===================================================================${NC}"
}

show_interactive_menu() {
  while true; do
    echo -e "\n${CYAN}===================================================================${NC}"
    echo -e "${MAGENTA}       BẢNG ĐIỀU KHIỂN HỆ THỐNG WIDS/WIPS & SIEM (ELK) ${NC}"
    echo -e "${CYAN}===================================================================${NC}"
    echo -e "  ${WHITE}[1]${NC} Bật WIDS/WIPS & Mininet-WiFi (${GREEN}Không kèm SIEM${NC})"
    echo -e "  ${WHITE}[2]${NC} Bật WIDS/WIPS & Mininet-WiFi (${GREEN}KÈM SIEM ELK Stack${NC})"
    echo -e "  ${WHITE}[3]${NC} Tắt & Dọn dẹp WIDS/WIPS và Mininet-WiFi (${YELLOW}Giữ SIEM nếu có${NC})"
    echo -e "  ${WHITE}[4]${NC} Tắt & Dọn dẹp toàn bộ hệ thống (${RED}Cả WIDS/WIPS & SIEM${NC})"
    echo -e "  ${WHITE}[5]${NC} Chỉ khởi động SIEM (Cụm container ELK Stack)"
    echo -e "  ${WHITE}[6]${NC} Chỉ tắt SIEM (Cụm container ELK Stack)"
    echo -e "  ${WHITE}[0]${NC} Thoát"
    echo -e "${CYAN}===================================================================${NC}"
    
    echo -e -n "${WHITE}Vui lòng chọn chức năng [0-6]: ${NC}"
    read choice
    case $choice in
      1)
        start_project "false"
        break
        ;;
      2)
        start_project "true"
        break
        ;;
      3)
        cleanup_processes
        break
        ;;
      4)
        cleanup_processes
        stop_siem
        break
        ;;
      5)
        start_siem
        break
        ;;
      6)
        stop_siem
        break
        ;;
      0)
        echo -e "${WHITE}Tạm biệt!${NC}"
        exit 0
        ;;
      *)
        echo -e "${RED}[!] Lựa chọn không hợp lệ, vui lòng chọn lại!${NC}"
        sleep 1
        ;;
    esac
  done
}

# --- Xử lý tham số dòng lệnh ---
ACTION=""
WITH_SIEM="false"

if [ $# -gt 0 ]; then
  case "$1" in
    start|on|up)
      ACTION="start"
      ;;
    stop|off|down)
      ACTION="stop"
      ;;
    help|-h|--help)
      echo -e "${CYAN}Cách sử dụng:${NC} sudo ./run_project.sh [action] [options]"
      echo -e ""
      echo -e "${YELLOW}Các Action khả dụng:${NC}"
      echo -e "  ${GREEN}start | on | up${NC}       Khởi động hệ thống WIDS/WIPS & Mininet-WiFi"
      echo -e "  ${GREEN}stop | off | down${NC}     Dừng hệ thống & dọn dẹp các tiến trình mạng"
      echo -e ""
      echo -e "${YELLOW}Các Options khả dụng:${NC}"
      echo -e "  ${GREEN}--with-siem | -s${NC}     Tích hợp thêm bật/tắt cụm SIEM (ELK Stack)"
      echo -e ""
      echo -e "${CYAN}Ví dụ sử dụng:${NC}"
      echo -e "  sudo ./run_project.sh start               # Chỉ bật WIDS/WIPS & mạng giả lập"
      echo -e "  sudo ./run_project.sh start --with-siem   # Bật đầy đủ cả mạng giả lập và SIEM"
      echo -e "  sudo ./run_project.sh stop                # Chỉ dọn dẹp mạng giả lập"
      echo -e "  sudo ./run_project.sh stop --with-siem    # Tắt sạch cả mạng giả lập và cụm SIEM"
      echo -e "  sudo ./run_project.sh                     # Khởi chạy giao diện Menu tương tác"
      exit 0
      ;;
    *)
      echo -e "${RED}[!] Không nhận dạng được action: $1${NC}"
      echo -e "Gõ ${YELLOW}sudo ./run_project.sh --help${NC} để xem hướng dẫn chi tiết."
      exit 1
      ;;
  esac
  shift
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --with-siem|-s)
      WITH_SIEM="true"
      ;;
    *)
      echo -e "${RED}[!] Không nhận dạng được tùy chọn: $1${NC}"
      exit 1
      ;;
  esac
  shift
done

if [ -z "$ACTION" ]; then
  show_interactive_menu
else
  if [ "$ACTION" = "start" ]; then
    start_project "$WITH_SIEM"
  elif [ "$ACTION" = "stop" ]; then
    cleanup_processes
    if [ "$WITH_SIEM" = "true" ]; then
      stop_siem
    fi
    echo -e "${GREEN}[+] Hoàn tất quá trình dừng các tiến trình theo yêu cầu.${NC}"
  fi
fi
