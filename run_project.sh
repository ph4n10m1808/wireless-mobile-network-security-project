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
mkdir -p /var/log/virtual-wips /var/log/virtual-network /var/log/kismet
chmod -R 777 /var/log/virtual-wips /var/log/virtual-network /var/log/kismet 2>/dev/null || true

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
  pkill -f kismet_to_elk.py >/dev/null 2>&1
  
  # Dọn dẹp Mininet-WiFi
  mn -c >/dev/null 2>&1
  
  # Xóa/Làm rỗng log alerts để chuẩn bị cho lượt chạy mới
  > /var/log/virtual-wips/wips-alerts.json 2>/dev/null || true
  chmod 777 /var/log/virtual-wips/wips-alerts.json 2>/dev/null || true
  
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

  echo -e "${BLUE}[SIEM] Thực thi: $DOCKER_COMPOSE up -d${NC}"
  $DOCKER_COMPOSE up -d
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Đã khởi động cụm SIEM thành công!${NC}"
    echo -e "      => Dashboard Kibana: ${CYAN}https://localhost:5601${NC}"
    echo -e "      => Thông tin đăng nhập: ${YELLOW}elastic / Vsl@2026${NC}"
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

start_project() {
  local with_siem=$1

  echo -e "\n${CYAN}===================================================================${NC}"
  echo -e "${GREEN}      BẮT ĐẦU KHỞI CHẠY HỆ THỐNG MÔ PHỎNG WIDS/WIPS & MININET-WIFI   ${NC}"
  echo -e "${CYAN}===================================================================${NC}"

  # 1. Dọn dẹp môi trường cũ trước khi start
  echo -e "${YELLOW}[1/4] Dọn dẹp môi trường mạng và tiến trình cũ...${NC}"
  cleanup_processes

  # 1.5. Khởi động SIEM nếu được chỉ định
  if [ "$with_siem" = "true" ]; then
    start_siem
  fi

  # 2. Khởi chạy Kismet to ELK Bridge ngầm
  echo -e "${YELLOW}[2/4] Khởi động Kismet to ELK Bridge (chạy ngầm)...${NC}"
  $PYTHON_BIN src/kismet_to_elk.py > /var/log/virtual-wips/kismet_bridge_stdout.log 2>&1 &
  WIPS_PID=$!
  echo -e "      => Log Bridge: ${CYAN}/var/log/virtual-wips/kismet_bridge_stdout.log${NC}"
  echo -e "      => Log cảnh báo WIPS JSON : ${CYAN}/var/log/virtual-wips/wips-alerts.json${NC}"

  # 3. Kịch bản chờ tự động bật Kismet WIDS
  echo -e "${YELLOW}[3/4] Kích hoạt trigger tự động bật Kismet WIDS...${NC}"
  (
    # Chờ giao diện wlan15 xuất hiện (do topology tạo ra)
    for i in {1..30}; do
      if ip link show wlan15 >/dev/null 2>&1; then
        echo -e "\n${GREEN}[Background] Phát hiện wlan15! Đang bật Kismet WIDS...${NC}"
        kismet -c wlan15:hop=false,channel=11 --no-sqlite --homedir /home/ph4n10m >/var/log/virtual-wips/kismet.log 2>&1 &
        break
      fi
      sleep 2
    done
  ) &

  # 4. Khởi chạy Mininet-WiFi Topology
  echo -e "${YELLOW}[4/4] Khởi động Mininet-WiFi Topology (Foreground)...${NC}"
  echo -e "${CYAN}-------------------------------------------------------------------${NC}"
  echo -e "${WHITE}[*] Đang khởi tạo topo mạng ảo. Vui lòng đợi trong giây lát...${NC}"
  echo -e "${WHITE}[*] Khi xuất hiện prompt ${GREEN}'mininet-wifi>'${WHITE}, hệ thống đã sẵn sàng!${NC}"
  echo -e "      - Mở terminal khác thực hiện giả lập tấn công: ${GREEN}sudo ./src/kali_wids_attacks.sh${NC}"
  echo -e "      - Theo dõi Kismet Web UI tại: ${GREEN}http://localhost:2501${NC}"
  if [ "$with_siem" = "true" ]; then
    echo -e "      - Giao diện Kibana SIEM Dashboard: ${CYAN}https://localhost:5601${NC}"
  fi
  echo -e "      - Nhập ${RED}'exit'${NC} tại console 'mininet-wifi>' để dừng hệ thống."
  echo -e "${CYAN}-------------------------------------------------------------------${NC}"

  # Chạy foreground để lấy shell điều khiển
  $PYTHON_BIN src/dense_wifi_topology.py

  # Dọn dẹp sau khi thoát
  echo -e "\n${CYAN}===================================================================${NC}"
  echo -e "${YELLOW}[*] Đang dọn dẹp các dịch vụ ngầm...${NC}"
  kill $WIPS_PID >/dev/null 2>&1
  cleanup_processes

  if [ "$with_siem" = "true" ]; then
    echo -e -n "${YELLOW}[SIEM] Bạn có muốn tắt cụm SIEM (ELK Stack) ngay lúc này không? (y/n) [Mặc định: y]: ${NC}"
    read -t 15 stop_siem_choice
    stop_siem_choice=${stop_siem_choice:-y}
    if [[ "$stop_siem_choice" =~ ^[Yy]$ ]]; then
      stop_siem
    else
      echo -e "${GREEN}[*] Giữ cụm SIEM chạy trong nền. Tắt thủ công bằng: sudo ./run_project.sh stop --with-siem${NC}"
    fi
  fi
  echo -e "${GREEN}[+] Hoàn tất dọn dẹp. Cảm ơn bạn đã sử dụng hệ thống!${NC}"
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
