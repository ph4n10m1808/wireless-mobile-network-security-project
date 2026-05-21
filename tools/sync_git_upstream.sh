#!/bin/bash
# tools/sync_git_upstream.sh
# Tự động đồng bộ hóa kho chính (Upstream Mininet-WiFi) với bản Fork của bạn,
# sau đó cập nhật con trỏ submodule và đẩy tất cả lên GitHub.
#
# Cách chạy: ./tools/sync_git_upstream.sh

# ANSI Color Codes for Premium Look
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE_DIR="$PROJ_DIR/mininet-wifi"

echo -e "${CYAN}===================================================================${NC}"
echo -e "${MAGENTA}   TỰ ĐỘNG ĐỒNG BỘ UPSTREAM MININET-WIFI VÀ CẬP NHẬT GITHUB${NC}"
echo -e "${CYAN}===================================================================${NC}"

# 1. Kiểm tra trạng thái Git cha
cd "$PROJ_DIR" || exit 1
if [ ! -d ".git" ]; then
  echo -e "${RED}[!] Lỗi: Thư mục hiện tại không phải là một kho Git.${NC}"
  exit 1
fi

# 2. Xử lý Submodule mininet-wifi
if [ ! -d "$SUBMODULE_DIR/.git" ] && [ ! -f "$SUBMODULE_DIR/.git" ]; then
  echo -e "${YELLOW}[*] Đang khởi tạo submodule mininet-wifi...${NC}"
  git submodule update --init --recursive
fi

echo -e "\n${BLUE}[1/4] Kiểm tra cấu hình Remote cho Submodule mininet-wifi...${NC}"
cd "$SUBMODULE_DIR" || exit 1

# Đảm bảo remote origin trỏ đúng fork của bạn
ORIGIN_URL=$(git remote get-url origin 2>/dev/null)
echo -e "  • Origin URL: ${WHITE}$ORIGIN_URL${NC}"

# Tự động thêm remote upstream nếu chưa tồn tại
if ! git remote | grep -q "upstream"; then
  echo -e "${YELLOW}  [!] Chưa tìm thấy remote 'upstream'. Đang cấu hình trỏ về kho gốc...${NC}"
  git remote add upstream https://github.com/intrig-unicamp/mininet-wifi.git
fi
UPSTREAM_URL=$(git remote get-url upstream 2>/dev/null)
echo -e "  • Upstream URL: ${WHITE}$UPSTREAM_URL${NC}"

# 3. Kéo và gộp thay đổi từ Upstream
echo -e "\n${BLUE}[2/4] Kéo thay đổi mới nhất từ Upstream (kho gốc) và gộp vào master...${NC}"
git checkout master 2>/dev/null || git checkout -b master 2>/dev/null
git fetch upstream

# Thực hiện merge upstream/master
if git merge upstream/master -m "chore: auto-sync with upstream master"; then
  echo -e "${GREEN}[+] Gộp mã nguồn gốc thành công!${NC}"
else
  echo -e "${RED}[!] Phát hiện xung đột (conflict) khi gộp code từ upstream.${NC}"
  echo -e "${YELLOW}[!] Vui lòng giải quyết xung đột thủ công trong thư mục: mininet-wifi/${NC}"
  exit 1
fi

# 4. Đẩy mã nguồn sạch của bản Fork lên GitHub
echo -e "\n${BLUE}[3/4] Đẩy mã nguồn bản Fork đã cập nhật lên GitHub của bạn...${NC}"
if git push origin master; then
  echo -e "${GREEN}[+] Đã đồng bộ thành công bản Fork mininet-wifi trên GitHub!${NC}"
else
  echo -e "${YELLOW}[!] Cảnh báo: Push bị từ chối. Thử push đè (force push)...${NC}"
  if git push origin master --force; then
    echo -e "${GREEN}[+] Đã force-push đồng bộ thành công bản Fork!${NC}"
  else
    echo -e "${RED}[!] Không thể đẩy code lên Fork. Vui lòng kiểm tra quyền truy cập Git.${NC}"
    exit 1
  fi
fi

# 5. Cập nhật con trỏ Submodule ở kho dự án cha
echo -e "\n${BLUE}[4/4] Cập nhật con trỏ Submodule ở dự án chính...${NC}"
cd "$PROJ_DIR" || exit 1

git add mininet-wifi
# Kiểm tra xem có thay đổi nào cần commit không
if git diff --cached --quiet; then
  echo -e "${GREEN}[+] Dự án chính đã trỏ đúng commit mới nhất — Không cần cập nhật.${NC}"
else
  echo -e "${YELLOW}[*] Đang commit con trỏ submodule mới ở dự án chính...${NC}"
  git commit -m "chore: auto-sync mininet-wifi submodule pointer to latest upstream master"
  
  echo -e "${BLUE}[*] Đang đẩy dự án chính lên GitHub...${NC}"
  if git push origin master; then
    echo -e "${GREEN}[+] Đã đồng bộ thành công toàn bộ dự án và đẩy lên GitHub!${NC}"
  else
    echo -e "${RED}[!] Lỗi khi đẩy dự án chính lên GitHub.${NC}"
    exit 1
  fi
fi

echo -e "\n${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   QUÁ TRÌNH TỰ ĐỘNG ĐỒNG BỘ HOÀN TẤT THÀNH CÔNG!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
