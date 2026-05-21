#!/usr/bin/env bash

# Exit on error
set -e

# ============================================================
#   Miniconda3 Auto-Installer & Network Environment Setup
#   - Downloads Miniconda (Python 3.12) if not installed
#   - Creates 'network' conda env with Python 3.12
#   - Installs all project dependencies
#   - Runs Mininet-WiFi system installer
# ============================================================

MINICONDA_DIR="/opt/miniconda3"
CONDA_BIN="$MINICONDA_DIR/bin/conda"
CONDA_ENV_NAME="network"
CONDA_ENV="$MINICONDA_DIR/envs/$CONDA_ENV_NAME"
CONDA_PYTHON="$CONDA_ENV/bin/python"
PYTHON_VER="3.12"

# Miniconda installer URL for Python 3.12 (Linux x86_64)
MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-py312_24.11.1-0-Linux-x86_64.sh"
INSTALLER_PATH="/tmp/miniconda_installer.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================================="
echo "   🛡️  MININET-WIFI MINICONDA3 NETWORK ENVIRONMENT SETTING UP SCRIPT  🛡️"
echo "=========================================================================="

# ─── Step 0: Check if running as root (required for /opt install) ────────────
if [ "$EUID" -ne 0 ]; then
    echo "[!] Script cần quyền root để cài đặt vào $MINICONDA_DIR"
    echo "    Hãy chạy lại: sudo $0"
    exit 1
fi

# ─── Step 1: Download & Install Miniconda if not present ─────────────────────
if [ ! -f "$CONDA_BIN" ]; then
    echo ""
    echo "[*] 1. Miniconda chưa được cài đặt tại $MINICONDA_DIR"
    echo "    → Đang tải Miniconda (Python $PYTHON_VER)..."
    echo "    URL: $MINICONDA_URL"

    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "$INSTALLER_PATH" "$MINICONDA_URL"
    elif command -v curl &>/dev/null; then
        curl -L -o "$INSTALLER_PATH" "$MINICONDA_URL"
    else
        echo "[!] Error: Cần wget hoặc curl để tải Miniconda."
        echo "    Cài đặt: apt install wget -y"
        exit 1
    fi

    echo "[*] Đang cài đặt Miniconda vào $MINICONDA_DIR..."
    bash "$INSTALLER_PATH" -b -p "$MINICONDA_DIR"
    rm -f "$INSTALLER_PATH"

    # Set ownership to the real user and open permissions
    REAL_USER="${SUDO_USER:-$(whoami)}"
    REAL_GROUP="$(id -gn "$REAL_USER")"
    echo "[*] Cấu hình quyền sở hữu thư mục Miniconda cho user '$REAL_USER'..."
    chown -R "$REAL_USER:$REAL_GROUP" "$MINICONDA_DIR"
    chmod -R 777 "$MINICONDA_DIR"
    echo "[+] Đã chown $REAL_USER:$REAL_GROUP và chmod 777 cho $MINICONDA_DIR"

    # Initialize conda for the current shell
    eval "$("$CONDA_BIN" shell.bash hook)"
    echo "[+] Miniconda đã cài đặt thành công!"
    echo "    Phiên bản: $("$CONDA_BIN" --version)"
else
    echo ""
    echo "[+] 1. Miniconda đã được cài đặt tại $MINICONDA_DIR"
    echo "    Phiên bản: $("$CONDA_BIN" --version)"
    eval "$("$CONDA_BIN" shell.bash hook)"
fi

# ─── Step 2: Create 'network' conda environment if not exists ────────────────
if [ ! -d "$CONDA_ENV" ]; then
    echo ""
    echo "[*] 2. Tạo môi trường conda '$CONDA_ENV_NAME' với Python $PYTHON_VER..."
    "$CONDA_BIN" create -y -n "$CONDA_ENV_NAME" python="$PYTHON_VER"
    echo "[+] Đã tạo môi trường '$CONDA_ENV_NAME' thành công!"
else
    echo ""
    echo "[+] 2. Môi trường conda '$CONDA_ENV_NAME' đã tồn tại."
fi

# Verify Python in the environment
if [ ! -f "$CONDA_PYTHON" ]; then
    echo "[!] Error: Python không tìm thấy tại $CONDA_PYTHON"
    echo "    Thử xóa và tạo lại: $CONDA_BIN env remove -n $CONDA_ENV_NAME"
    exit 1
fi

DETECTED_VER=$("$CONDA_PYTHON" -c "import sys; print('.'.join(map(str, sys.version_info[:3])))")
echo "    Python interpreter: $CONDA_PYTHON"
echo "    Python version: $DETECTED_VER"

# ─── Step 3: Install Python dependencies ─────────────────────────────────────
echo ""
echo "[*] 3. Cài đặt các thư viện Python trong môi trường conda..."
"$CONDA_PYTHON" -m pip install --upgrade pip
"$CONDA_PYTHON" -m pip install \
    "setuptools<70" \
    "numpy<2" \
    FlightRadarAPI \
    FlightRadar24 \
    pillow \
    bitstring \
    skyfield \
    matplotlib \
    psutil \
    requests

# ─── Step 4: Run Mininet-WiFi system installer ──────────────────────────────
echo ""
echo "[*] 4. Chạy bộ cài đặt hệ thống Mininet-WiFi (-Wlnfv)..."

# Fix: Clean up stale 'iw' gitlink that confuses git submodule update
# (iw was previously git-cloned as standalone repo, not a real submodule)
if [ -d "$SCRIPT_DIR/mininet-wifi/iw" ]; then
    echo "[*] Dọn dẹp thư mục iw cũ (fix git submodule conflict)..."
    rm -rf "$SCRIPT_DIR/mininet-wifi/iw"
fi
# Also remove iw from git index if still tracked as gitlink
if git -C "$SCRIPT_DIR/mininet-wifi" ls-files --stage | grep -q $'\t'"iw$"; then
    echo "[*] Xóa iw khỏi git index..."
    git -C "$SCRIPT_DIR/mininet-wifi" rm --cached -f iw 2>/dev/null || true
fi

cd "$SCRIPT_DIR/mininet-wifi"
PYTHON="$CONDA_PYTHON" ./util/install.sh -Wlnfv
cd "$SCRIPT_DIR"

# ─── Step 5: Verify installation ────────────────────────────────────────────
echo ""
echo "[*] 5. Kiểm tra cài đặt Mininet-WiFi..."
if "$CONDA_PYTHON" -c "import mininet; import mn_wifi; print('[+] mininet & mn_wifi imported thành công!'); print('    - mininet path:', mininet.__file__); print('    - mn_wifi path:', mn_wifi.__file__)" 2>/dev/null; then
    echo ""
    echo "=========================================================================="
    echo "   🎉 THÀNH CÔNG: Miniconda + Mininet-WiFi đã sẵn sàng!  🎉"
    echo "=========================================================================="
    echo " Thông tin môi trường:"
    echo "   Miniconda:  $MINICONDA_DIR"
    echo "   Conda Env:  $CONDA_ENV"
    echo "   Python:     $CONDA_PYTHON (v$DETECTED_VER)"
    echo ""
    echo " Bạn có thể chạy các script dự án:"
    echo "   sudo ./run_project.sh"
    echo "   sudo ./src/kismet_wips_daemon.py"
    echo "   sudo ./src/kali_wids_attacks.sh"
    echo "   ./notion_sync.py"
    echo "=========================================================================="
else
    echo ""
    echo "[!] Kiểm tra cài đặt thất bại. Vui lòng xem log phía trên."
    exit 1
fi
