#!/usr/bin/env bash

# Exit on error
set -e

CONDA_ENV="/opt/miniconda3/envs/network"
CONDA_PYTHON="$CONDA_ENV/bin/python"

echo "=========================================================================="
echo "   🛡️  MININET-WIFI MINICONDA3 NETWORK ENVIRONMENT SETTING UP SCRIPT  🛡️"
echo "=========================================================================="
echo "[*] Conda Environment Target: $CONDA_ENV"
echo "[*] Checking Python interpreter..."

if [ ! -f "$CONDA_PYTHON" ]; then
    echo "[!] Error: Conda Python not found at $CONDA_PYTHON"
    echo "    Please verify that miniconda3 is installed and the 'network' env exists."
    exit 1
fi

PYTHON_VER=$($CONDA_PYTHON -c "import sys; print('.'.join(map(str, sys.version_info[:3])))")
echo "[+] Detected Conda Python version: $PYTHON_VER"

echo ""
echo "[*] 1. Installing python dependencies in Conda environment..."
sudo "$CONDA_PYTHON" -m pip install --upgrade pip
sudo "$CONDA_PYTHON" -m pip install "setuptools<70" "numpy<2" FlightRadarAPI FlightRadar24 pillow bitstring skyfield matplotlib psutil requests

echo ""
echo "[*] 2. Running mininet-wifi system and network installer (-Wlnfv)..."
cd mininet-wifi
sudo PYTHON="$CONDA_PYTHON" ./util/install.sh -Wlnfv
cd ..

echo ""
echo "[*] 3. Verifying Mininet-WiFi installation in Conda environment..."
if sudo "$CONDA_PYTHON" -c "import mininet; import mn_wifi; print('[+] mininet & mn_wifi libraries imported successfully!'); print('    - mininet path:', mininet.__file__); print('    - mn_wifi path:', mn_wifi.__file__)" 2>/dev/null; then
    echo ""
    echo "=========================================================================="
    echo "   🎉 SUCCESS: Mininet-WiFi is fully configured for Miniconda network env! 🎉"
    echo "=========================================================================="
    echo " You can now run the topology and other scripts directly:"
    echo "   sudo ./src/dense_wifi_topology.py"
    echo "   ./src/virtual_wips_detector.py"
    echo "   ./src/network_event_generator.py"
    echo "   ./src/wips_elk_containment_simulator.py"
    echo "=========================================================================="
else
    echo ""
    echo "[!] Installation verification failed. Please check the logs above for details."
    exit 1
fi
