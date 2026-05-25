#!/opt/miniconda3/envs/network/bin/python
# dense_wifi_topology.py
# Mô phỏng mạng Wi-Fi mật độ cao với:
#   - 4 AP vật lý, mỗi AP có 2 băng tần (2.4 GHz & 5 GHz) = 8 AP nodes hợp lệ
#   - 4 Rogue AP: 2 Evil Twin (Company-WiFi 2.4G/5G), 2 Guest Spoof (2.4G/5G)
#   - 12 Stations client phân tán trên 3 tầng (4 sta/tầng)
#   - Toàn bộ AP hợp lệ dùng WPA2 / mật khẩu: Vsl@2026
#   - wlan30  : WIPS deauth interface (host, không giao cho Mininet)
#   - wlan31  : Kismet monitor interface (host, không giao cho Mininet)
# Tổng nodes Mininet: 12 sta + 8 AP hợp lệ + 4 Rogue = 24 nodes
# → hwsim dùng 32 radios → wlan1–wlan32 (wlan0 thật), Mininet chiếm wlan1–wlan24

import subprocess
import os
from mn_wifi.net import Mininet_wifi
from mininet.node import Controller
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info

# Mật khẩu WPA2 dùng chung cho toàn bộ AP hợp lệ
WIFI_PASSWD = 'Vsl@2026'

# Interface dành riêng cho Host (không được để Mininet chiếm)
WIPS_IFACE    = 'wlan30'   # WIPS deauth interface (kismet_wips_daemon.py)
MONITOR_IFACE = 'wlan31'   # Kismet monitor interface

# -------------------------------------------------------------------
# Hàm tiện ích: Cấu hình NetworkManager bỏ qua card ảo
# -------------------------------------------------------------------
def configure_network_manager():
    conf_path = '/etc/NetworkManager/conf.d/99-unmanage-hwsim.conf'
    conf_content = """[keyfile]
unmanaged-devices=interface-name:wlan*,except:interface-name:wlan0;interface-name:sta*-wlan*;interface-name:ap*-wlan*
"""
    if os.path.exists('/etc/NetworkManager/conf.d'):
        info("*** [NetworkManager] Cấu hình bỏ qua interface ảo...\n")
        try:
            already = False
            if os.path.exists(conf_path):
                with open(conf_path, 'r') as f:
                    if f.read().strip() == conf_content.strip():
                        already = True
            if not already:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                subprocess.run(['systemctl', 'reload', 'NetworkManager'], capture_output=True)
                info("[+] Đã cập nhật cấu hình NetworkManager\n")
            else:
                info("[+] NetworkManager đã cấu hình từ trước — Bỏ qua\n")
        except Exception as e:
            info(f"[!] Lỗi NetworkManager: {e}\n")


# -------------------------------------------------------------------
# Dọn dẹp tài nguyên trước khi nạp module
# -------------------------------------------------------------------
def cleanup_before_reload():
    import sys
    info("*** [Dọn dẹp] Tắt kismet và dọn dẹp Mininet cũ...\n")
    subprocess.run(['killall', '-9', 'kismet'], capture_output=True)
    # Tìm mn trong cùng thư mục với python interpreter đang chạy (Conda environment)
    mn_path = 'mn'
    conda_mn = os.path.join(os.path.dirname(sys.executable), 'mn')
    if os.path.exists(conda_mn):
        mn_path = conda_mn
    else:
        for path in ['/usr/bin/mn', '/usr/local/bin/mn']:
            if os.path.exists(path):
                mn_path = path
                break
    subprocess.run([mn_path, '-c'], capture_output=True)


# -------------------------------------------------------------------
# Nạp lại mac80211_hwsim với số radios chỉ định
# -------------------------------------------------------------------
def reload_hwsim(radios=32):
    """
    32 radios → hwsim tạo wlan1–wlan32 (wlan0 là card thật, bỏ qua).
    Mininet dùng wlan1–wlan24 (24 nodes: 12 sta + 8 AP hợp lệ + 4 rogue).
    Host giữ wlan25–wlan32; ta dùng wlan30 (WIPS) và wlan31 (Kismet).
    """
    info(f"*** Nạp lại mac80211_hwsim với {radios} radios\n")
    subprocess.run(['modprobe', '-r', 'mac80211_hwsim'], capture_output=True)
    result = subprocess.run(
        ['modprobe', 'mac80211_hwsim', f'radios={radios}'],
        capture_output=True)
    if result.returncode != 0:
        info(f"[!] Không thể nạp mac80211_hwsim: {result.stderr.decode()}\n")
    else:
        info(f"[+] mac80211_hwsim nạp thành công ({radios} radios)\n")


# -------------------------------------------------------------------
# Vá: ngăn Mininet gỡ mac80211_hwsim khi thoát
# -------------------------------------------------------------------
def patch_cleanup():
    try:
        from mn_wifi.clean import Cleanup
        orig = Cleanup.kill_mod
        _orig_fn = orig.__func__ if hasattr(orig, '__func__') else orig

        @classmethod
        def _patched_kill_mod(cls, module):
            if module == 'mac80211_hwsim':
                info("[+] Bỏ qua rmmod mac80211_hwsim — wlan30/wlan31 được giữ nguyên\n")
                return
            _orig_fn(cls, module)

        Cleanup.kill_mod = _patched_kill_mod
        info("[+] Đã vô hiệu hóa việc gỡ mac80211_hwsim khi thoát\n")
    except Exception as e:
        info(f"[!] Không thể vá cleanup: {e}\n")


# -------------------------------------------------------------------
# Cấu hình interface monitor cho Kismet
# -------------------------------------------------------------------
def setup_monitor_interface(iface=MONITOR_IFACE, channel=11):
    """
    Chuyển interface chỉ định sang monitor mode và lock kênh.
    Gọi SAU khi net.build() hoàn tất để tránh Mininet chiếm interface.
    """
    info(f"*** Cấu hình {iface} → monitor mode (CH{channel})\n")
    cmds = [
        ['ip', 'link', 'set', iface, 'down'],
        ['iw', 'dev', iface, 'set', 'type', 'monitor'],
        ['ip', 'link', 'set', iface, 'up'],
        ['iw', 'dev', iface, 'set', 'channel', str(channel)],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            info(f"[!] Lỗi: {' '.join(cmd)}: {r.stderr.decode().strip()}\n")
            return False
    info(f"[+] {iface} → monitor mode CH{channel} — sẵn sàng cho Kismet\n")
    return True


# -------------------------------------------------------------------
# Khởi động Open vSwitch
# -------------------------------------------------------------------
def start_ovs():
    info("*** Khởi động dịch vụ Open vSwitch...\n")
    result = subprocess.run(
        ['service', 'openvswitch-switch', 'start'], capture_output=True)
    if result.returncode == 0:
        info("[+] Open vSwitch đã khởi động.\n")
    else:
        info(f"[!] OVS: {result.stderr.decode().strip()}\n")


# ===================================================================
# TOPOLOGY CHÍNH
# ===================================================================
def topology():
    # Bước -1: NetworkManager
    configure_network_manager()

    # Bước 0: OVS
    start_ovs()

    # Bước 1: Dọn dẹp + nạp hwsim
    cleanup_before_reload()
    # 32 radios: wlan1–wlan32 (wlan0 là card thật)
    # Mininet chiếm wlan1–wlan24 (24 nodes); wlan30=WIPS, wlan31=Kismet
    reload_hwsim(radios=32)
    patch_cleanup()

    # Bước 2: Khởi tạo mạng (không dùng wmediumd)
    net = Mininet_wifi(controller=Controller)

    # ------------------------------------------------------------------
    # Bước 3: 12 Stations — phân bố 3 tầng (4 sta/tầng)
    # ------------------------------------------------------------------
    info("*** Tạo 12 Stations (client) phân bố mật độ cao\n")
    # Tầng 1
    sta1  = net.addStation('sta1',  ip='10.0.1.1/8')
    sta2  = net.addStation('sta2',  ip='10.0.1.2/8')
    sta3  = net.addStation('sta3',  ip='10.0.1.3/8')
    sta4  = net.addStation('sta4',  ip='10.0.1.4/8')
    # Tầng 2
    sta5  = net.addStation('sta5',  ip='10.0.2.1/8')
    sta6  = net.addStation('sta6',  ip='10.0.2.2/8')
    sta7  = net.addStation('sta7',  ip='10.0.2.3/8')
    sta8  = net.addStation('sta8',  ip='10.0.2.4/8')
    # Tầng 3
    sta9  = net.addStation('sta9',  ip='10.0.3.1/8')
    sta10 = net.addStation('sta10', ip='10.0.3.2/8')
    sta11 = net.addStation('sta11', ip='10.0.3.3/8')
    sta12 = net.addStation('sta12', ip='10.0.3.4/8')

    # ------------------------------------------------------------------
    # Bước 4: 8 AP hợp lệ — 4 vị trí vật lý × 2 băng tần
    #
    # Cấu trúc BSSID:
    #   02:00:00:00:Z{zone}:{band}0
    #   band: 00 = 2.4 GHz, 50 = 5 GHz
    # ------------------------------------------------------------------
    info("*** Tạo 10 AP hợp lệ — 5 zone × dual-band (2.4G + 5G)\n")

    # ── Zone A / Tầng 1 ───────────────────────────────────────────────
    ap1 = net.addAccessPoint(
        'ap1',
        ssid='Company-WiFi',
        mode='g', channel='1',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A1:00',
    )
    ap2 = net.addAccessPoint(
        'ap2',
        ssid='Company-WiFi-5G',
        mode='a', channel='36',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A1:50',
    )

    # ── Zone B / Tầng 2 ───────────────────────────────────────────────
    ap3 = net.addAccessPoint(
        'ap3',
        ssid='Company-WiFi',
        mode='g', channel='6',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A2:00',
    )
    ap4 = net.addAccessPoint(
        'ap4',
        ssid='Company-WiFi-5G',
        mode='a', channel='40',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A2:50',
    )

    # ── Zone C / Tầng 3 ───────────────────────────────────────────────
    ap5 = net.addAccessPoint(
        'ap5',
        ssid='Company-WiFi',
        mode='g', channel='11',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A3:00',
    )
    ap6 = net.addAccessPoint(
        'ap6',
        ssid='Company-WiFi-5G',
        mode='a', channel='44',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A3:50',
    )

    # ── Zone D / Guest Network ─────────────────────────────────────────
    ap7 = net.addAccessPoint(
        'ap7',
        ssid='Company-Guest',
        mode='g', channel='6',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A4:00',
    )
    ap8 = net.addAccessPoint(
        'ap8',
        ssid='Company-Guest-5G',
        mode='a', channel='149',
        encrypt='wpa2', passwd=WIFI_PASSWD,
        mac='02:00:00:00:A4:50',
    )

    # ------------------------------------------------------------------
    # Bước 5: Rogue AP (Evil Twin) — giả mạo Company-WiFi, không mật khẩu
    # ------------------------------------------------------------------
    info("*** Tạo Rogue AP (Evil Twin) — MỤC TIÊU WIDS\n")
    rogueap_2g = net.addAccessPoint(
        'ap9',
        ssid='Company-WiFi',        # SSID giống hệt ap1/ap3/ap5 → kích hoạt APSPOOF
        mode='g', channel='11',     # Cùng kênh CH11 với ap5 → dễ phát hiện
        encrypt='none',             # Không mật khẩu → thêm dấu hiệu giả mạo
        mac='02:00:00:00:FF:00',    # BSSID không có trong whitelist Kismet
    )
    # Rogue AP 5 GHz: giả mạo Company-WiFi-5G (Evil Twin băng tần cao)
    rogueap_5g = net.addAccessPoint(
        'ap10',
        ssid='Company-WiFi-5G',     # SSID giống ap2/ap4/ap6 → APSPOOF trên 5G
        mode='a', channel='36',     # Cùng kênh CH36 với ap2 → dễ phát hiện
        encrypt='none',             # Không mật khẩu
        mac='02:00:00:00:FE:50',    # BSSID không có trong whitelist Kismet
    )

    # Rogue AP giả mạo Guest Network (không mật khẩu, dụ các client guest kết nối)
    ap11 = net.addAccessPoint(
        'ap11',
        ssid='Company-Guest',       # SSID giống ap7 → APSPOOF trên Guest 2.4G
        mode='g', channel='1',      # CH1 (khác CH6 của ap7 → tránh xác thực trùng)
        encrypt='none',             # Không mật khẩu → dấu hiệu giả mạo
        mac='02:00:00:00:FD:00',    # BSSID không có trong whitelist Kismet
    )
    ap12 = net.addAccessPoint(
        'ap12',
        ssid='Company-Guest-5G',    # SSID giống ap8 → APSPOOF trên Guest 5G
        mode='a', channel='153',    # CH153 (khác CH149 của ap8)
        encrypt='none',             # Không mật khẩu
        mac='02:00:00:00:FD:50',    # BSSID không có trong whitelist Kismet
    )

    # ------------------------------------------------------------------
    # Bước 6: Controller + Build
    # ------------------------------------------------------------------
    info("*** Khởi tạo Controller\n")
    c1 = net.addController('c1')

    info("*** Cấu hình WiFi nodes\n")
    net.configureWifiNodes()

    info("*** Build topology\n")
    net.build()
    c1.start()

    # Khởi động toàn bộ AP (hợp lệ + rogue)
    for ap in [ap1, ap2, ap3, ap4, ap5, ap6, ap7, ap8,
               rogueap_2g, rogueap_5g, ap11, ap12]:
        ap.start([c1])

    # ------------------------------------------------------------------
    # Bước 7: Cấu hình wlan31 → monitor mode CH11 cho Kismet
    # ------------------------------------------------------------------
    setup_monitor_interface(iface=MONITOR_IFACE, channel=11)

    # Thông tin BSSID cho Kismet whitelist / kiểm tra
    info("\n[BSSIDs Topology Mật Độ Cao — 12 Stations, 8 AP hợp lệ, 4 Rogue]\n")
    info("  Zone A / Tầng 1 [HỢP LỆ - WPA2]:\n")
    info("    ap1   Company-WiFi      2.4G CH1    02:00:00:00:A1:00\n")
    info("    ap2   Company-WiFi-5G    5G  CH36   02:00:00:00:A1:50\n")
    info("  Zone B / Tầng 2 [HỢP LỆ - WPA2]:\n")
    info("    ap3   Company-WiFi      2.4G CH6    02:00:00:00:A2:00\n")
    info("    ap4   Company-WiFi-5G    5G  CH40   02:00:00:00:A2:50\n")
    info("  Zone C / Tầng 3 [HỢP LỆ - WPA2]:\n")
    info("    ap5   Company-WiFi      2.4G CH11   02:00:00:00:A3:00\n")
    info("    ap6   Company-WiFi-5G    5G  CH44   02:00:00:00:A3:50\n")
    info("  Zone D / Guest [HỢP LỆ - WPA2]:\n")
    info("    ap7   Company-Guest     2.4G CH6    02:00:00:00:A4:00\n")
    info("    ap8   Company-Guest-5G   5G  CH149  02:00:00:00:A4:50\n")
    info("  ROGUE — Mục tiêu WIDS (không mật khẩu):\n")
    info("    ap9   Company-WiFi      2.4G CH11   02:00:00:00:FF:00  [Evil Twin 2.4G]\n")
    info("    ap10  Company-WiFi-5G    5G  CH36   02:00:00:00:FE:50  [Evil Twin 5G] \n")
    info("    ap11  Company-Guest     2.4G CH1    02:00:00:00:FD:00  [Guest Spoof 2.4G]\n")
    info("    ap12  Company-Guest-5G   5G  CH153  02:00:00:00:FD:50  [Guest Spoof 5G] \n")
    info(f"\n[Interfaces]\n")
    info(f"  {WIPS_IFACE}  → WIPS deauth (kismet_wips_daemon)\n")
    info(f"  {MONITOR_IFACE} → Kismet monitor CH11\n")
    info("\n*** Mạng Wi-Fi mật độ cao đang chạy! Gõ 'exit' để thoát.\n")

    CLI(net)

    info("*** Đang dừng topology...\n")
    net.stop()
    info("[+] Topology đã dừng. mac80211_hwsim vẫn còn (wlan30/wlan31 không bị xóa)\n")


if __name__ == '__main__':
    setLogLevel('info')
    topology()
