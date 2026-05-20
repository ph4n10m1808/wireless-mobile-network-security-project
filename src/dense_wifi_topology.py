#!/opt/miniconda3/envs/network/bin/python
# dense_wifi_topology.py
# Mô phỏng mạng Wi-Fi mật độ cao với 3 AP hợp lệ, 1 Rogue AP và 8 trạm client.
# Sử dụng mac80211_hwsim (không có wmediumd) để card wlan15 trên Host
# có thể bắt gói tin trực tiếp từ tất cả AP ảo (dùng cho Kismet WIDS / Airgeddon).

import subprocess
import os
from mn_wifi.net import Mininet_wifi
from mininet.node import Controller
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info

# -------------------------------------------------------------------
# Hàm tiện ích: Cấu hình NetworkManager để bỏ qua toàn bộ card ảo
# -------------------------------------------------------------------
def configure_network_manager():
    """
    Tạo cấu hình NetworkManager để bỏ qua toàn bộ card mạng ảo wlan*,
    tránh việc NetworkManager quét sóng và tranh chấp tài nguyên gây sập nguồn (Kernel Panic).
    Giữ lại wlan0 (card mạng thật của Host) để người dùng không bị mất mạng.
    """
    conf_path = '/etc/NetworkManager/conf.d/99-unmanage-hwsim.conf'
    conf_content = """[keyfile]
unmanaged-devices=interface-name:wlan*,except:interface-name:wlan0;interface-name:sta*-wlan*;interface-name:ap*-wlan*
"""
    if os.path.exists('/etc/NetworkManager/conf.d'):
        info("*** [NetworkManager] Cấu hình để bỏ qua các interface ảo...\n")
        try:
            already_configured = False
            if os.path.exists(conf_path):
                with open(conf_path, 'r') as f:
                    if f.read().strip() == conf_content.strip():
                        already_configured = True
            
            if not already_configured:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                info("[+] Đã tạo file cấu hình: /etc/NetworkManager/conf.d/99-unmanage-hwsim.conf\n")
                # Reload NetworkManager để áp dụng ngay lập tức
                subprocess.run(['systemctl', 'reload', 'NetworkManager'], capture_output=True)
                info("[+] Đã reload NetworkManager để áp dụng cấu hình mới\n")
            else:
                info("[+] NetworkManager đã được cấu hình từ trước — Bỏ qua\n")
        except Exception as e:
            info(f"[!] Lỗi khi cấu hình NetworkManager: {e}\n")


# -------------------------------------------------------------------
# Hàm tiện ích: Dọn dẹp tài nguyên rác trước khi nạp module
# -------------------------------------------------------------------
def cleanup_before_reload():
    """
    Dọn dẹp các tiến trình kismet và dọn dẹp Mininet-WiFi cũ
    để giải phóng hoàn toàn driver mac80211_hwsim trước khi nạp lại.
    """
    info("*** [Dọn dẹp] Tắt các tiến trình kismet và dọn dẹp Mininet cũ...\n")
    subprocess.run(['killall', '-9', 'kismet'], capture_output=True)
    subprocess.run(['mn', '-c'], capture_output=True)


# -------------------------------------------------------------------
# Hàm tiện ích: Nạp lại mac80211_hwsim với đúng số radios
# -------------------------------------------------------------------
def reload_hwsim(radios=16):
    """
    Đảm bảo driver mac80211_hwsim được nạp với đúng số lượng radio ảo.
    Sử dụng 16 radios giúp tránh tranh chấp namespace giữa Host và Mininet-WiFi.
    Mininet-WiFi sẽ lấy các card wlan0-wlan11 cho 8 Stations và 4 APs,
    để lại các card wlan12-wlan15 cho Host (wlan15 dùng làm monitor).
    """
    info(f"*** Kiểm tra và nạp mac80211_hwsim với {radios} radios\n")
    # Gỡ module cũ nếu đang chạy
    subprocess.run(['modprobe', '-r', 'mac80211_hwsim'],
                   capture_output=True)
    # Nạp lại với đúng số radios
    result = subprocess.run(['modprobe', 'mac80211_hwsim', f'radios={radios}'],
                            capture_output=True)
    if result.returncode != 0:
        info(f"[!] Cảnh báo: Không thể nạp mac80211_hwsim: {result.stderr.decode()}\n")
    else:
        info(f"[+] mac80211_hwsim đã được nạp với {radios} radios ảo\n")

# -------------------------------------------------------------------
# Vá lỗi: Ngăn Mininet-WiFi gỡ mac80211_hwsim khi thoát
# để giữ nguyên card wlan15 cho Kismet và Airgeddon
# -------------------------------------------------------------------
def patch_cleanup():
    """
    Mininet-WiFi 2.7 gọi 'rmmod mac80211_hwsim' thông qua
    Cleanup.kill_mod() trong mn_wifi/clean.py khi net.stop() được gọi.
    Điều này xóa sạch wlan15 khiến Kismet mất interface.
    Hàm này vô hiệu hóa hành vi đó bằng cách monkey-patch Cleanup.kill_mod
    để bỏ qua riêng module mac80211_hwsim.

    BUG-04 FIX: Dùng hasattr(__func__) để tránh AttributeError khi kill_mod
    không phải classmethod trên các phiên bản mn_wifi khác nhau.
    """
    try:
        from mn_wifi.clean import Cleanup
        orig = Cleanup.kill_mod
        # An toàn cho cả classmethod lẫn staticmethod / regular method
        _orig_fn = orig.__func__ if hasattr(orig, '__func__') else orig

        @classmethod
        def _patched_kill_mod(cls, module):
            if module == 'mac80211_hwsim':
                info("[+] Bỏ qua rmmod mac80211_hwsim (đã vá) — wlan15 được giữ nguyên\n")
                return
            _orig_fn(cls, module)

        Cleanup.kill_mod = _patched_kill_mod
        info("[+] Đã vô hiệu hóa việc gỡ mac80211_hwsim khi thoát\n")
    except AttributeError as e:
        info(f"[!] Không thể vá hàm unload (AttributeError - kiểm tra phiên bản mn_wifi): {e}\n")
    except Exception as e:
        info(f"[!] Không thể vá hàm unload: {e}\n")


def setup_monitor_wlan15(iface='wlan15', channel=11):
    """
    Chuyển wlan15 sang monitor mode và lock vào kênh chỉ định.
    Gọi sau khi net.build() hoàn tất.
    """
    info(f"*** Cấu hình {iface} -> monitor mode (ch{channel})\n")
    cmds = [
        ['ip', 'link', 'set', iface, 'down'],
        ['iw', 'dev', iface, 'set', 'type', 'monitor'],
        ['ip', 'link', 'set', iface, 'up'],
        ['iw', 'dev', iface, 'set', 'channel', str(channel)],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            info(f"[!] Lỗi khi chạy {' '.join(cmd)}: {r.stderr.decode().strip()}\n")
            return False
    info(f"[+] {iface} đã ở monitor mode, kênh {channel} — sẵn sàng cho Kismet\n")
    return True


def start_ovs():
    """
    Khởi động dịch vụ Open vSwitch (openvswitch-switch) trước khi Mininet-WiFi
    build topology. OVS là bắt buộc để Mininet quản lý switch ảo.
    """
    info("*** Khởi động dịch vụ Open vSwitch (openvswitch-switch)...\n")
    result = subprocess.run(
        ['service', 'openvswitch-switch', 'start'],
        capture_output=True
    )
    if result.returncode == 0:
        info("[+] Open vSwitch đã khởi động thành công.\n")
    else:
        info(f"[!] Cảnh báo: Không thể khởi động Open vSwitch: {result.stderr.decode().strip()}\n")
        info("    Vui lòng chạy thủ công: sudo service openvswitch-switch start\n")


def topology():
    # --- Bước -1: Cấu hình NetworkManager để tránh Kernel Panic ---
    configure_network_manager()

    # --- Bước 0: Khởi động Open vSwitch (bắt buộc cho Mininet switch ảo) ---
    start_ovs()

    # --- Bước 1: Dọn dẹp tài nguyên cũ và nạp lại mac80211_hwsim ---
    cleanup_before_reload()
    reload_hwsim(radios=16)
    patch_cleanup()

    # --- Bước 2: Khởi tạo mạng (KHÔNG dùng wmediumd để host wlan15 có thể thấy AP) ---
    net = Mininet_wifi(
        controller=Controller,
        # Không dùng link=wmediumd để tránh chặn gói tin từ card host (wlan15)
    )

    # --- Bước 3: Thêm 8 Trạm Client ---
    info("*** Tạo các thiết bị trạm (Stations)\n")
    sta1 = net.addStation('sta1', ip='10.0.0.1/8')
    sta2 = net.addStation('sta2', ip='10.0.0.2/8')
    sta3 = net.addStation('sta3', ip='10.0.0.3/8')
    sta4 = net.addStation('sta4', ip='10.0.0.4/8')
    sta5 = net.addStation('sta5', ip='10.0.0.5/8')
    sta6 = net.addStation('sta6', ip='10.0.0.6/8')
    sta7 = net.addStation('sta7', ip='10.0.0.7/8')
    sta8 = net.addStation('sta8', ip='10.0.0.8/8')

    # --- Bước 4: Thêm các AP hợp lệ ---
    info("*** Tạo các Access Point hợp lệ (Legitimate APs)\n")
    ap1 = net.addAccessPoint(
        'ap1',
        ssid='Company-WiFi',
        mode='g',
        channel='1',
        # BSSID cố định: 02:00:00:00:1c:00 (Kênh 1)
        mac='02:00:00:00:1c:00',
    )
    ap2 = net.addAccessPoint(
        'ap2',
        ssid='Company-WiFi',
        mode='g',
        channel='6',
        # BSSID cố định: 02:00:00:00:1d:00 (Kênh 6)
        mac='02:00:00:00:1d:00',
    )
    ap3 = net.addAccessPoint(
        'ap3',
        ssid='Company-Guest',
        mode='g',
        channel='11',
        # BSSID cố định: 02:00:00:00:1e:00 (Kênh 11)
        mac='02:00:00:00:1e:00',
    )

    # --- Bước 5: Thêm Rogue AP (Evil Twin - giả mạo Company-WiFi trên kênh 11) ---
    # Lưu ý: Mininet-WiFi yêu cầu tên AP có hậu tố số (ap4) để tự sinh datapath ID.
    info("*** Tạo AP giả mạo (Rogue AP / Evil Twin)\n")
    rogueap = net.addAccessPoint(
        'ap4',                     # Phải dùng tên dạng apN để Mininet sinh được DPID
        ssid='Company-WiFi',       # SSID giống hệt AP hợp lệ => kích hoạt APSPOOF
        mode='g',
        channel='11',              # Cùng kênh với ap3 => Kismet dễ bắt
        # BSSID cố định: 02:00:00:00:1f:00 - KHÔNG có trong whitelist Kismet
        mac='02:00:00:00:1f:00',
        encrypt='none',            # Open (không mã hóa) => thêm dấu hiệu giả mạo
    )

    # --- Bước 6: Controller và khởi chạy ---
    info("*** Khởi tạo Controller\n")
    c1 = net.addController('c1')

    info("*** Cấu hình các nút Wi-Fi\n")
    net.configureWifiNodes()

    info("*** Khởi chạy mạng giả lập\n")
    net.build()
    c1.start()
    ap1.start([c1])
    ap2.start([c1])
    ap3.start([c1])
    rogueap.start([c1])

    # --- Bước 7: Cấu hình wlan15 -> monitor mode tự động ---
    setup_monitor_wlan15(iface='wlan15', channel=11)
    info("    Khởi động Kismet bằng lệnh:\n")
    info("    sudo kismet -c wlan15:hop=false,channel=11 --no-sqlite --homedir /home/ph4n10m\n")
    info("\n[BSSIDs của topology này]\n")
    info("  ap1      (Company-WiFi , CH 1 ): 02:00:00:00:1c:00  [HỢP LỆ]\n")
    info("  ap2      (Company-WiFi , CH 6 ): 02:00:00:00:1d:00  [HỢP LỆ]\n")
    info("  ap3      (Company-Guest, CH 11): 02:00:00:00:1e:00  [HỢP LỆ]\n")
    info("  ap4      (Company-WiFi , CH 11): 02:00:00:00:1f:00  [ROGUE AP - MỤC TIÊU WIDS]\n")
    info("\n*** Mạng Wi-Fi mật độ cao ảo hóa đang chạy!\n")
    info("Các lệnh hữu ích trong CLI:\n")
    info("  sta1 ping sta2\n")
    info("  sta1 iw dev sta1-wlan0 scan\n")
    info("  nodes\n")

    CLI(net)

    info("*** Đang dừng hệ thống mạng...\n")
    net.stop()
    info("[+] Topology đã dừng. mac80211_hwsim vẫn còn (wlan15 không bị xóa)\n")


if __name__ == '__main__':
    setLogLevel('info')
    topology()
