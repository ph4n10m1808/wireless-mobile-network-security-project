#!/opt/miniconda3/envs/network/bin/python
# -*- coding: utf-8 -*-
"""
kismet_wips_daemon.py
Hệ thống Ngăn chặn Xâm nhập Không dây Chủ động (WIPS) tích hợp Kismet WIDS & SIEM ELK.
- Thu thập cảnh báo từ Kismet REST API thời gian thực.
- Chuẩn hóa log sang định dạng JSON đẩy về Logstash/Elasticsearch.
- Kích hoạt Động cơ Phản ứng Chủ động (Active Response Engine):
  1. Cô lập mức mạng (IP Blacklisting).
  2. Cách ly mức sóng vô tuyến (Wireless Deauth Containment).
"""

import os
import sys
import json
import time
import requests
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone, timedelta
from functools import lru_cache

# ==========================================
# CẤU HÌNH HỆ THỐNG WIPS
# ==========================================
# Giao diện mạng giám sát/tấn công ảo
# wlan30: Host giữ được sau khi Mininet chiếm wlan1–wlan21 (21 nodes)
# wlan31: Kismet monitor (sử dụng bởi run_project.sh)
WIPS_INTERFACE = "wlan30"  # Card mạng ảo dùng để gửi gói deauth cô lập
MONITOR_CHANNEL = 11

# Đường dẫn lưu trữ log tương thích với ELK SIEM
LOG_DIR = "/var/log/kismet-wips"
WIDS_LOG_FILE = os.path.join(LOG_DIR, "wips-alerts.json")
ACTIVE_RESPONSE_LOG = os.path.join(LOG_DIR, "active-response.log")
FIREWALL_BLACKLIST = os.path.join(LOG_DIR, "simulated_blacklist.txt")

# Thông tin xác thực Kismet API (đọc từ biến môi trường để tránh lộ thông tin)
KISMET_HOST = os.environ.get("KISMET_HOST", "http://localhost:2501")
KISMET_USER = os.environ.get("KISMET_USER", "ph4n10m")
KISMET_PASS = os.environ.get("KISMET_PASS", "")

# Quyền hạn thực thi cách ly không dây thực tế (True/False)
ENABLE_WIRELESS_CONTAINMENT = True

# ANSI Color Codes for Premium Console Look
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'

# Đảm bảo thư mục log tồn tại
os.makedirs(LOG_DIR, exist_ok=True)

# Khóa ghi file đồng thời
file_lock = threading.Lock()

# ==========================================
# BẢO VỆ CHỐNG VÒNG LẶP DEAUTH STORM
# ==========================================
# Semaphore: tối đa 2 luồng deauth chạy song song (tránh kernel overload)
_deauth_semaphore = threading.Semaphore(2)

# Cooldown tracker: không deauth lại cùng BSSID trong DEAUTH_COOLDOWN_SECONDS giây
_deauth_cooldown: dict = {}
_deauth_cooldown_lock = threading.Lock()
DEAUTH_COOLDOWN_SECONDS = 60

# Tập hợp các BSSID đang bị WIPS containment (tránh xử lý alert từ chính mình)
_wips_controlled_bssids: set = set()
_wips_controlled_lock = threading.Lock()

# Broadcast/null MAC không hợp lệ để gửi deauth đến
_INVALID_MACS = frozenset({
    "FF:FF:FF:FF:FF:FF",
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
})

def get_vietnam_time():
    tz = timezone(timedelta(hours=7)) # UTC+7
    return datetime.now(tz)

def format_iso_time():
    return get_vietnam_time().isoformat()

def format_log_time():
    return get_vietnam_time().strftime("%Y-%m-%d %H:%M:%S")

def log_console(level, msg):
    color = NC
    if level == "INFO":
        color = GREEN
    elif level == "WARN":
        color = YELLOW
    elif level == "ALERT":
        color = RED
    elif level == "SYSTEM":
        color = BLUE
    print(f"{color}[{format_log_time()}] [{level}] {msg}{NC}")

def log_active_response(action_msg):
    log_console("SYSTEM", f"Active Response Action: {action_msg}")
    with file_lock:
        try:
            with open(ACTIVE_RESPONSE_LOG, "a") as f:
                f.write(f"[{format_log_time()}] {action_msg}\n")
        except IOError as e:
            log_console("WARN", f"Không thể ghi log phản ứng: {e}")

# ==========================================
# CÁC BIỆN PHÁP NGĂN CHẶN CHỦ ĐỘNG (WIPS)
# ==========================================

def block_ip_firewall(ip_address):
    """Cơ chế cách ly mức mạng: Ghi nhận IP vi phạm vào danh sách đen tường lửa"""
    # BUG-02 FIX: Tách logic ghi file (cần lock) khỏi log_active_response (cũng cần lock)
    # để tránh deadlock do reentrant lock acquisition.
    already_blocked = False
    write_failed = False
    with file_lock:
        if os.path.exists(FIREWALL_BLACKLIST):
            try:
                with open(FIREWALL_BLACKLIST, "r") as f:
                    if ip_address in f.read():
                        already_blocked = True
            except IOError:
                pass

        if not already_blocked:
            try:
                with open(FIREWALL_BLACKLIST, "a") as f:
                    f.write(f"[{format_log_time()}] [CONTAINMENT - BLOCK IP] -> {ip_address}\n")
            except IOError as e:
                log_console("WARN", f"Không thể ghi vào file Blacklist: {e}")
                write_failed = True

    # Gọi log_active_response SAU KHI giải phóng file_lock để tránh deadlock
    if not write_failed:
        if not already_blocked:
            log_active_response(f"Đã đưa IP {ip_address} vào FIREWALL BLACKLIST. Ngăn chặn truy cập mạng LAN thành công!")
        else:
            log_active_response(f"IP {ip_address} đã nằm trong BLACKLIST từ trước. Tiếp tục duy trì cách ly.")

def wireless_deauth_containment(target_bssid, channel=None, client_mac="FF:FF:FF:FF:FF:FF"):
    """
    Cơ chế cách ly mức sóng vô tuyến: Gửi gói deauth làm gián đoạn kết nối
    của client với Rogue AP/Evil Twin hoặc phá sóng AP giả mạo.

    FIX-STORM-01: Lọc broadcast/null MAC để tránh deauth vô nghĩa và vòng lặp.
    FIX-STORM-02: Cooldown 60s/BSSID để chặn deauth storm tự khuếch đại.
    FIX-STORM-03: Semaphore giới hạn tối đa 2 luồng aireplay-ng song song.
    """
    # FIX-STORM-01: Bỏ qua nếu BSSID là địa chỉ broadcast/null (không hợp lệ)
    norm_bssid = target_bssid.upper()
    if norm_bssid in _INVALID_MACS or norm_bssid == "FF:FF:FF:FF:FF:FF":
        log_console("WARN", f"[STORM GUARD] Bỏ qua deauth đến broadcast/null MAC: {target_bssid}")
        return
 
    # FIX-STORM-02: Kiểm tra cooldown — không deauth lại cùng BSSID trong 60s
    with _deauth_cooldown_lock:
        now = time.time()
        last_time = _deauth_cooldown.get(norm_bssid, 0)
        elapsed = now - last_time
        if elapsed < DEAUTH_COOLDOWN_SECONDS:
            log_console("INFO", f"[STORM GUARD] Cooldown active cho {target_bssid} "
                                f"({elapsed:.0f}s/{DEAUTH_COOLDOWN_SECONDS}s). Bỏ qua deauth.")
            return
        _deauth_cooldown[norm_bssid] = now
 
    if not ENABLE_WIRELESS_CONTAINMENT:
        log_active_response(f"[MÔ PHỎNG] Phát hiện Rogue AP {target_bssid}. "
                            f"Đề xuất gửi gói deauth cách ly qua interface {WIPS_INTERFACE}.")
        return
 
    # Đăng ký BSSID vào tập đang containment (FIX-STORM-04: tránh self-trigger)
    with _wips_controlled_lock:
        _wips_controlled_bssids.add(norm_bssid)
 
    # Khởi chạy một tiến trình con thực hiện deauthentication bằng aireplay-ng
    def run_deauth():
        # FIX-STORM-03: Giữ semaphore — tối đa 2 luồng deauth song song
        with _deauth_semaphore:
            target_channel = channel if channel else MONITOR_CHANNEL
            log_active_response(f"KÍCH HOẠT VÔ TUYẾN CÔ LẬP: Phát deauth flood nhắm vào AP "
                                f"{target_bssid} trên kênh {target_channel} bằng interface {WIPS_INTERFACE}...")
 
            # Bước 1: Cấu hình card mạng sang monitor mode và đúng channel
            try:
                subprocess.run(["ip", "link", "set", WIPS_INTERFACE, "down"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iw", "dev", WIPS_INTERFACE, "set", "type", "monitor"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ip", "link", "set", WIPS_INTERFACE, "up"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iw", "dev", WIPS_INTERFACE, "set", "channel", str(target_channel)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.SubprocessError as e:
                log_console("WARN", f"Không thể cấu hình {WIPS_INTERFACE} sang monitor mode: {e}")
 
            # Bước 2: Gửi gói Deauth cô lập thông qua aireplay-ng với các tùy chọn sửa lỗi kênh ảo (-D và --ignore-negative-one)
            # Gửi 30 gói (giảm từ 60 → 30) để giảm tải kernel driver
            # client_mac luôn là FF:FF:FF:FF:FF:FF (broadcast) là đủ
            cmd = ["aireplay-ng", "-0", "30", "-a", target_bssid, "-D", "--ignore-negative-one", WIPS_INTERFACE]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                proc.wait(timeout=30)
                log_active_response(f"HOÀN TẤT CÔ LẬP VÔ TUYẾN: Đã gửi thành công đợt deauth "
                                    f"flood ngắt kết nối Rogue AP BSSID: {target_bssid}.")
            except subprocess.TimeoutExpired:
                proc.terminate()
                log_console("WARN", "Tiến trình gửi deauth bị quá thời gian (timeout 30s) và đã bị hủy.")
            except Exception as e:
                log_active_response(f"Thực thi deauth thất bại: {e}. "
                                    f"Kiểm tra quyền sudo và công cụ aireplay-ng.")
            finally:
                # Giải phóng BSSID khỏi tập containment sau khi hoàn tất
                with _wips_controlled_lock:
                    _wips_controlled_bssids.discard(norm_bssid)

    # Chạy trên một luồng riêng biệt để tránh làm chậm vòng lặp chính của WIPS
    t = threading.Thread(target=run_deauth, name=f"deauth-{norm_bssid[-5:]}", daemon=True)
    t.start()

# ==========================================
# ĐỒNG BỘ LOG & ĐÁNH GIÁ SỰ KIỆN WIDS
# ==========================================

def write_elk_log(event):
    """Ghi cảnh báo đã chuẩn hóa ra file JSON để Logstash thu thập"""
    with file_lock:
        try:
            with open(WIDS_LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
        except IOError as e:
            log_console("WARN", f"Không thể ghi log chuẩn hóa: {e}")

def map_kismet_severity(kismet_sev):
    try:
        sev = int(kismet_sev)
        if sev >= 8: return "critical"
        elif sev >= 5: return "high"
        elif sev >= 3: return "medium"
        else: return "low"
    except (ValueError, TypeError):
        return "medium"

def process_wids_alert(kalert):
    """Xử lý cảnh báo từ Kismet, chuẩn hóa định dạng, và quyết định biện pháp WIPS.

    FIX-STORM-04 v2: Alerts LUÔN được ghi vào ELK (không bao giờ bị drop).
    Chỉ bỏ qua phần ACTIVE RESPONSE nếu đó là self-generated alert,
    để tránh vòng lặp containment tự khuếch đại.
    """
    k_msg = kalert.get("kismet.alert.text", "")
    k_header = kalert.get("kismet.alert.header", "")
    k_class = kalert.get("kismet.alert.class", "")
    k_mac = kalert.get("kismet.alert.source_mac", "00:00:00:00:00:00")
    k_dest = kalert.get("kismet.alert.dest_mac", "")

    # FIX-STORM-04 v2: Xác định alert có phải do WIPS tự tạo ra không
    # Nếu đúng → vẫn log nhưng KHÔNG kích hoạt active response
    norm_src = k_mac.upper() if k_mac else ""
    alert_type_raw = k_header.upper()
    self_generated_types = {"DEAUTHFLOOD", "BCASTDISCON"}
    is_self_generated = False
    if any(t in alert_type_raw for t in self_generated_types):
        with _wips_controlled_lock:
            if norm_src in _wips_controlled_bssids:
                is_self_generated = True
                log_console("INFO", f"[STORM GUARD] Alert '{k_header}' từ BSSID đang containment: "
                                    f"{k_mac} — vẫn ghi log, bỏ qua active response")
    
    event_type = "unknown_wireless_alert"
    severity = map_kismet_severity(kalert.get("kismet.alert.severity", 5))
    
    lower_msg = k_msg.lower() + " " + k_header.lower()
    
    # Chuẩn hóa loại tấn công
    if "deauth" in lower_msg or "disassoc" in lower_msg:
        event_type = "deauth_flood"
        severity = "critical"
    elif "rogue" in lower_msg or "spoof" in lower_msg or "unauthorized ap" in lower_msg:
        event_type = "rogue_ap_detected"
        severity = "high"
    elif "evil twin" in lower_msg or "ssid spoofing" in lower_msg:
        event_type = "evil_twin_detected"
        severity = "critical"
    elif "brute force" in lower_msg or "wps push" in lower_msg:
        event_type = "wifi_auth_fail"
        severity = "medium"
    elif "unknown client" in lower_msg or "unregistered" in lower_msg:
        event_type = "unknown_client_joined"
        severity = "high"

    bssid = kalert.get("kismet.alert.bssid", k_mac)
    client_mac = k_dest if k_dest else k_mac
    ssid = kalert.get("kismet.alert.ssid", "Company-WiFi")
    alert_ch = kalert.get("kismet.alert.channel", MONITOR_CHANNEL)

    # Xác định nguồn gốc alert: WIPS tự tạo hay từ bên ngoài
    alert_origin = "wips_containment" if is_self_generated else "external"

    # Tạo schema sự kiện JSON chuẩn hóa tương thích ELK SIEM
    bridged_event = {
        "timestamp": format_iso_time(),
        "source": "kismet-wips-daemon",
        "sensor": "kali-kismet-hybrid-wips",
        "event_type": event_type,
        "alert_origin": alert_origin,
        "description": f"[Kismet-WIPS Realtime Alert] {k_header}: {k_msg}",
        "ssid": ssid,
        "bssid": bssid,
        "client_mac": client_mac,
        "channel": alert_ch,
        "encryption": kalert.get("kismet.alert.crypt", "N/A"),
        "authorized": False,
        "severity": severity,
        "kismet_raw": {
            "class": k_class,
            "hash": kalert.get("kismet.alert.hash", ""),
            "severity_raw": kalert.get("kismet.alert.severity", 5)
        }
    }

    # LUÔN ghi log chuẩn hóa vào ELK (không bao giờ drop)
    write_elk_log(bridged_event)
    log_console("ALERT", f"Phát hiện mối đe dọa không dây! Kiểu: {event_type} | BSSID: {bssid} | "
                         f"Mức độ: {severity} | Nguồn: {alert_origin}")

    # ==========================================
    # CƠ CHẾ CHẶN/PHẢN ỨNG THỰC TẾ CỦA WIPS
    # (Chỉ kích hoạt nếu KHÔNG phải self-generated)
    # ==========================================
    if is_self_generated:
        return

    if event_type in ["evil_twin_detected", "rogue_ap_detected"]:
        log_active_response(f"PHÁT HIỆN MỐI ĐE DỌA NGUY CẤP: {event_type.upper()} trên SSID '{ssid}' (BSSID giả mạo: {bssid})!")
        # 1. Kích hoạt chặn mạng không dây (Wireless Deauth Containment)
        wireless_deauth_containment(bssid, channel=alert_ch)
        # 2. Ghi nhận chặn BSSID này trên tường lửa giả lập
        block_ip_firewall(bssid)

    elif event_type == "deauth_flood":
        log_active_response(f"PHÁT HIỆN TẤN CÔNG DEAUTH FLOOD: Client mục tiêu: {client_mac} | Attacker MAC: {bssid}!")
        # Thực hiện chặn MAC của kẻ tấn công phát deauth
        block_ip_firewall(bssid)
        # Trả đũa vô tuyến (phản công deauth cắt kết nối của kẻ tấn công nếu cần)
        wireless_deauth_containment(bssid, channel=alert_ch)


# ==========================================
# VÒNG LẶP ĐIỀU KHIỂN CHÍNH
# ==========================================

def start_wips():
    log_console("SYSTEM", "==========================================================")
    log_console("SYSTEM", "   BẮT ĐẦU KHỞI CHẠY KISMET WIPS DAEMON - ACTIVE CONTAINMENT")
    log_console("SYSTEM", "==========================================================")
    log_console("SYSTEM", f"Giám sát Kismet Web API tại: {KISMET_HOST}")
    log_console("SYSTEM", f"Giao diện ngăn chặn vô tuyến: {WIPS_INTERFACE} (Kênh {MONITOR_CHANNEL})")
    log_console("SYSTEM", f"Tải tự động deauth cách ly: {'BẬT' if ENABLE_WIRELESS_CONTAINMENT else 'TẮT'}")
    log_console("SYSTEM", f"Đường dẫn lưu log SIEM ELK: {WIDS_LOG_FILE}")
    log_console("SYSTEM", f"Danh sách chặn tường lửa: {FIREWALL_BLACKLIST}")
    log_console("SYSTEM", "----------------------------------------------------------")

    if os.geteuid() != 0 and ENABLE_WIRELESS_CONTAINMENT:
        log_console("WARN", "Cảnh báo: Bạn không chạy bằng quyền root. Các lệnh deauth không dây (aireplay-ng) có thể thất bại!")

    session = requests.Session()
    if KISMET_USER and KISMET_PASS:
        session.auth = (KISMET_USER, KISMET_PASS)

    # Đăng nhập và thiết lập cookie Kismet
    try:
        login_resp = session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
        if login_resp.status_code == 200:
            log_console("INFO", "Đăng nhập Kismet API thành công, đã thiết lập session.")
        else:
            log_console("WARN", f"Không thể xác thực session Kismet: {login_resp.status_code}. Vui lòng kiểm tra lại thông tin đăng nhập.")
    except Exception as e:
        log_console("WARN", f"Không thể kết nối khởi tạo session với Kismet: {e}")

    # BUG-01 FIX: Dùng deque ring-buffer (tối đa 5000 phần tử) thay vì set tăng vô hạn.
    # Tra cứu O(1) qua processed_set; deque tự động loại phần tử cũ khi đầy.
    MAX_PROCESSED = 5000
    processed_deque = deque(maxlen=MAX_PROCESSED)
    processed_set = set()

    # Bỏ qua các cảnh báo cũ
    try:
        response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            for al in alerts:
                h = al.get("kismet.alert.hash")
                if h is not None:
                    if len(processed_deque) == MAX_PROCESSED:
                        evicted = processed_deque[0]  # sắp bị loại ra
                        processed_set.discard(evicted)
                    processed_deque.append(h)
                    processed_set.add(h)
            log_console("INFO", f"Đã bỏ qua {len(processed_set)} cảnh báo cũ tồn tại trong Kismet database.")
    except Exception as e:
        log_console("WARN", f"Mất kết nối tới Kismet server ban đầu: {e}. Vui lòng đảm bảo Kismet daemon đang chạy.")

    # Vòng lặp giám sát liên tục
    # BUG-11 FIX: Exponential backoff khi mất kết nối (tránh spam log)
    retry_delay = 5
    MAX_RETRY_DELAY = 60

    while True:
        try:
            response = session.get(f"{KISMET_HOST}/alerts/all_alerts.json", timeout=5)
            retry_delay = 5  # reset backoff khi kết nối thành công
            if response.status_code == 200:
                alerts = response.json()
                for al in alerts:
                    # BUG-03 FIX: Bỏ qua hash None để tránh chặn tất cả alert không có hash
                    a_hash = al.get("kismet.alert.hash")
                    if a_hash is None:
                        process_wids_alert(al)  # luôn xử lý alert không có hash
                        continue
                    if a_hash not in processed_set:
                        process_wids_alert(al)
                        if len(processed_deque) == MAX_PROCESSED:
                            evicted = processed_deque[0]
                            processed_set.discard(evicted)
                        processed_deque.append(a_hash)
                        processed_set.add(a_hash)
            elif response.status_code == 401:
                log_console("WARN", "API Kismet báo lỗi xác thực (401). Đang thử đăng nhập lại...")
                try:
                    session.get(f"{KISMET_HOST}/session/check_session.json", timeout=5)
                except Exception:
                    pass
                time.sleep(10)
        except requests.exceptions.ConnectionError:
            log_console("WARN", f"Mất kết nối tới Kismet API Server. Thử lại sau {retry_delay}s...")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)  # exponential backoff
            continue
        except Exception as e:
            log_console("WARN", f"Lỗi không xác định trong vòng lặp giám sát: {e}")
            time.sleep(2)

        time.sleep(2.0)  # Quét API định kỳ 2 giây/lần

if __name__ == "__main__":
    try:
        start_wips()
    except KeyboardInterrupt:
        log_console("SYSTEM", "\n[+] Đang tắt Kismet WIPS Daemon. Dọn dẹp tiến trình...")
        sys.exit(0)
