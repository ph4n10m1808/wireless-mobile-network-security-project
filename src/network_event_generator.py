#!/opt/miniconda3/envs/network/bin/python
import os
import json
import time
import random
from datetime import datetime, timezone, timedelta

LOG_DIR = "/var/log/virtual-network"
LOG_FILE = os.path.join(LOG_DIR, "network-events.json")

# Tạo thư mục log nếu chưa có
os.makedirs(LOG_DIR, exist_ok=True)

def now():
    tz = timezone(timedelta(hours=7))
    return datetime.now(tz).isoformat()

EVENTS = [
    {
        "source": "virtual-dhcp",
        "event_type": "dhcp_lease_assigned",
        "description": "DHCP Server cấp phát địa chỉ IP cho thiết bị mạng không dây",
        "client_mac": "FA:KE:CL:IE:NT:01",
        "assigned_ip": "10.0.0.120",
        "hostname": "unknown-wireless-client",
        "severity": "medium"
    },
    {
        "source": "virtual-firewall",
        "event_type": "port_scan_detected",
        "description": "Firewall phát hiện hành vi dò quét cổng dịch vụ (Port Scan) bất thường",
        "src_ip": "10.0.0.120",
        "dst_ip": "10.0.0.1",
        "dst_ports": "21,22,80,443,1514,5601,9200",
        "severity": "high"
    },
    {
        "source": "virtual-dns",
        "event_type": "suspicious_dns_query",
        "description": "DNS Server phát hiện yêu cầu phân giải tên miền độc hại (C2 Connection)",
        "src_ip": "10.0.0.120",
        "query": "c2-server.malicious-domain-wids.test",
        "severity": "critical"
    }
]

def main():
    print("[+] Khởi chạy Network Event Generator...")
    print(f"[+] Nhật ký hệ thống ghi vào: {LOG_FILE}")
    while True:
        event = random.choice(EVENTS).copy()
        event["timestamp"] = now()
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
            print(f"[Network Log Created]: Source: {event['source']} | Type: {event['event_type']} | Severity: {event['severity']}")
        except IOError as e:
            print(f"[!] Error writing to {LOG_FILE}: {e}. Make sure to set permissions (chmod 666 /var/log/virtual-network/network-events.json)")
        time.sleep(12)

if __name__ == "__main__":
    main()
