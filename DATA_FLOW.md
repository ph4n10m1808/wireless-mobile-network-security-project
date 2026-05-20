# 🛡️ Data Flow — Wireless Network Security WIDS-SIEM

> **Dự án:** Wireless/Mobile Network Security — WIDS tích hợp ELK Stack  
> **Stack:** Mininet-WiFi · Kismet · Python Scripts · Logstash · Elasticsearch · Kibana  
> **Mục tiêu:** Phát hiện, thu thập và trực quan hóa các mối đe dọa Wi-Fi (Rogue AP, Evil Twin, Deauth Flood, v.v.)

---

## 1. Tổng quan kiến trúc hệ thống

```mermaid
flowchart TB
    subgraph VIRTUAL_NET["🖥️ Tầng Mạng Ảo (Mininet-WiFi + mac80211_hwsim)"]
        direction LR
        AP1["📡 ap1/ap3/ap5\nCompany-WiFi\nCH1/6/11 · legit BSSIDs\n✅ HỢP LỆ"]
        AP2["📡 ap2/ap4/ap6\nCompany-WiFi-5G\nCH36/40/44 · legit BSSIDs\n✅ HỢP LỆ"]
        AP3["📡 ap7/ap8\nCompany-Guest & 5G\nCH6/149 · legit BSSIDs\n✅ HỢP LỆ"]
        ROGUE["⚠️ ap9–ap12 (4 Rogue APs)\nCompany-WiFi & Guest\n2.4G/5G · Open Encryption\n🔴 Evil Twin & Guest Spoof"]
        STA["📱 sta1–sta12\n12 Wireless Clients\n10.0.1.1/8 – 10.0.3.4/8"]
        STA -->|liên kết Wi-Fi| AP1 & AP2 & AP3
        STA -.->|bị dụ kết nối| ROGUE
    end

    subgraph SENSORS["🔍 Tầng Cảm biến (Sensor Layer)"]
        direction TB
        WLAN7["🛰️ wlan31\nMonitor Mode · CH11\nHost Physical Interface"]
        KISMET["🐾 Kismet WIDS\nlocalhost:2501\nsudo kismet -c wlan31"]
        WLAN7 -->|"Packet Capture\n802.11 raw frames"| KISMET
        VIRTUAL_NET -.->|"virtual radio frames\n(mac80211_hwsim)"| WLAN7
    end

    subgraph BRIDGE["🔄 Tầng Cầu nối & WIPS (WIPS & Bridge Layer)"]
        KISMET_WIPS["🛡️ kismet_wips_daemon.py\nActive WIPS Daemon & Bridge\nPolling & Containment Engine"]
        KISMET -->|"REST API\nHTTP GET\n/alerts/all_alerts.json"| KISMET_WIPS
        KISMET_WIPS -->|"Active Containment (Firewall/Deauth)"| VIRTUAL_NET
    end

    subgraph LOGS["📁 Log Files (Host Filesystem)"]
        direction LR
        LOG_WIPS["/var/log/kismet-wips/\nwips-alerts.json\nNewline-delimited JSON"]
        KISMET_WIPS -->|"ghi JSON chuẩn hóa\n& active response log"| LOG_WIPS
    end

    subgraph SIEM["📊 Tầng SIEM (ELK Stack — Docker)"]
        direction LR
        LOGSTASH["⚙️ Logstash\necp-logstash:5044\nPipeline: filter + parse + enrich"]
        ES["🔎 Elasticsearch\necp-elasticsearch:9200\nIndex: wids-alerts-*\nTLS + xpack.security"]
        KIBANA["📈 Kibana\necp-kibana:5601\nDashboard · Alerts · Maps\nTLS + Auth"]
        LOGSTASH -->|"Bulk Index\nHTTPS/9200"| ES
        ES -->|"Query & Aggregate"| KIBANA
    end

    LOG_WIPS -->|"file input\n(bind mount :ro)"| LOGSTASH
```

---

## 2. Chi tiết luồng dữ liệu từ nguồn đến đích

```mermaid
sequenceDiagram
    participant MN  as 🖥️ Mininet-WiFi<br/>(dense_wifi_topology.py)
    participant HW  as 📻 mac80211_hwsim<br/>(wlan15 monitor)
    participant KS  as 🐾 Kismet WIDS<br/>(localhost:2501)
    participant WD  as 🛡️ kismet_wips_daemon.py<br/>(WIPS Daemon & Bridge)
    participant LS  as ⚙️ Logstash
    participant ES  as 🔎 Elasticsearch
    participant KB  as 📈 Kibana

    Note over MN,HW: Khởi động hạ tầng ảo hóa
    MN->>HW: modprobe mac80211_hwsim radios=32
    MN->>MN: Tạo 8 AP hợp lệ, 4 Rogue AP (ap9-ap12)
    MN->>MN: Tạo sta1–sta12
    MN->>HW: iw dev wlan31 set type monitor
    MN->>HW: iw dev wlan31 set channel 11

    Note over HW,KS: Bắt gói tin không dây
    HW->>KS: 802.11 raw frames (Beacon, Probe, Deauth, ...)
    KS->>KS: Phân tích frame → phát hiện<br/>Evil Twin / Rogue AP / Deauth Flood



    Note over KS,WD: Kismet WIPS Daemon (Active Response)
    WD->>KS: GET /session/check_session.json (auth)
    KS-->>WD: 200 OK + session cookie
    loop Polling mỗi 2 giây
        WD->>KS: GET /alerts/all_alerts.json
        KS-->>WD: JSON array of alerts
        WD->>WD: Lọc alert mới & Chuẩn hóa schema → JSON event
        WD->>WD: Ghi log wips-alerts.json & active-response.log
        alt Phát hiện Rogue AP / Evil Twin / Deauth Flood
            WD->>WD: block_ip_firewall() -> simulated_blacklist.txt
            WD->>MN: wireless_deauth_containment() via wlan30
        end
    end

    Note over LS,ES: ELK Pipeline (Docker bind mount)
    LS->>LS: file input: tail wips-alerts.json
    LS->>LS: filter: json codec<br/>date: parse timestamp
    LS->>ES: POST /_bulk HTTPS + TLS<br/>index: wids-alerts-YYYY.MM.DD
    ES->>ES: Lưu trữ, index mapping, shard

    Note over ES,KB: Trực quan hóa
    KB->>ES: GET /_search (aggregation queries)
    ES-->>KB: JSON aggregated results
    KB->>KB: Render Dashboard:<br/>Alert Timeline / Severity Chart<br/>Rogue AP Map / Event Table
```

---

## 3. Luồng xử lý sự kiện tấn công (Attack Event Flow)

```mermaid
flowchart LR
    subgraph ATTACK["🔴 Tình huống tấn công"]
        A1["Evil Twin\nap9/ap10 phát Company-WiFi\ntrên CH11/36 không mã hóa"]
        A2["Deauth Flood\nGửi frame deauth\nhàng loạt tới clients"]
        A3["Rogue AP\nAP trái phép phát\nSSID nội bộ / guest"]
        A4["Auth Brute Force\nThử auth thất bại\n> 10 lần / 5 phút"]
        A5["Unknown Client\nThiết bị lạ kết nối\nvào SSID nội bộ"]
    end

    subgraph DETECT["🔍 Phát hiện (Detection)"]
        D1["Kismet WIDS\nCảnh báo APSPOOF / SSID spoofing"]
        D2["Kismet WIDS\nPhân tích storm deauth / disassoc"]
        D3["Kismet WIDS\nCảnh báo Rogue AP / Unauthorized AP"]
        D4["Kismet WIDS\nCảnh báo Brute Force / WPS push"]
        D5["Kismet WIDS\nCảnh báo Unknown/Unregistered client"]
    end

    subgraph NORMALIZE["⚙️ Chuẩn hóa (ETL & WIPS)"]
        N1["event_type: evil_twin_detected\nseverity: critical\n-> Kích hoạt Deauth & IP Block"]
        N2["event_type: deauth_flood\nseverity: critical\n-> Kích hoạt IP Block & Deauth"]
        N3["event_type: rogue_ap_detected\nseverity: high\n-> Kích hoạt Deauth & IP Block"]
        N4["event_type: wifi_auth_fail\nseverity: medium"]
        N5["event_type: unknown_client_joined\nseverity: high"]
    end

    subgraph STORE["💾 Lưu trữ & Phân tích"]
        ES2["Elasticsearch Index\nwids-alerts-*\nfields: timestamp, source,\nsensor, event_type, ssid,\nbssid, client_mac, severity"]
    end

    subgraph VISUALIZE["📊 Trực quan hóa"]
        KB2["Kibana Dashboard\n🔴 Critical Alerts Panel\n📡 Rogue AP Map\n📈 Attack Timeline\n📋 Event Log Table"]
    end

    A1 --> D1 --> N1
    A2 --> D2 --> N2
    A3 --> D3 --> N3
    A4 --> D4 --> N4
    A5 --> D5 --> N5
    N1 & N2 & N3 & N4 & N5 --> ES2 --> KB2
```

---

## 4. Kiến trúc Docker và kết nối dịch vụ

```mermaid
flowchart TB
    subgraph HOST["🐧 Kali Linux Host"]
        KISMET_HOST["Kismet Process\n:2501"]
        WIPS_DAEMON["kismet_wips_daemon.py\n(WIPS & Bridge)"]
        LOG_HOST["📁 /var/log/\n└── kismet-wips/wips-alerts.json"]
    end

    subgraph DOCKER["🐳 Docker Network (ecp-*)"]
        direction TB
        subgraph SETUP["Setup Service (One-time)"]
            CERTGEN["elasticsearch-certutil\nGenerate CA + TLS Certs\n→ /certs volume"]
        end
        subgraph ES_SVC["Elasticsearch Service"]
            ES_NODE["ecp-elasticsearch\n:9200 (HTTPS)\nxpack.security=true\nTLS + Basic Auth"]
        end
        subgraph KB_SVC["Kibana Service"]
            KB_NODE["ecp-kibana\n:5601 (HTTPS)\nEncryption Keys via ENV"]
        end
        subgraph LS_SVC["Logstash Service"]
            LS_NODE["ecp-logstash\n:5044 (Beats)\nPipeline: wids.conf"]
        end

        CERTGEN -->|"certs volume"| ES_NODE
        CERTGEN -->|"certs volume"| KB_NODE
        CERTGEN -->|"certs volume"| LS_NODE
        ES_NODE <-->|"HTTPS :9200"| KB_NODE
        ES_NODE <-->|"HTTPS :9200"| LS_NODE
    end

    LOG_HOST -->|"Docker bind mount\n(read-only :ro)"| LS_NODE

    BROWSER["🌐 Browser\nhttps://localhost:5601"]
    BROWSER -->|HTTPS| KB_NODE
```

---

## 5. Schema sự kiện JSON chuẩn (Event Schema)

```mermaid
classDiagram
    class WIDSEvent {
        +String timestamp           %% ISO8601, UTC+7
        +String source              %% "kismet-wips-daemon" | "kismet-wids"
        +String sensor              %% "kali-mininet-wifi-sensor-01"
        +String event_type          %% Xem EventType enum bên dưới
        +String description         %% Mô tả chi tiết sự kiện
        +String ssid                %% SSID bị ảnh hưởng
        +String bssid               %% BSSID của AP
        +String client_mac          %% MAC của client (nếu có)
        +Integer channel            %% Kênh Wi-Fi (1/6/11)
        +String encryption          %% "WPA2-Enterprise" | "open" | ...
        +Boolean authorized         %% false = cảnh báo
        +String severity            %% Xem Severity enum
    }

    class EventType {
        <<enumeration>>
        evil_twin_detected
        rogue_ap_detected
        deauth_flood
        wifi_auth_fail
        unknown_client_joined
        unknown_wireless_alert
    }

    class Severity {
        <<enumeration>>
        critical
        high
        medium
        low
    }

    class KismetRaw {
        +String class
        +String hash
        +Integer severity_raw
    }

    class DeauthExtra {
        +Integer deauth_count
        +Integer affected_clients
    }

    class AuthFailExtra {
        +Integer auth_fail_count
        +Integer window_seconds
    }

    WIDSEvent --> EventType
    WIDSEvent --> Severity
    WIDSEvent "1" o-- "0..1" KismetRaw : kismet_raw
    WIDSEvent "1" o-- "0..1" DeauthExtra : deauth fields
    WIDSEvent "1" o-- "0..1" AuthFailExtra : auth_fail fields
```

---

## 6. Timeline khởi động hệ thống

```mermaid
gantt
    title Quy trình khởi động hệ thống WIDS-SIEM
    dateFormat  mm:ss
    axisFormat  %M:%S

    section Hạ tầng ảo
    modprobe mac80211_hwsim radios=32      :a1, 00:00, 5s
    Mininet-WiFi build topology            :a2, after a1, 15s
    Cấu hình wlan31 monitor mode CH11      :a3, after a2, 3s

    section Kismet WIDS
    sudo kismet -c wlan31                  :b1, after a3, 10s
    Kismet sẵn sàng nhận request API      :milestone, b2, after b1, 0s

    section ELK Stack (Docker)
    docker compose up setup (TLS certs)    :c1, 00:00, 60s
    Elasticsearch khởi động               :c2, after c1, 30s
    Kibana khởi động                       :c3, after c2, 20s
    Logstash pipeline active               :c4, after c2, 15s

    section Bridge/WIPS Daemon
    kismet_wips_daemon.py chạy            :d2, after b2, 2s
    Logstash đọc wips-alerts.json         :d3, after c4, 1s
    Kibana hiển thị dữ liệu đầu tiên      :milestone, d4, after d3, 0s
```

---

## 7. Bảng tóm tắt thành phần

| Thành phần | Loại | Địa chỉ / Đường dẫn | Vai trò |
|---|---|---|---|
| `dense_wifi_topology.py` | Python Script | `src/` | Tạo mạng Wi-Fi ảo với 8 AP hợp lệ + 4 Rogue AP |
| `mac80211_hwsim` | Kernel Module | `wlan0`–`wlan32` | Cung cấp 32 card Wi-Fi ảo |
| `wlan31` | Monitor Interface | CH11 | Bắt mọi frame 802.11 cho Kismet |
| **Kismet WIDS** | Daemon | `localhost:2501` | Phân tích frame → sinh alert APSPOOF/Deauth/v.v. |
| `kismet_wips_daemon.py` | Active WIPS Daemon & Bridge | `src/` | Daemon kết nối API Kismet, chuẩn hóa log và cô lập Rogue AP (IP block & Deauth) |
| **Logstash** | Docker Container | `ecp-logstash:5044` | Parse + enrich + forward → Elasticsearch |
| **Elasticsearch** | Docker Container | `ecp-elasticsearch:9200` | Lưu trữ + index WIDS events |
| **Kibana** | Docker Container | `ecp-kibana:5601` | Dashboard trực quan hóa cảnh báo |
| `/var/log/kismet-wips/` | Log Dir | Host FS | File trung gian giữa Scripts và Logstash |
| TLS Certificates | PKI Volume | Docker `certs` volume | Bảo mật toàn bộ kênh truyền ELK |

---

## 8. Luồng dữ liệu bảo mật (Security Data Path)

```mermaid
flowchart LR
    subgraph UNTRUSTED["🔴 Vùng không tin cậy"]
        ROGUE2["Rogue AP\nEvil Twin\nDeauth Attacker"]
    end

    subgraph DETECTION["🟡 Vùng phát hiện & Phản ứng"]
        AIR["📻 Không gian vô tuyến\n(802.11 frames)"]
        KS2["Kismet\nReal-time WIDS\nDetection Engine"]
        WIPS["Kismet WIPS\nDaemon Engine"]
    end

    subgraph PROCESSING["🟠 Vùng xử lý"]
        PIPE["Logstash Pipeline\nParse → Enrich → Normalize\nGeo-IP · Severity mapping · Timestamp fix"]
    end

    subgraph STORAGE["🟢 Vùng lưu trữ & phân tích"]
        IDX["Elasticsearch\nTime-series Index\nFull-text Search"]
        DASH["Kibana\nReal-time Dashboard\nAlert Rules · SIEM Views"]
    end

    ROGUE2 -->|"Beacon / Probe / Deauth\n802.11 frames"| AIR
    AIR -->|"Captured by wlan31\nMonitor Mode"| KS2
    KS2 -->|"REST API\nalerts JSON"| WIPS
    WIPS -->|"Normalized JSON Events\n/var/log/kismet-wips/wips-alerts.json"| PIPE
    PIPE -->|"HTTPS + TLS\nBulk Index"| IDX
    IDX -->|"Aggregated Results"| DASH

    style UNTRUSTED fill:#ff4444,color:#fff
    style DETECTION fill:#ff9900,color:#000
    style PROCESSING fill:#ffcc00,color:#000
    style STORAGE fill:#00aa44,color:#fff
```

---

*Tài liệu được tạo tự động theo kiến trúc thực tế của dự án.*  
*Cập nhật lần cuối: 2026-05-18*
