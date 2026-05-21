# 📑 Kế Hoạch Triển Khai & Thực Nghiệm Hệ Thống WIDS/WIPS Thực Tế Sử Dụng Kismet & ELK Stack

Tài liệu này trình bày chi tiết kế hoạch triển khai, cấu trúc luồng dữ liệu thực tế và kịch bản thực nghiệm kiểm thử cho hệ thống **WIDS/WIPS lai (Hybrid WIDS/WIPS)**. Hệ thống kết hợp giả lập môi trường Wi-Fi mật độ cao bằng **Mininet-WiFi**, bắt gói tin thật ở chế độ Monitor Mode bằng công cụ tiêu chuẩn **Kismet WIDS**, và quản lý an ninh tập trung trên cụm **SIEM ELK Stack (Elasticsearch, Logstash, Kibana)**.

> [!NOTE]
> Dự án được thiết kế chạy hoàn toàn trên máy host **Kali Linux** (cấu hình khuyến nghị: RAM 16-32 GB), không yêu cầu phần cứng Router/AP vật lý. Tối ưu hóa tài nguyên bằng cách kết hợp Docker (chạy cụm ELK Stack) và môi trường Native của Kali (chạy giả lập Wi-Fi bằng Mininet-WiFi + Kismet WIDS thật).

---

## 1. Kiến Trúc Luồng Dữ Liệu Thực Nghiệm (Data Flow)

Kiến trúc hệ thống được thiết kế để Kismet WIDS trực tiếp bắt và phân tích gói tin 802.11 thô từ không gian vô tuyến ảo (mac80211_hwsim), sau đó qua bộ WIPS Active Response tự động thực hiện cô lập và đẩy log chuẩn hóa lên SIEM.

```mermaid
graph TD
    subgraph "Môi trường Wi-Fi ảo (Mininet-WiFi)"
        A1[Legit AP1 - AP8] -->|Sóng Wi-Fi ảo 802.11| S[Stations sta1-sta12]
        R[4 Rogue APs / Evil Twin & Guest Spoof] -.->|Phát sóng trùng kênh 11/36/1/153| S
        AT[Kẻ tấn công: kali_wids_attacks.sh] -.->|Bắn deauth flood thực| S
    end

    subgraph "Giám sát Vô tuyến & Phân tích (Kismet WIDS)"
        W[Card monitor ảo: wlan31] -->|Bắt gói tin raw 802.11| K[Kismet WIDS Daemon: Port 2501]
        K -->|Alert Engine| KA[Kismet REST API /alerts/all_alerts.json]
    end

    subgraph "Đồng bộ, Ngăn chặn & Chuẩn hóa (WIPS & Bridge)"
        WD[Active WIPS: kismet_wips_daemon.py] -->|Query API & Sync| KA
        WD -->|Ghi log JSON chuẩn hóa| M[wips-alerts.json]
        WD -->|Ghi log cách ly| AR[active-response.log]
        WD -.->|Gửi gói Deauth cô lập via wlan30| S
        WD -.->|Block IP/MAC vi phạm| BL[simulated_blacklist.txt]
    end

    subgraph "Lưu trữ & Trực quan (SIEM ELK Stack)"
        M -->|Mount Volume| LS[Logstash Containers: Port 5044]
        LS -->|Đẩy log qua HTTPS| ES[Elasticsearch: Port 9200]
        ES -->|Lưu index wids-alerts-*| ES
        ES -->|Truy vấn dữ liệu| KB[Kibana SIEM Dashboard: Port 5601]
    end

    style R fill:none,stroke:#ff3333,stroke-width:2px;
    style K fill:none,stroke:#cc00cc,stroke-width:2px;
    style ES fill:none,stroke:#3366cc,stroke-width:2px;
    style KB fill:none,stroke:#9933ff,stroke-width:2px;
    style WD fill:none,stroke:#ff9933,stroke-width:2px;
```

---

## 2. Thiết Kế Tích Hợp ELK Stack Cho Kismet

### 2.1. Cấu hình Volume Mount trong Docker Compose
Dữ liệu log được đồng bộ từ Host vào container Logstash thông qua bind mount thư mục chia sẻ `/var/log/kismet-wips/`. Cấu hình dịch vụ `logstash` trong tệp `SIEM/docker-compose.yml` được tối ưu hóa như sau:

```yaml
  logstash:
    depends_on:
      elasticsearch:
        condition: service_healthy
    image: docker.elastic.co/logstash/logstash:${STACK_VERSION}
    container_name: ecp-logstash
    volumes:
      - ./certs:/usr/share/logstash/config/certs:z
      - ./logstash/pipeline:/usr/share/logstash/pipeline:z
      - /var/log/kismet-wips:/usr/share/logstash/wids:ro # Mount thư mục log WIPS & Kismet Bridge
    ports:
      - "5044:5044"
    restart: always
    environment:
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - LS_JAVA_OPTS=-Xms1g -Xmx1g
```

### 2.2. Pipeline Logstash Tinh Chỉnh (`SIEM/logstash/pipeline/logstash.conf`)
Đầu vào và bộ lọc được thiết kế chuyên biệt để chỉ nhận duy nhất luồng dữ liệu an ninh WIDS từ file log chuẩn hóa `wips-alerts.json`:

```ruby
input {
  # Nhận log từ hệ thống WIDS ảo (đã chuẩn hóa qua kismet_wips_daemon)
  file {
    path => "/usr/share/logstash/wids/wips-alerts.json"
    codec => "json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    tags => ["wids", "wireless"]
  }
}

filter {
  if "wids" in [tags] {
    mutate {
      add_field => { "[@metadata][index_prefix]" => "wids-alerts" }
    }
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
}

output {
  if "wids" in [tags] {
    elasticsearch {
      hosts => ["https://ecp-elasticsearch:9200"]
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
      ssl_enabled => true
      ssl_certificate_authorities => ["/usr/share/logstash/config/certs/ca/ca.crt"]
      index => "%{[@metadata][index_prefix]}-%{+YYYY.MM.dd}"
    }
  }
}
```

### 2.3. Cấu hình Whitelist bảo vệ trong Kismet (AP Spoofing Detection)
Để Kismet WIDS có thể tự động phân biệt được AP hợp lệ và Rogue AP (Evil Twin / SSID Spoofing), danh sách các MAC (BSSID) hợp lệ được cấu hình trong `/etc/kismet/kismet_site.conf` như sau:

```ini
# =========================================================================
# Whitelist bảo vệ mạng nội bộ giả lập (Dense Dual-Band Topology)
# =========================================================================

# 1. Bảo vệ SSID "Company-WiFi" (2.4 GHz - AP1, AP3, AP5)
apspoof=CompanyWiFiRule:ssid="Company-WiFi",validmacs="02:00:00:00:A1:00,02:00:00:00:A2:00,02:00:00:00:A3:00"

# 2. Bảo vệ SSID "Company-WiFi-5G" (5 GHz - AP2, AP4, AP6)
apspoof=CompanyWiFi5GRule:ssid="Company-WiFi-5G",validmacs="02:00:00:00:A1:50,02:00:00:00:A2:50,02:00:00:00:A3:50"

# 3. Bảo vệ SSID "Company-Guest" (2.4 GHz - AP7)
apspoof=CompanyGuestRule:ssid="Company-Guest",validmacs="02:00:00:00:A4:00"

# 4. Bảo vệ SSID "Company-Guest-5G" (5 GHz - AP8)
apspoof=CompanyGuest5GRule:ssid="Company-Guest-5G",validmacs="02:00:00:00:A4:50"
```

### 2.4. Thiết lập Quyền truy cập Log cho Container Logstash

Để đảm bảo Logstash chạy trong Docker có quyền đọc các file log WIDS trên Host Kali Linux:

```bash
# Tạo và phân quyền cho thư mục log WIDS
sudo mkdir -p /var/log/kismet-wips
sudo chmod -R 755 /var/log/kismet-wips

# Tạo file log rỗng và cấp quyền đọc ghi cho container
sudo touch /var/log/kismet-wips/wips-alerts.json
sudo touch /var/log/kismet-wips/active-response.log
sudo chmod 666 /var/log/kismet-wips/wips-alerts.json
sudo chmod 666 /var/log/kismet-wips/active-response.log
```

# ─── Chuẩn bị trước khi chạy (Dành cho máy Kali Linux mới) ───────────────────
Nếu đây là một máy ảo/máy vật lý Kali Linux mới được cài đặt, vui lòng chạy các lệnh sau để đảm bảo đầy đủ môi trường:

```bash
# 1. Cập nhật hệ thống & cài đặt Git, Docker, Docker Compose, Kismet
sudo apt update && sudo apt install git docker.io docker-compose kismet curl -y

# 2. Khởi động Docker & cấp quyền không cần sudo
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

# 3. Phân quyền và chạy script cài đặt môi trường ảo (Miniconda & Mininet-WiFi)
chmod +x run_project.sh setup_miniconda_env.sh src/*.sh src/*.py tools/*.py tools/*.sh SIEM/*.sh
sudo ./setup_miniconda_env.sh
```

---

## 3. Quy Trình Thực Nghiệm Từng Bước

### Bước 1: Khởi động Toàn bộ Hạ tầng bằng `run_project.sh`
Thay vì phải cấu hình thủ công từng thành phần, bạn chỉ cần thực thi script điều khiển hợp nhất:
```bash
sudo ./run_project.sh
```
* **Chọn Menu `[2]`**: Hệ thống sẽ tự động thực hiện:
  1. Khởi động cụm SIEM Docker (Elasticsearch, Logstash, Kibana) ngầm.
  2. Nạp driver `mac80211_hwsim` cấu hình **32 radios ảo** (wlan0 đến wlan32).
  3. Cấu hình NetworkManager để bỏ qua toàn bộ card mạng ảo `wlan*`, tránh Kernel Panic.
  4. Khởi chạy topo mạng Mininet-WiFi (`dense_wifi_topology.py`).
  5. Đưa card `wlan31` sang chế độ **Monitor Mode** khóa kênh 11.
  6. Khởi động ngầm **Kismet WIDS** lắng nghe trên card `wlan31`.
  7. Khởi chạy ngầm **Active WIPS Daemon** (`kismet_wips_daemon.py`) để bắt đầu poll API.

### Bước 2: Thực Hiện Kịch Bản Tấn Công Để Kích Hoạt WIDS
Mở một Terminal mới trên Host Kali và thực thi script tấn công:
```bash
sudo ./src/kali_wids_attacks.sh
```

#### 🛡️ Kịch bản 1: Tấn công Deauthentication Flood (Phát hiện và Cô lập)
* Trên menu của `kali_wids_attacks.sh`, chọn **`1`** (Deauth Attack) hoặc **`4`** (Amok Deauth).
* Script sẽ sử dụng `aireplay-ng` qua card chuyên dụng `wlan30` gửi hàng loạt deauth frame.
* **Quy trình xử lý tự động**:
  1. Kismet phát hiện mật độ Deauth bất thường $\rightarrow$ Sinh cảnh báo qua REST API.
  2. `kismet_wips_daemon.py` poll được cảnh báo $\rightarrow$ Tạo sự kiện JSON lưu vào `wips-alerts.json`.
  3. Logstash phát hiện tệp log thay đổi $\rightarrow$ Đẩy lên Elasticsearch.
  4. Đồng thời, `kismet_wips_daemon.py` phát hiện cuộc tấn công Deauth $\rightarrow$ Tự động trích xuất MAC kẻ tấn công đưa vào tường lửa chặn (`simulated_blacklist.txt`) và ghi nhật ký chặn vào `active-response.log`.

#### 🛡️ Kịch bản 2: Tấn công Evil Twin / Rogue AP
* Khi Mininet-WiFi khởi chạy, các node rogueAP `ap9-ap12` tự động phát sóng giả mạo SSID `Company-WiFi` và `Company-Guest` không mã hóa.
* **Quy trình xử lý tự động**:
  1. Kismet quét qua kênh 11/36, phát hiện AP giả mạo trùng SSID nhưng sai BSSID và cấu hình bảo mật $\rightarrow$ Sinh alert `SSID_SPOOFING` / `ROGUE_AP`.
  2. `kismet_wips_daemon.py` ghi nhận sự kiện $\rightarrow$ Tự động kích hoạt **Wireless Deauth Containment**: dùng `aireplay-ng` qua card `wlan30` liên tục bắn gói deauth vào AP giả mạo này để ngăn cản client ảo `sta*` kết nối vào nó.
  3. Ghi log cô lập vào `active-response.log` và chuyển tiếp thông tin an ninh lên Kibana Dashboard.

---

## 4. Cấu Hình Trực Quan Hóa & Tương Quan Trên Kibana (SIEM Dashboard)

Sau khi khởi động ELK Stack và chạy hệ thống WIDS/WIPS, log sẽ tự động được gửi tới Elasticsearch. Thực hiện các bước sau trên Kibana để xây dựng Security Dashboard:

### 4.1. Tạo Data Views trên Kibana

1. Truy cập Kibana tại `https://localhost:5601` (Tài khoản: `elastic` / mật khẩu trong file `.env`).
2. Vào **Stack Management** > **Kibana** > **Data Views** (hoặc Index Patterns).
3. Tạo Data View mới:
   * **`wids-alerts-*`** (Trường thời gian: `@timestamp`) → Chứa toàn bộ log cảnh báo an ninh vô tuyến từ Kismet WIDS qua WIPS Daemon.

### 4.2. Thiết Kế Dashboard "Wireless Security SIEM"

Thêm các Widget trực quan hóa sau vào Dashboard:

1. **Metric Count (Bộ đếm cảnh báo nguy hiểm)**: Tổng số cảnh báo Wi-Fi mức Critical/High thực tế do Kismet phát hiện (Lọc theo `event_type: "evil_twin_detected" OR event_type: "deauth_flood" OR event_type: "rogue_ap_detected"`).
2. **Bar Chart (Top SSIDs / BSSIDs bị tấn công)**: Trục X là `bssid.keyword` hoặc `ssid.keyword`, trục Y là số lượng sự kiện. Giúp xác định mục tiêu bị tấn công nhiều nhất.
3. **Pie Chart (Tỷ lệ các loại tấn công vô tuyến)**: Phân tách theo `event_type.keyword`. Cho cái nhìn trực quan về phân bổ loại tấn công trong môi trường lab.
4. **Bar Chart (Giám sát hành động cách ly)**: Trực quan hóa số lần WIPS Active Response kích hoạt ngăn chặn thành công (deauth containment, IP block).
5. **Data Table (Nhật ký sự kiện chi tiết)**:
   * Trình bày các trường: `@timestamp`, `event_type`, `severity`, `ssid`, `bssid`, `client_mac`, `description`.
   * Thể hiện rõ timeline chuỗi sự kiện từ phát hiện → cảnh báo → cô lập.

---

## 5. Kịch Bản Demo & Hướng Dẫn Thuyết Trình Trước Hội Đồng

Để thuyết trình đề tài một cách ấn tượng và thuyết phục nhất, hãy mở các cửa sổ Terminal như sau:

| Terminal | Mục tiêu trình diễn | Chi tiết hiển thị |
| :--- | :--- | :--- |
| **Terminal 1** (Host) | Bảng điều khiển `run_project.sh` | Show quá trình cấu hình Driver 32 radios, tự động cấu hình bypass NetworkManager, và prompt điều khiển Mininet-WiFi (`mininet-wifi>`). |
| **Terminal 2** (Host) | Monitor Log Cô lập | Chạy lệnh `tail -f /var/log/kismet-wips/active-response.log` để show thời gian thực WIPS tự động kích hoạt ngăn chặn, block IP/MAC và kích hoạt deauth cách ly. |
| **Terminal 3** (Host) | Trình tấn công `kali_wids_attacks.sh` | Thực hiện các tùy chọn tấn công trực quan (bắn deauth, beacon flood). |
| **Trình duyệt Web** | Giao diện Kibana SIEM | Truy cập `https://localhost:5601`, trình diễn Dashboard tương quan an ninh vô tuyến trực quan, biểu đồ timeline nhảy vọt ngay khi bấm tấn công (độ trễ < 3 giây). |

### 💡 Các lập luận "đắt giá" bảo vệ đề tài:

1. **Khắc phục triệt để hạn chế tài nguyên**: Sử dụng driver `mac80211_hwsim` với 32 radios giúp cách ly hoàn toàn môi trường mạng thật của Host (`wlan0`) với môi trường Mininet-WiFi (`wlan1-24`) và các card an ninh (`wlan30-31`), đảm bảo lab chạy cực kỳ ổn định không bị mất mạng hay treo đơ máy.
2. **Kỹ thuật sniffer lai thực tế (Hybrid Emulation)**: Hệ thống sử dụng công cụ WIDS tiêu chuẩn **Kismet** thực thụ để bắt và phân tích frame thô 802.11 ảo, chứng minh khả năng làm chủ công nghệ WIDS/WIPS cấp độ doanh nghiệp. Đây là điểm khác biệt so với các đồ án mô phỏng log thuần túy.
3. **Quy trình WIPS khép kín và tự động**: WIPS daemon không chỉ cảnh báo mà còn chủ động phản ứng bằng cơ chế phản kích vô tuyến (Deauth Containment qua `wlan30`) và ngăn chặn mạng (Blacklist), giải quyết trọn vẹn bài toán phản ứng phòng vệ vô tuyến.
4. **Giải quyết vấn đề "False Positive" (Cảnh báo giả) trong môi trường mật độ cao**:
   * *Lập luận*: Trong môi trường mật độ cao (văn phòng, trường học), có rất nhiều sóng Wi-Fi của nhà dân hoặc văn phòng lân cận lọt vào, dễ gây ra cảnh báo giả liên tục.
   * *Giải pháp*: WIDS của chúng ta đã thiết lập cơ chế **AP Baseline Whitelist** trong Kismet (cấu hình `apspoof` rule trong `kismet_site.conf`), so khớp cả SSID, BSSID và chuẩn mã hóa. Hệ thống chỉ cảnh báo Rogue AP/Evil Twin khi có thiết bị phát sóng trùng SSID nội bộ nhưng sai địa chỉ BSSID, triệt tiêu phần lớn cảnh báo giả từ các AP xung quanh.

---

## 6. Hướng Dẫn Khắc Phục Sự Cố (Troubleshooting)

### 6.1. Lỗi Logstash báo không có quyền đọc log (`Permission Denied`)

* **Triệu chứng**: Logstash container chạy bình thường nhưng không đẩy được dữ liệu lên Elasticsearch, log của Logstash báo lỗi truy cập file JSON.
* **Cách khắc phục**: Cấp quyền đọc/ghi rộng hơn cho các file log trên Host để container truy cập được:
  ```bash
  sudo chmod 666 /var/log/kismet-wips/wips-alerts.json
  sudo chmod 666 /var/log/kismet-wips/active-response.log
  ```

### 6.2. Lỗi Elasticsearch sập liên tục do RAM ảo (`max virtual memory areas`)

* **Triệu chứng**: Khi chạy `docker-compose up`, Elasticsearch Container tự động dừng đột ngột.
* **Cách khắc phục**: Hệ điều hành mặc định giới hạn bộ nhớ ảo quá thấp cho Elasticsearch. Hãy chạy lệnh sau trên host Kali:
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  # Đảm bảo lưu cấu hình sau khi reboot máy:
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
  ```

### 6.3. Mininet-WiFi bị lỗi xung đột cổng/interface ảo cũ

* **Triệu chứng**: Chạy script `dense_wifi_topology.py` báo lỗi interface bận (`busy`) hoặc không tạo được nút mạng.
* **Cách khắc phục**: Hãy dọn dẹp các tài nguyên Mininet cũ trước khi chạy mới:
  ```bash
  sudo mn -c
  # Nếu vẫn lỗi, hãy reload lại driver giả lập sóng:
  sudo modprobe -r mac80211_hwsim
  sudo modprobe mac80211_hwsim radios=32
  ```

### 6.4. Kismet WIDS không phát hiện AP ảo

* **Triệu chứng**: Kismet khởi chạy thành công nhưng không quét thấy bất kỳ AP nào trên giao diện Web UI.
* **Cách khắc phục**: Kiểm tra card monitor đúng mode và đúng kênh:
  ```bash
  # Xác nhận wlan31 đang ở Monitor Mode
  iw dev wlan31 info
  # Nếu type không phải "monitor", cấu hình lại:
  sudo ip link set wlan31 down
  sudo iw dev wlan31 set type monitor
  sudo ip link set wlan31 up
  sudo iw dev wlan31 set channel 11
  ```

### 6.5. WIPS Daemon không nhận được alert từ Kismet API

* **Triệu chứng**: `kismet_wips_daemon.py` chạy nhưng log trống, không có sự kiện nào được ghi.
* **Cách khắc phục**: Kiểm tra kết nối API và xác thực:
  ```bash
  # Test thủ công API Kismet
  curl -s -k http://localhost:2501/system/status.json | python3 -m json.tool
  # Kiểm tra thông tin đăng nhập trong .env
  cat .env | grep KISMET
  ```
