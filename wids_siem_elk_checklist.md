# Checklist Tiến độ Hoàn thành Dự án/Đề tài WIDS & ELK SIEM (Dạng Tree Chi tiết)

Dưới đây là sơ đồ cây checklist phân cấp giúp bạn theo dõi chi tiết từng đầu mục công việc từ chuẩn bị, lập cấu hình, phát triển mã nguồn, tích hợp hệ thống cho đến thử nghiệm và bảo vệ đồ án. Đây là tài liệu quản lý độc lập đồng hành cùng tài liệu kế hoạch triển khai [wids_siem_elk_plan.md](file:///home/ph4n10m/Code/wireless-mobile-network-security-project/wids_siem_elk_plan.md).

---

## 🌳 SƠ ĐỒ CÂY CHECKLIST TIẾN ĐỘ

- [ ] **1. Chuẩn bị Hạ tầng & Thiết lập Môi trường**
  - [ ] **1.1. Cấu hình Kali Linux Host**
    - [ ] 1.1.1. Cập nhật hệ thống Kali Linux (`apt update && apt upgrade`)
    - [ ] 1.1.2. Cài đặt Python 3 và các thư viện cốt lõi (`pip install datetime timezone`)
    - [ ] 1.1.3. Cài đặt các công cụ mạng bổ trợ (`nmap`, `iw`, `wireless-tools`, `jq`)
  - [ ] **1.2. Giả lập Sóng Vô tuyến ảo**
    - [ ] 1.2.1. Nạp driver nhân Linux giả lập sóng (`sudo modprobe mac80211_hwsim radios=8`)
    - [ ] 1.2.2. Kiểm tra driver bằng lệnh `iw dev` (Đảm bảo xuất hiện các interface ảo `wlan0` - `wlan7`)
    - [ ] 1.2.3. Tạo cơ chế tự động nạp module driver sau khi reboot host (Cập nhật `/etc/modules`)
  - [ ] **1.3. Cài đặt & Dọn dẹp Mininet-WiFi**
    - [ ] 1.3.1. Cài đặt Mininet-WiFi gốc và các thành phần phụ thuộc (`wmediumd`)
    - [ ] 1.3.2. Chạy lệnh dọn dẹp ban đầu `sudo mn -c` để tránh xung đột cổng
  - [ ] **1.4. Thiết lập Môi trường Docker cho SIEM**
    - [ ] 1.4.1. Cài đặt Docker & Docker Compose trên Kali Host
    - [ ] 1.4.2. Tăng giới hạn bộ nhớ ảo cho Elasticsearch (`sudo sysctl -w vm.max_map_count=262144`)
    - [ ] 1.4.3. Lưu cấu hình bộ nhớ ảo vĩnh viễn vào file `/etc/sysctl.conf`

- [ ] **2. Triển khai & Tùy biến Hạ tầng SIEM ELK Stack**
  - [ ] **2.1. Cấu hình Docker Compose (`docker-compose.yml`)**
    - [ ] 2.1.1. Khai báo các thông số môi trường trong file `.env` (phiên bản `9.0.1`, mật khẩu `Vsl@2026`)
    - [ ] 2.1.2. Cấu hình volume mount log cho Logstash để map `/var/log/virtual-wips` và `/var/log/virtual-network` từ Host vào Container
    - [ ] 2.1.3. Khởi tạo chứng chỉ bảo mật TLS (`certs/`) bằng script `generate_key.sh`
  - [ ] **2.2. Cấu hình Pipeline Logstash (`logstash.conf`)**
    - [ ] 2.2.1. Thiết lập input `file` đọc log WIDS (`wips-alerts.json`) với tag `wids`
    - [ ] 2.2.2. Thiết lập input `file` đọc log Network (`network-events.json`) với tag `network`
    - [ ] 2.2.3. Viết bộ lọc filter `json` để giải mã cấu trúc log tự động
    - [ ] 2.2.4. Cấu hình trường `@timestamp` khớp chính xác với thời gian thực của sự kiện
    - [ ] 2.2.5. Cấu hình output đẩy log động vào Elasticsearch theo tên index (`wids-alerts-*` và `network-events-*`)
  - [ ] **2.3. Phân quyền và Khởi động dịch vụ**
    - [ ] 2.3.1. Tạo các thư mục log và thiết lập quyền đọc ghi cho container (`sudo chmod 755` và `sudo chmod 666`)
    - [ ] 2.3.2. Khởi động cụm ELK Stack bằng lệnh `docker-compose up -d`
    - [ ] 2.3.3. Kiểm tra trạng thái container (`docker-compose ps`) đảm bảo cả 3 dịch vụ đều `healthy`

- [ ] **3. Phát triển Các Module Giả lập & Thu thập (Host Kali)**
  - [ ] **3.1. Topology Mạng Wi-Fi Mật Độ Cao (`dense_wifi_topology.py`)**
    - [ ] 3.1.1. Định nghĩa vị trí địa lý (`position`) và cấu hình các trạm (`sta1` đến `sta8`)
    - [ ] 3.1.2. Khởi tạo 2 AP hợp lệ phát SSID `Company-WiFi` (AP1 kênh 1, AP2 kênh 6)
    - [ ] 3.1.3. Khởi tạo 1 AP khách hợp lệ phát SSID `Company-Guest` (AP3 kênh 11)
    - [ ] 3.1.4. Thiết lập AP giả mạo phát trùng SSID `Company-WiFi` nhưng dùng mã hóa open (Rogue AP/Evil Twin trên kênh 11)
    - [ ] 3.1.5. Tích hợp Controller ảo điều phối kết nối
  - [ ] **3.2. Module Phát hiện Xâm nhập Vô tuyến (`virtual_wips_detector.py`)**
    - [ ] 3.2.1. Xây dựng whitelist baseline chứa danh sách AP hợp lệ (SSID, BSSID, encryption, channel)
    - [ ] 3.2.2. Triển khai logic phát hiện Rogue AP (SSID trùng công ty nhưng BSSID không có trong whitelist)
    - [ ] 3.2.3. Triển khai logic phát hiện Evil Twin (SSID trùng công ty, BSSID lạ, và cấu hình mã hóa Open)
    - [ ] 3.2.4. Triển khai logic phát hiện Deauthentication Flood (Vượt ngưỡng deauth_count trong khoảng thời gian)
    - [ ] 3.2.5. Triển khai logic phát hiện Wi-Fi Brute Force (Vượt ngưỡng auth_fail_count từ cùng một MAC)
    - [ ] 3.2.6. Triển khai logic phát hiện thiết bị chưa đăng ký (`unknown_client_joined`) kết nối vào mạng
  - [ ] **3.3. Bộ sinh Sự kiện Mạng Tương quan (`network_event_generator.py`)**
    - [ ] 3.3.1. Giả lập log DHCP Server cấp phát IP cho MAC lạ kết nối vào Wi-Fi (`dhcp_lease_assigned`)
    - [ ] 3.3.2. Giả lập log Firewall phát hiện IP lạ quét cổng dịch vụ nhạy cảm (`port_scan_detected`)
    - [ ] 3.3.3. Giả lập log DNS Server phát hiện truy vấn tên miền độc hại của C2 (`suspicious_dns_query`)

- [ ] **4. Triển khai Module Phản ứng Chủ động (WIPS Active Response)**
  - [ ] **4.1. Thiết lập Engine Phản ứng (`wips_elk_containment_simulator.py`)**
    - [ ] 4.1.1. Lập cấu hình đọc tệp tin WIDS Alerts và Network Events theo thời gian thực (Cơ chế `tail -f`)
    - [ ] 4.1.2. Triển khai hàm phân tích cú pháp log JSON
  - [ ] **4.2. Thực thi Ngăn chặn & Cô lập**
    - [ ] 4.2.1. Tự động trích xuất thông tin vi phạm (BSSID giả mạo hoặc IP kẻ tấn công) khi phát hiện sự kiện nguy cấp
    - [ ] 4.2.2. Triển khai cơ chế Blacklist (Ghi MAC/IP vi phạm vào tệp tin `simulated_blacklist.txt` trên Host)
    - [ ] 4.2.3. Ghi lại lịch sử hoạt động ngăn chặn vào tệp tin nhật ký `/var/log/virtual-wips/active-response.log`

- [ ] **5. Cấu hình Dashboard & Phân tích Cảnh báo (Kibana SIEM)**
  - [ ] **5.1. Tạo Data Views trên Kibana**
    - [ ] 5.1.1. Tạo Data View `wids-alerts-*` kết nối tới Elasticsearch
    - [ ] 5.1.2. Tạo Data View `network-events-*` kết nối tới Elasticsearch
    - [ ] 5.1.3. Kiểm tra ánh xạ kiểu dữ liệu (đảm bảo các trường như `event_type.keyword` đã sẵn sàng truy vấn)
  - [ ] **5.2. Thiết kế giao diện Dashboard tập trung**
    - [ ] 5.2.1. Widget 1: Bộ đếm tổng số cuộc tấn công vô tuyến thời gian thực
    - [ ] 5.2.2. Widget 2: Biểu đồ cột thể hiện Top SSIDs/BSSIDs giả mạo bị phát hiện
    - [ ] 5.2.3. Widget 3: Biểu đồ tròn phân tích tỷ lệ các loại tấn công (Deauth, Evil Twin, Brute Force)
    - [ ] 5.2.4. Widget 4: Bảng theo dõi tương quan sâu (Liên kết MAC vô tuyến $\rightarrow$ IP DHCP cấp $\rightarrow$ Port scan trên tường lửa)
    - [ ] 5.2.5. Widget 5: Trực quan hóa nhật ký cách ly của WIPS Active Response từ file log của daemon

- [ ] **6. Kiểm thử, Đánh giá & Khắc phục Sự cố (Testing & Validation)**
  - [ ] **6.1. Kiểm thử Từng phần (Unit Testing)**
    - [ ] 6.1.1. Khởi động Mininet-WiFi, quét sóng và kiểm tra AP giả mạo
    - [ ] 6.1.2. Kiểm tra quyền ghi log JSON của Python Scripts và quyền đọc log của container Logstash
    - [ ] 6.1.3. Xem trực tiếp Logstash pipeline stdout để xác nhận dữ liệu đã được parse đúng cấu trúc JSON
  - [ ] **6.2. Kiểm thử Tương quan Hệ thống (System Integration Testing)**
    - [ ] 6.2.1. Kích hoạt kịch bản tấn công Evil Twin $\rightarrow$ Kiểm tra Logstash nhận log $\rightarrow$ Kiểm tra Kibana hiển thị cảnh báo mức `Critical`
    - [ ] 6.2.2. Chạy tương quan liên kết (Unknown Client $\rightarrow$ DHCP Lease $\rightarrow$ Nmap Scan) $\rightarrow$ Xác nhận Kibana hiển thị sự kiện tương quan đầy đủ thông tin
    - [ ] 6.2.3. Kiểm tra độ trễ (Từ lúc tấn công vô tuyến xảy ra cho đến khi hiển thị trên Kibana, mục tiêu < 5 giây)
  - [ ] **6.3. Đánh giá Khả năng Ngăn chặn**
    - [ ] 6.3.1. Kích hoạt Evil Twin $\rightarrow$ Xác nhận daemon Active Response phát hiện và ghi nhận chặn BSSID thành công
    - [ ] 6.3.2. Chạy giả lập IP port scan $\rightarrow$ Xác nhận daemon Active Response block IP thành công
    - [ ] 6.3.3. Kiểm chứng nội dung tệp tin `simulated_blacklist.txt` có khớp chính xác với đối tượng vi phạm hay không

- [ ] **7. Hoàn thiện Đồ án & Chuẩn bị Báo cáo Bảo vệ**
  - [ ] **7.1. Biên soạn Slide Thuyết trình**
    - [ ] 7.1.1. Slide Giới thiệu: Đề tài, tính cấp thiết và lý do chọn giải pháp ảo hóa Mininet-WiFi
    - [ ] 7.1.2. Slide Kiến trúc: Sơ đồ Mermaid biểu diễn luồng dữ liệu (Mininet-WiFi $\rightarrow$ Logstash $\rightarrow$ ES $\rightarrow$ Kibana)
    - [ ] 7.1.3. Slide Giá trị của SIEM: Phân tích sự khác biệt giữa WIDS đơn lẻ và SIEM tương quan logs
    - [ ] 7.1.4. Slide Ngăn chặn & Giảm False Positive: Giải pháp Baseline Whitelist và cơ chế Active Response
  - [ ] **7.2. Chuẩn bị Kịch bản Demo thực tế trước Hội đồng**
    - [ ] 7.2.1. Cấu hình sẵn 5 Terminal chuyên nghiệp tương ứng với các luồng hoạt động
    - [ ] 7.2.2. Kiểm tra tốc độ mạng và khả năng tải của Kibana Dashboard trước giờ bảo vệ
    - [ ] 7.2.3. Chuẩn bị sẵn tài liệu backup (Ảnh chụp dashboard, Log file mẫu) đề phòng sự cố kỹ thuật đột xuất
