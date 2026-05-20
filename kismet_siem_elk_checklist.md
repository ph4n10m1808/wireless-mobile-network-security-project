# Checklist Tiến độ Hoàn thành Dự án Kismet WIDS & ELK SIEM (Dạng Tree Chi tiết)

Dưới đây là sơ đồ cây checklist phân cấp giúp bạn theo dõi chi tiết từng đầu mục công việc từ chuẩn bị, lập cấu hình, cài đặt Kismet, chạy script đồng bộ, thực hiện tấn công thực nghiệm cho đến tích hợp SIEM ELK và bảo vệ đồ án. Đây là tài liệu quản lý đi cùng kế hoạch [kismet_siem_elk_plan.md](file:///home/ph4n10m/Code/wireless-mobile-network-security-project/kismet_siem_elk_plan.md).

---

## 🌳 SƠ ĐỒ CÂY CHECKLIST TIẾN ĐỘ KISMET WIDS

- [x] **1. Chuẩn bị Hạ tầng & Thiết lập Môi trường**
  - [x] **1.1. Cấu hình Kali Linux Host**
    - [x] 1.1.1. Cập nhật hệ thống Kali Linux (`apt update && apt upgrade`)
    - [x] 1.1.2. Cài đặt Python 3 và các thư viện cần thiết (`pip install requests datetime timezone`)
    - [x] 1.1.3. Cài đặt các công cụ mạng bổ trợ và tấn công không dây (`nmap`, `wireless-tools`, `aircrack-ng`, `jq`)
  - [x] **1.2. Giả lập Sóng Vô tuyến ảo**
    - [x] 1.2.1. Nạp driver nhân Linux giả lập sóng (`sudo modprobe mac80211_hwsim radios=32`)
    - [x] 1.2.2. Kiểm tra driver bằng lệnh `iw dev` (Đảm bảo xuất hiện các interface ảo từ `wlan0` đến `wlan32`)
    - [x] 1.2.3. Cấu hình tự động nạp module driver sau khi reboot host (Cập nhật `/etc/modules`)
  - [x] **1.3. Cài đặt & Dọn dẹp Mininet-WiFi**
    - [x] 1.3.1. Cài đặt Mininet-WiFi gốc và các thành phần phụ thuộc (`wmediumd`)
    - [x] 1.3.2. Chạy lệnh dọn dẹp ban đầu `sudo mn -c` để tránh xung đột interface ảo
  - [x] **1.4. Thiết lập Môi trường Docker cho SIEM**
    - [x] 1.4.1. Cài đặt Docker & Docker Compose trên Kali Host
    - [x] 1.4.2. Tăng giới hạn bộ nhớ ảo cho Elasticsearch (`sudo sysctl -w vm.max_map_count=262144`)
    - [x] 1.4.3. Lưu cấu hình bộ nhớ ảo vĩnh viễn vào file `/etc/sysctl.conf`

- [x] **2. Triển khai & Tùy biến Hạ tầng SIEM ELK Stack**
  - [x] **2.1. Cấu hình Docker Compose (`docker-compose.yml`)**
    - [x] 2.1.1. Khai báo các thông số môi trường trong file `.env` (phiên bản `9.0.1`, mật khẩu `Vsl@2026`)
    - [x] 2.1.2. Cấu hình volume mount log cho Logstash để map `/var/log/kismet-wips` từ Host vào Container
    - [x] 2.1.3. Khởi tạo khóa mã hóa Kibana (`ENCRYPTION_KEY`) bằng script `generate_key.sh`
  - [x] **2.2. Cấu hình Pipeline Logstash chuyên biệt**
    - [x] 2.2.1. Thiết lập cấu hình chính `logstash.conf` nhận log WIDS chuẩn hóa (`wips-alerts.json`)
    - [x] 2.2.2. Cấu hình bộ lọc phân tích thời gian thực khớp sự kiện `@timestamp`
    - [x] 2.2.3. Loại bỏ các file sinh log mạng giả lập không liên quan để tối ưu hóa pipeline SIEM
  - [x] **2.3. Phân quyền và Khởi động dịch vụ**
    - [x] 2.3.1. Tạo các thư mục log và thiết lập quyền đọc ghi cho container (`sudo chmod 755` và `sudo chmod 666`)
    - [x] 2.3.2. Khởi động cụm ELK Stack bằng lệnh `docker-compose up -d`
    - [x] 2.3.3. Kiểm tra trạng thái container (`docker-compose ps`) đảm bảo cả 3 dịch vụ đều `healthy`

- [x] **3. Cài đặt & Triển khai Kismet WIDS (Tầng Giám sát Vô tuyến)**
  - [x] **3.1. Cài đặt Kismet Daemon**
    - [x] 3.1.1. Cài đặt Kismet thông qua repository (`sudo apt install kismet -y`)
    - [x] 3.1.2. Xác nhận Kismet đã cài đặt thành công (`kismet --version`)
  - [x] **3.2. Cấu hình Card Giám sát Monitor Mode**
    - [x] 3.2.1. Lựa chọn card mạng ảo trống `wlan31` làm anten nghe trộm sóng ảo
    - [x] 3.2.2. Chuyển card `wlan31` sang Monitor mode (`sudo ip link set wlan31 down && sudo iw dev wlan31 set type monitor && sudo ip link set wlan31 up`)
    - [x] 3.2.3. Kiểm tra lại trạng thái monitor mode bằng lệnh `iw dev wlan31`
  - [x] **3.3. Cấu hình & Chạy Kismet**
    - [x] 3.3.1. Chạy Kismet chỉ định bắt gói trên card monitor ảo (`sudo kismet -c wlan31 --log-prefix /var/log/kismet-wips/`)
    - [x] 3.3.2. Truy cập giao diện Web UI Kismet tại `http://localhost:2501` để kiểm tra quét sóng ảo thành công
    - [x] 3.3.3. Cấu hình whitelist bảo vệ AP Spoofing (8 BSSID hợp lệ) trong `/etc/kismet/kismet_site.conf`
  - [x] **3.4. Chạy WIPS Daemon & Cầu nối API (`kismet_wips_daemon.py`)**
    - [x] 3.4.1. Tạo file WIPS Daemon Python `src/kismet_wips_daemon.py` kết nối với REST API của Kismet
    - [x] 3.4.2. Cấu hình hàm map trường dữ liệu thô của Kismet sang chuẩn JSON SIEM
    - [x] 3.4.3. Chạy daemon và xác nhận log chuẩn hóa được ghi vào `/var/log/kismet-wips/wips-alerts.json`

- [x] **4. Triển khai Bộ Ngăn Chặn Chủ Động (WIPS Active Response)**
  - [x] **4.1. Thiết lập Engine Phòng vệ (`kismet_wips_daemon.py`)**
    - [x] 4.1.1. Chạy daemon giám sát real-time API cảnh báo Kismet, xử lý phân tích logic an ninh
    - [x] 4.1.2. Kiểm tra hàm ghi log chuẩn hóa JSON hoạt động ổn định
  - [x] **4.2. Thực thi Ngăn chặn & Cô lập Vô tuyến**
    - [x] 4.2.1. Trích xuất thông tin vi phạm (BSSID của Rogue AP hoặc MAC của Attacker thực hiện deauth flood)
    - [x] 4.2.2. Tự động dùng card mạng `wlan30` bắn gói deauth ngăn chặn kết nối tới Rogue AP
    - [x] 4.2.3. Tự động ghi MAC/IP vi phạm vào file blacklist tường lửa (`simulated_blacklist.txt` trên Host)
    - [x] 4.2.4. Ghi lại lịch sử hoạt động ngăn chặn vào nhật ký cách ly `/var/log/kismet-wips/active-response.log`

- [ ] **5. Cấu hình Dashboard & Phân tích Cảnh báo (Kibana SIEM)**
  - [ ] **5.1. Tạo Data Views trên Kibana**
    - [ ] 5.1.1. Tạo Data View `wids-alerts-*` kết nối tới Elasticsearch
    - [ ] 5.1.2. Kiểm tra ánh xạ kiểu dữ liệu (đảm bảo các trường như `event_type.keyword` đã sẵn sàng)
  - [ ] **5.2. Thiết kế giao diện Dashboard tập trung**
    - [ ] 5.2.1. Widget 1: Bộ đếm tổng số cuộc tấn công vô tuyến thực tế do Kismet phát hiện
    - [ ] 5.2.2. Widget 2: Biểu đồ cột thể hiện Top SSIDs/BSSIDs bị tấn công hoặc giả mạo do Kismet bắt được
    - [ ] 5.2.3. Widget 3: Biểu đồ tròn phân tích tỷ lệ các loại tấn công (Deauth Flood, Rogue AP, Evil Twin)
    - [ ] 5.2.4. Widget 4: Biểu đồ giám sát các hành động cách ly thành công (Active response containment)
    - [ ] 5.2.5. Widget 5: Trực quan hóa nhật ký cách ly của WIPS Active Response từ file log của daemon

- [x] **6. Tấn công Thực nghiệm, Kiểm thử & Đánh giá (Live Hacking & Testing)**
  - [x] **6.1. Kiểm thử Kịch bản Rogue AP / Evil Twin**
    - [x] 6.1.1. Chạy Mininet-WiFi `dense_wifi_topology.py` kích hoạt các node rogue AP `ap9-ap12` phát sóng trùng tên
    - [x] 6.1.2. Xác nhận Kismet phát hiện cảnh báo Rogue AP / SSID Spoofing trên giao diện Web UI và qua API
  - [x] **6.2. Kiểm thử Kịch bản Deauthentication Flood thật**
    - [x] 6.2.1. Mở terminal tấn công, sử dụng `aireplay-ng -0 150 -a <BSSID> -c <Client_MAC> wlan30` gửi gói deauth flood thực
    - [x] 6.2.2. Xác nhận Kismet phát hiện, kích hoạt cảnh báo `DEAUTH_FLOOD` mức `Critical`
  - [x] **6.3. Kiểm thử Tương quan Hệ thống & Phản ứng**
    - [x] 6.3.1. Kiểm tra log WIPS Daemon nhận sự kiện $\rightarrow$ Đẩy lên Logstash $\rightarrow$ Kibana hiển thị cảnh báo
    - [x] 6.3.2. Xác nhận daemon Active Response tự động chặn Rogue AP qua `wlan30` và ghi MAC/IP vi phạm vào `simulated_blacklist.txt` cách ly thành công

- [ ] **7. Hoàn thiện Đồ án & Chuẩn bị Báo cáo Bảo vệ**
  - [ ] **7.1. Biên soạn Slide Thuyết trình**
    - [ ] 7.1.1. Slide Giới thiệu: Đề tài bảo mật WiFi thực tế sử dụng Kismet WIDS thật kết hợp Mininet-WiFi ảo hóa
    - [ ] 7.1.2. Slide Kiến trúc: Sơ đồ Mermaid luồng dữ liệu Kismet WIDS -> WIPS Daemon -> Logstash -> ES -> Kibana SIEM
    - [ ] 7.1.3. Slide Giá trị thực tiễn: Lợi ích của việc phân tích gói tin 802.11 thực bằng Kismet so với các bộ mô phỏng log thông thường
  - [ ] **7.2. Chuẩn bị Kịch bản Demo thực tế trước Hội đồng**
    - [ ] 7.2.1. Thiết lập sẵn các Cửa sổ Terminal chuyên nghiệp tương ứng với các luồng hoạt động
    - [ ] 7.2.2. Kiểm tra tính ổn định của Kismet quét sóng ảo và tốc độ tương quan log trên Kibana Dashboard trước giờ bảo vệ
    - [ ] 7.2.3. Chuẩn bị sẵn tài liệu backup (ảnh chụp dashboard, log file mẫu) đề phòng sự cố kỹ thuật đột xuất
