# 🎓 KHUNG BÁO CÁO ĐỀ TÀI CHUYÊN SÂU (REPORT FRAMEWORK)

## Đề tài: "Thiết kế và mô phỏng hệ thống ngăn chặn xâm nhập không dây WIPS trong môi trường Wi-Fi mật độ cao sử dụng Mininet-WiFi tích hợp ELK Stack SIEM"

> [!NOTE]
> Khung báo cáo này đã được tinh chỉnh toàn diện dựa trên tài liệu tham khảo `Triển khai WIDS SIEM Wazuh_1.pdf`, đồng thời cập nhật chính xác theo thực tế mã nguồn hiện tại của bạn: chuyển đổi từ **Wazuh** sang **ELK Stack (Elasticsearch, Logstash, Kibana)** làm SIEM chính, thay thế bộ sinh cảnh báo giả lập bằng **Kismet WIDS** thật bắt gói tin trên interface ảo `wlan31` trong chế độ Monitor Mode của Mininet-WiFi, sử dụng động cơ WIPS Daemon (`kismet_wips_daemon.py`) tích hợp cầu nối để gửi log chuẩn hóa, và loại bỏ các file sinh log mạng giả lập (`network_event_generator.py`) để tập trung tuyệt đối vào luồng log bảo mật từ Kismet.

---

## 📑 MỤC LỤC CHI TIẾT ĐỀ XUẤT

```mermaid
mindmap
  root((Báo cáo WIPS-SIEM))
    Chương 1: Tổng quan
      Mạng Wi-Fi mật độ cao
      Rogue AP & Evil Twin
      Deauth Flood
      Khái niệm WIDS / WIPS
      Hệ thống SIEM
    Chương 2: Thiết kế hệ thống
      Kiến trúc tổng thể
      Tầng giả lập vô tuyến
      Luồng log chuẩn hóa
      Kịch bản phản ứng WIPS
    Chương 3: Xây dựng & Cấu hình
      Cụm Docker ELK
      Cấu hình Logstash Pipeline
      Topology Mininet-WiFi
      Cấu hình Kismet Monitor wlan31
      Whitelist bảo vệ AP Spoofing
      Động cơ WIPS kismet_wips_daemon
    Chương 4: Active Response WIPS
      Daemon Giám sát
      Cơ chế Blacklist tự động
      Log cách ly phòng chống
    Chương 5: Thực nghiệm & Đánh giá
      Demo Rogue AP & Evil Twin
      Tấn công Deauth Flood thật
      Kibana Dashboard
      Đánh giá độ trễ & hiệu năng
    Chương 6: Kết luận
      Kết quả đạt được
      Hạn chế giả lập
      Hướng phát triển AP thật
```

---

### CHƯƠNG 1: TỔNG QUAN VỀ AN TOÀN MẠNG KHÔNG DÂY VÀ SIEM

* **1.1. Thách thức bảo mật trong mạng Wi-Fi mật độ cao (High-Density Wi-Fi)**
  * Phân tích đặc thù môi trường doanh nghiệp lớn, trường học hoặc hội nghị.
  * Vấn đề quản lý thiết bị, sự chồng chéo kênh sóng, và các điểm yếu cố hữu của chuẩn 802.11.
* **1.2. Các kỹ thuật tấn công vô tuyến phổ biến**
  * **1.2.1. Rogue AP (Điểm truy cập trái phép):** Cách thức kẻ tấn công lắp đặt thiết bị AP lậu trong mạng nội bộ để bypass tường lửa.
  * **1.2.2. Evil Twin (Điểm truy cập sinh đôi độc hại):** Kỹ thuật giả mạo SSID của doanh nghiệp với cấu hình không mật khẩu (Open) hoặc giả mạo trang đăng nhập (Captive Portal) nhằm đánh cắp thông tin.
  * **1.2.3. Deauthentication Flood Attack (Tấn công từ chối dịch vụ vô tuyến):** Cơ chế gửi frame ngắt kết nối liên tục để ép Client rớt mạng hoặc ép Client chuyển vùng (roaming) sang AP giả mạo của kẻ tấn công.
* **1.3. Giải pháp WIDS và WIPS**
  * Định nghĩa, chức năng giám sát (WIDS) và chủ động ngăn chặn cách ly (WIPS).
  * So sánh cơ chế hoạt động của WIDS/WIPS dựa trên phần cứng chuyên dụng so với giả lập.
* **1.4. Hệ thống SIEM và vai trò quản lý log tập trung**
  * Giới thiệu về khái niệm SIEM (Security Information and Event Management).
  * Phân tích cấu trúc hạ tầng **ELK Stack** (Elasticsearch, Logstash, Kibana) đóng vai trò làm trung tâm tiếp nhận, chuẩn hóa và trực quan hóa các sự kiện an ninh mạng vô tuyến.

---

### CHƯƠNG 2: THIẾT KẾ KIẾN TRÚC HỆ THỐNG MÔ PHỎNG WIPS-SIEM

* **2.1. Yêu cầu thiết kế hệ thống**
  * Khả năng mô phỏng mạng Wi-Fi mật độ cao với nhiều AP và Station hoạt động song song.
  * Khả năng thu giữ gói tin vô tuyến thực tế (802.11 frames) từ môi trường giả lập.
  * Khả năng chuẩn hóa cấu trúc dữ liệu JSON đồng bộ và bảo mật đường truyền log SIEM qua mã hóa TLS.
  * Cơ chế tự động kích hoạt phản ứng (Active Response) ngăn chặn kẻ tấn công thời gian thực.
* **2.2. Kiến trúc tổng thể hệ thống (System Architecture)**
  * Chi tiết sơ đồ 4 phân tầng cốt lõi:
    1. **Tầng mạng ảo (Mininet-WiFi + mac80211_hwsim):** Tạo ra sóng Wi-Fi ảo, các AP hợp lệ và AP tấn công.
    2. **Tầng cảm biến (Kismet WIDS):** Sử dụng anten giám sát ảo (`wlan31`) chuyển sang Monitor Mode để thu giữ dữ liệu thô.
    3. **Tầng cầu nối & phản ứng chủ động (kismet_wips_daemon.py):** Lấy cảnh báo từ Kismet REST API thông qua cookie-based session, chuẩn hóa schema JSON ghi vào nhật ký trung gian đồng thời kích hoạt các luồng phản ứng ngăn chặn.
    4. **Tầng SIEM trung tâm (ELK Stack):** Tiếp nhận log qua Logstash pipeline, lưu trữ tại Elasticsearch và hiển thị trên Kibana Dashboard.
* **2.3. Thiết kế luồng dữ liệu sự kiện an ninh (Security Data Flow)**
  * Sơ đồ tuần tự từ lúc xảy ra vụ tấn công vô tuyến $\rightarrow$ Card monitor thu giữ $\rightarrow$ Kismet sinh alert $\rightarrow$ Bridge script trích xuất $\rightarrow$ Logstash chuyển tiếp $\rightarrow$ Elasticsearch lập chỉ mục $\rightarrow$ Kibana cảnh báo.
* **2.4. Thiết kế Schema sự kiện chuẩn (Event Schema Standardization)**
  * Định nghĩa định dạng JSON chuẩn dùng chung cho hệ thống bao gồm: `timestamp`, `source`, `sensor`, `event_type`, `ssid`, `bssid`, `client_mac`, `channel`, `encryption`, `authorized` và các metadata thô của Kismet.

---

### CHƯƠNG 3: XÂY DỰNG VÀ CẤU HÌNH HỆ THỐNG

* **3.1. Thiết lập hạ tầng SIEM ELK Stack trong môi trường Docker Container**
  * **3.1.1. Cài đặt chứng chỉ SSL/TLS tự động:** Sử dụng dịch vụ Setup sinh CA và chứng chỉ nội bộ bảo mật kết nối HTTPS.
  * **3.1.2. Cấu hình Docker Compose:** Phân bổ tài nguyên (`mem_limit`, `vm.max_map_count`), mở cổng và bind mount thư mục lưu log `/var/log/kismet-wips` từ host Kali.
* **3.2. Cấu hình và tối ưu hóa Pipeline Logstash**
  * Thiết lập đầu vào (`input { file { path => "/usr/share/logstash/wids/wips-alerts.json" } }`).
  * Xây dựng bộ lọc (`filter`): Tự động phân tích JSON, thiết lập chỉ mục thời gian thực khớp sự kiện (`@timestamp`), và gán siêu dữ liệu index prefix cho Elasticsearch.
  * Loại bỏ Double Ingestion và các log mạng giả lập không liên quan để tối ưu băng thông.
* **3.3. Xây dựng môi trường giả lập mạng Wi-Fi mật độ cao**
  * Thiết lập mã nguồn `src/dense_wifi_topology.py` cấu hình 32 radios ảo bằng `mac80211_hwsim`.
  * Cấu hình monkey-patch vô hiệu hóa hành vi gỡ driver của Mininet-WiFi khi thoát nhằm bảo vệ card giám sát của host.
  * Khai báo vị trí tọa độ địa lý, thiết lập 8 AP hợp lệ ứng với 4 zone vật lý, hỗ trợ cả 2 băng tần (2.4 GHz & 5 GHz) sử dụng mật khẩu chung và 12 Stations di động kết nối xen kẽ.
* **3.4. Cài đặt và cấu hình bộ cảm biến Kismet WIDS & Whitelist bảo vệ**
  * Tận dụng card mạng ảo dư thừa `wlan31`, chuyển đổi sang chế độ Monitor Mode để thực hiện giám sát quét đa kênh (dual-band hopping).
  * Khởi động `kismet` ngầm định hướng thu thập gói tin không dây ảo, cấu hình đường dẫn log chuyên biệt bằng `--log-prefix` để lưu trữ dữ liệu forensics.
  * Cấu hình Whitelist nhận dạng AP Spoofing / SSID Spoofing thông qua `apspoof` rule trong `/etc/kismet/kismet_site.conf` bảo vệ 8 APs hợp lệ chống lại 4 Rogue APs ảo:
    * `apspoof=CompanyWiFiRule:ssid="Company-WiFi",validmacs="..."`
    * `apspoof=CompanyWiFi5GRule:ssid="Company-WiFi-5G",validmacs="..."`
    * `apspoof=CompanyGuestRule:ssid="Company-Guest",validmacs="..."`
    * `apspoof=CompanyGuest5GRule:ssid="Company-Guest-5G",validmacs="..."`
* **3.5. Lập trình cầu nối API Kismet sang SIEM (`kismet_wips_daemon.py`)**
  * Cơ chế xác thực Session cookie thông qua `/session/check_session.json` của Kismet REST API.
  * Thuật toán khử trùng lặp cảnh báo (Deduplication) sử dụng tập hợp lưu trữ hash của Kismet alert.
  * Ánh xạ thông minh mức độ nghiêm trọng từ thang điểm 0-10 của Kismet sang chuẩn SIEM (`critical`, `high`, `medium`, `low`).

---

### CHƯƠNG 4: PHÁT TRIỂN MODULE PHẢN ỨNG CHỦ ĐỘNG WIPS (ACTIVE RESPONSE)

* **4.1. Sự cần thiết của cơ chế phản ứng chủ động và cô lập thực tế**
  * Giải thích việc kết hợp cả hai cơ chế phòng thủ: Cô lập mạng (IP Blacklist Tường lửa) và Cách ly sóng vô tuyến (Wireless Deauth Containment) để tạo ra lá chắn bảo mật toàn diện.
* **4.2. Thiết lập Engine Ngăn chặn tự động an ninh thời gian thực (`kismet_wips_daemon.py`)**
  * Cơ chế đa luồng (Multi-threading) theo dõi bất đồng bộ API cảnh báo Kismet.
  * Tự động trích xuất các thông số nguồn đe dọa: BSSID của Rogue AP/Evil Twin hoặc địa chỉ MAC của kẻ tấn công Deauth Flood.
* **4.3. Kỹ thuật Ngăn chặn thực tế sử dụng aireplay-ng và Tường lửa IP Blacklist**
  * Cơ chế sử dụng card mạng chuyên dụng `wlan30` gửi các gói tin deauthentication nhắm mục tiêu để phá vỡ kết nối tới Rogue AP giả mạo.
  * Tự động cập nhật danh sách đen (`simulated_blacklist.txt`) ghi nhận toàn bộ các thực thể độc hại bị phát hiện trong không gian vô tuyến ảo.
  * Lưu trữ nhật ký cách ly an ninh mạng đầy đủ tại `/var/log/kismet-wips/active-response.log` phục vụ công tác điều tra số (Digital Forensics) sau sự cố.

---

### CHƯƠNG 5: THỰC NGHIỆM, KIỂM THỬ VÀ ĐÁNH GIÁ KẾT QUẢ

* **5.1. Kịch bản thực nghiệm 1: Phát hiện và xử lý Rogue AP / Evil Twin**
  * **Các bước tiến hành:** Chạy topology $\rightarrow$ kích hoạt node `rogueap` phát SSID `Company-WiFi` open $\rightarrow$ client sta1 bị thu hút kết nối.
  * **Kết quả thu nhận:** Kismet phát hiện AP giả mạo trùng SSID nhưng sai BSSID $\rightarrow$ Kích hoạt cảnh báo mức độ **Critical** đẩy lên SIEM $\rightarrow$ Blacklist ghi nhận BSSID vi phạm.
* **5.2. Kịch bản thực nghiệm 2: Tấn công và ngăn chặn Deauthentication Flood thực tế**
  * **Các bước tiến hành:** Sử dụng công cụ `aireplay-ng` gửi dồn dập frame deauth thật trên card monitor ảo hướng tới client trong mạng ảo.
  * **Kết quả thu nhận:** Kismet bắt được mật độ frame deauth bất thường vượt ngưỡng $\rightarrow$ Ghi nhận log cảnh báo tấn công từ chối dịch vụ $\rightarrow$ Active response tự động bắt giữ MAC kẻ tấn công đưa vào diện cách ly.
* **5.3. Trực quan hóa và Tương quan dữ liệu an ninh trên Kibana SIEM Dashboard**
  * Thiết kế giao diện Dashboard chuyên nghiệp bao gồm:
    * Biểu đồ thời gian (Timeline) đếm số lượng tấn công vô tuyến thực tế.
    * Bản đồ phân tích mật độ các loại sự cố (Deauth Flood, Rogue AP, Evil Twin).
    * Bảng thống kê chi tiết BSSID giả mạo, cường độ sóng, và danh sách các MAC đang bị cô lập.
* **5.4. Đánh giá hiệu năng hệ thống**
  * Khảo sát độ trễ trung bình từ thời điểm thực hiện tấn công vật lý ảo đến khi Kibana SIEM cập nhật biểu đồ (Mục tiêu đạt $< 3$ giây).
  * Đánh giá độ chính xác của whitelist baseline và tỷ lệ dương tính giả (False Positive) của hệ thống.

---

### CHƯƠNG 6: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

* **6.1. Các kết quả đã đạt được của đề tài**
  * Xây dựng thành công môi trường mạng Wi-Fi ảo mật độ cao cực kỳ ổn định, không gây sập nguồn nhờ cấu hình bypass NetworkManager thông minh.
  * Tích hợp thành công bộ WIDS thực tế Kismet hoạt động mượt mà với hạ tầng SIEM ELK Stack doanh nghiệp.
  * Hoàn thiện đầy đủ quy trình khép kín của một hệ thống WIPS thông qua module Active Response.
* **6.2. Các hạn chế do điều kiện mô phỏng**
  * Môi trường ảo hóa chưa phản ánh trọn vẹn nhiễu sóng vật lý thực tế, sự suy hao khoảng cách, vật cản và môi trường sóng vô tuyến hỗn hợp.
* **6.3. Hướng phát triển tiếp theo của đề tài**
  * Tích hợp các thiết bị AP vật lý thật (như UniFi, Aruba) hỗ trợ giao thức Syslog/SNMP.
  * Triển khai hệ thống xác thực tập trung 802.1X (WPA3-Enterprise) kết hợp giải pháp kiểm soát truy cập NAC (Network Access Control) và tự động hóa điều phối SOAR.

---

> [!TIP]
>
> ### 💡 BÍ QUYẾT BẢO VỆ ĐỀ TÀI TRƯỚC HỘI ĐỒNG:
>
> Khi giảng viên đặt câu hỏi hóc búa: **"Đề tài ghi chữ 'Ngăn chặn' (Prevention - WIPS) nhưng em chạy lab ảo thì ngăn chặn thật bằng cách nào khi không có thiết bị switch/router/AP thật?"**
>
> **Bạn trả lời tự tin như sau:**
> *"Thưa thầy cô, do giới hạn hạ tầng phòng Lab không có Access Point doanh nghiệp hỗ trợ API chặn cứng hoặc tạo deauth-containment thật ngoài không khí. Vì vậy, đề tài tập trung chuyên sâu vào **Thiết kế kiến trúc hệ thống WIPS chuẩn doanh nghiệp** và xây dựng **Module Active Response mô phỏng**. Khi phát hiện tấn công, module này tự động trích xuất MAC/BSSID độc hại ghi vào tệp tin blacklist cách ly an ninh và ghi nhật ký xử lý. Trong thực tế doanh nghiệp, file blacklist này sẽ được tự động đồng bộ xuống API của Controller Wi-Fi (như Cisco WLC, Aruba) hoặc Firewall để chặn truy cập vật lý ngay lập tức."*

---

## 🛠️ FILE CHECKLIST CỦA BẠN (CẬP NHẬT TRẠNG THÁI MỚI NHẤT)

Dưới đây là bảng đối chiếu trực quan tiến độ thực hiện đề tài dựa trên những file bạn vừa thay đổi/xóa:

| Phân hệ / Công việc                  |      Trạng thái cũ      |              Trạng thái hiện tại              | Mô tả thay đổi kỹ thuật                                                                                                                                                                                                                                                                    |
| :--------------------------------------- | :-------------------------: | :-----------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Giập lập mạng vô tuyến ảo** |          8 Radios          |        **32 Radios (Hoàn thành)**        | Nâng cấp radios lên 32 giúp tách biệt dải interface của Mininet-WiFi (`wlan0`-`wlan24`) và Host Kali (`wlan30`-`wlan31`), tránh tuyệt đối lỗi tranh chấp namespace gây treo đơ hệ thống.                                                                             |
| **Bảo vệ card Monitor**          |          Chưa có          |      **Bỏ qua rmmod (Hoàn thành)**      | Cấu hình monkey-patch trong `dense_wifi_topology.py` chặn lệnh `rmmod mac80211_hwsim` giúp wlan31 monitor mode được giữ nguyên khi tắt mạng ảo.                                                                                                                                 |
| **Tránh xung đột OS**           |          Chưa có          |  **Bỏ qua NetworkManager (Hoàn thành)**  | Tạo file cấu hình `99-unmanage-hwsim.conf` để NetworkManager bỏ qua toàn bộ card ảo `wlan*`, loại bỏ hoàn toàn lỗi sập nguồn/Kernel Panic của máy tính host Kali.                                                                                                         |
| **Tầng cảm biến giám sát**    |     Sinh log giả lập     |    **Kismet WIDS Thật (Hoàn thành)**    | Thay thế hoàn toàn file giả lập `virtual_wips_detector.py` đã xóa bằng hệ thống **Kismet WIDS thật** nghe sóng ảo trên card `wlan31` chế độ monitor và có áp dụng whitelist bảo vệ AP Spoofing.                                                                                                                 |
| **Cầu nối log & Phòng vệ WIPS**  |   Chưa chạy tự động   | **Tích hợp WIPS Daemon (Hoàn thành)**    | Chuyển đổi file khởi chạy trong `run_project.sh` từ `virtual_wips_detector.py` sang **`src/kismet_wips_daemon.py`** để lấy alert thật từ REST API Kismet, tự động chuẩn hóa sang log JSON và kích hoạt ngăn chặn qua `wlan30`. |
| **Cấu hình Logstash**            | Hỗn hợp nhiều nguồn log | **Độc quyền Kismet Log (Hoàn thành)** | Tinh chỉnh file `logstash.conf` loại bỏ hoàn toàn input/filter của file sinh log mạng giả lập (`network_event_generator.py` đã xóa) và file log mẫu. Logstash hiện tại chỉ tiếp nhận và xử lý duy nhất luồng log WIDS từ Kismet để đẩy lên Elasticsearch SIEM. |
| **Giao diện Kibana SIEM**         |      Chưa cấu hình      |            **Đang thực hiện**            | Bạn chỉ cần import Data View `wids-alerts-*` và thiết kế các Dashboard Kibana theo mô tả ở Chương 5 để hoàn thiện 100% phần thực hành!                                                                                                                                      |
