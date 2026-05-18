# Hướng Dẫn Tích Hợp Kismet WIDS Vào Hệ Thế ELK SIEM & Mininet-WiFi
Tài liệu này phân tích tính khả thi, ưu/nhược điểm và hướng dẫn chi tiết cách thay thế bộ giả lập `virtual_wips_detector.py` bằng công cụ giám sát vô tuyến chuyên nghiệp **Kismet WIDS** trong môi trường giả lập mạng không dây ảo hóa.

---

## 💡 Câu trả lời nhanh: HOÀN TOÀN ĐƯỢC VÀ CỰC KỲ KHUYẾN NGHỊ!

Việc sử dụng **Kismet** thay thế cho script giả lập giúp đề tài/đồ án của bạn nâng tầm từ **"Mô phỏng/Giả lập lý thuyết"** lên thành **"Hệ thống Thực nghiệm Lai (Hybrid Emulation System)"**. Lúc này, hệ thống sẽ chạy một công cụ WIDS thực tế của ngành an ninh mạng để phân tích trực tiếp các gói tin 802.11 thực được truyền tải qua driver sóng vô tuyến ảo của Linux kernel.

---

## 📊 Bảng so sánh: Kismet WIDS vs. Virtual Detector Script

| Tiêu chí | 🐍 Virtual Detector Script (`virtual_wips_detector.py`) | 📡 Kismet WIDS (Hệ thống Thật) |
| :--- | :--- | :--- |
| **Bản chất** | Giả lập sự kiện bằng cách sinh log JSON ngẫu nhiên theo kịch bản định sẵn. | Công cụ Sniffer & WIDS chuyên dụng thực tế, bắt và phân tích gói tin vô tuyến thời gian thực. |
| **Độ chân thực** | **Thấp** (Chỉ mô phỏng dữ liệu đầu ra của WIDS để SIEM xử lý). | **Tuyệt đối** (Phát hiện dựa trên các khung hình vô tuyến 802.11 thực sự bay trong không gian ảo). |
| **Độ tin cậy Demo** | **100%** (Không sợ lỗi phần cứng, lỗi driver hay thiếu gói tin khi thuyết trình trước Hội đồng). | **Trung bình** (Đòi hỏi card mạng ảo hoạt động ổn định và phải thực hiện tấn công thật để sinh log). |
| **Độ khó triển khai** | **Cực kỳ dễ** (Chỉ cần chạy file Python có sẵn). | **Cao** (Yêu cầu cài đặt Kismet, cấu hình interface monitor mode và viết script cầu nối API). |
| **Giá trị học thuật** | Phù hợp để minh họa luồng hoạt động tổng quan và cơ chế tương quan SIEM. | **Điểm tuyệt đối (10/10)**, chứng minh khả năng làm chủ công cụ thực tế và môi trường giả lập mạng sâu. |

---

## 🏗️ Kiến Trúc Luồng Dữ Liệu Tích Hợp Kismet

Khi tích hợp Kismet, luồng dữ liệu của hệ thống SIEM sẽ thay đổi như sau để đảm bảo tính thực tế mà không phá vỡ cấu trúc pipeline ELK đã xây dựng:

```mermaid
graph TD
    %% Styling
    classDef idle fill:#f5f5f5,stroke:#ccc,stroke-dasharray: 5 5,color:#999;
    classDef active fill:#e8f4fd,stroke:#1890ff,stroke-width:2px;
    classDef monitor fill:#fce8e6,stroke:#ea4335,stroke-width:2px,font-weight:bold;
    classDef core fill:#fef7e0,stroke:#fbbc04,stroke-width:2px;
    classDef wids fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;
    classDef siem fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;

    subgraph Host ["Máy Vật Lý (Kali Host)"]
        subgraph Driver ["Tầng Vô Tuyến Ảo (Linux Kernel & Simulator)"]
            HWSIM["mac80211_hwsim<br>(Trình giả lập driver sóng vô tuyến)"]:::core
            WMED["wmediumd<br>(Mô phỏng môi trường truyền dẫn sóng)"]:::core
            HWSIM <--> WMED
        end

        subgraph Radios ["8 Card Mạng Không Dây Ảo (radios=8)"]
            w0["wlan0<br>(Idle)"]:::idle
            w1["wlan1<br>(Idle)"]:::idle
            w2["wlan2<br>(Idle)"]:::idle
            w3["wlan3<br>(Idle)"]:::idle
            w4["wlan4<br>(Idle)"]:::idle
            w5["wlan5<br>(Idle)"]:::idle
            w6["wlan6<br>(Idle)"]:::idle
            w7["wlan7<br>(Monitor Mode)"]:::monitor
        end

        %% Connections to Virtual Air
        w0 <--> HWSIM
        w1 <--> HWSIM
        w2 <--> HWSIM
        w3 <--> HWSIM
        w4 <--> HWSIM
        w5 <--> HWSIM
        w6 <--> HWSIM
        w7 <--> HWSIM

        subgraph MN ["Môi Trường Mininet-WiFi (Chạy dense_wifi_topology.py)"]
            subgraph Legit ["Mạng Wi-Fi Hợp Lệ"]
                ap1["ap1-wlan1<br>(SSID: Company-WiFi, CH 1)"]:::active
                ap2["ap2-wlan1<br>(SSID: Company-WiFi, CH 6)"]:::active
                ap3["ap3-wlan1<br>(SSID: Company-Guest, CH 11)"]:::active
                STAs["Các Trạm Client (sta1 - sta8)<br>(Bắn traffic, kết nối AP)"]:::active
            end

            subgraph Rogue ["Mạng Giả Mạo / Tấn Công"]
                rap["rogueap-wlan1<br>(SSID: Company-WiFi, CH 11)"]:::monitor
                atk["Kẻ Tấn Công (aireplay-ng)<br>(Tấn công qua wlan7)"]:::monitor
            end

            ap1 <--> HWSIM
            ap2 <--> HWSIM
            ap3 <--> HWSIM
            STAs <--> HWSIM
            rap <--> HWSIM
            atk -.->|Bắn gói tin hủy xác thực| w7
        end

        subgraph WIDS ["Hệ Thống Giám Sát & Cầu Nối (WIDS)"]
            w7 -->|Đọc gói tin thô 802.11| K["Kismet WIDS Daemon<br>(Cổng 2501, lọc Alert)"]:::wids
            K -->|Cung cấp Alert REST API| KA["/alerts/all_alerts.json"]:::wids
            KA -->|Polling API (2s/lần)| B["kismet_to_elk.py<br>(Bridge chuyển đổi JSON)"]:::wids
            B -->|Ghi log chuẩn hóa| L["wips-alerts.json<br>(/var/log/virtual-wips/)"]:::wids
        end
    end

    subgraph SIEM ["Tầng Phân Tích & Phản Ứng (Docker ELK)"]
        L -->|Shared Volume| LS["Logstash Pipeline"]:::siem
        LS -->|Elasticsearch Index| ES["Elasticsearch"]:::siem
        ES -->|Trực quan hóa| KB["Kibana SIEM Dashboard"]:::siem
        
        %% Active Response Connection
        L -->|Real-time Tail| AR["wips_elk_containment_simulator.py<br>(Active Response Engine)"]:::siem
        AR -->|Chặn tự động| BL["simulated_blacklist.txt"]:::siem
    end
```

> [!NOTE]
> Để tránh việc phải cấu hình lại toàn bộ bộ lọc Logstash phức tạp và Dashboard Kibana, chúng ta sử dụng một script cầu nối trung gian: [kismet_to_elk.py](file:///home/ph4n10m/Code/wireless-mobile-network-security-project/src/kismet_to_elk.py). Script này sẽ tự động kéo các cảnh báo thô của Kismet qua API, dịch chúng sang cấu trúc JSON chuẩn hóa tương thích ngược 100% với hệ thống của bạn.

---

## 🛠️ Các Bước Thay Thế Kismet Ở Bước 3

### Bước 3.1: Cài đặt Kismet trên Kali Linux
Chạy lệnh sau trên máy Kali Linux để cài đặt phiên bản Kismet mới nhất từ repository chính thức:
```bash
sudo apt update
sudo apt install kismet -y
```

### Bước 3.2: Chuyển Card Mạng Giả Lập sang Monitor Mode
Trong danh sách 8 card mạng ảo được sinh ra từ driver `mac80211_hwsim`, ta sẽ chọn một interface (ví dụ `wlan7`) không được Mininet-WiFi sử dụng để làm "Ăng-ten giám sát" (WIDS Sensor).

Chạy các lệnh sau để đưa card `wlan7` vào trạng thái giám sát:
```bash
# Tắt interface
sudo ip link set wlan7 down

# Chuyển đổi chế độ hoạt động sang Monitor mode
sudo iw dev wlan7 set type monitor

# Bật lại interface
sudo ip link set wlan7 up

# Kiểm tra lại trạng thái (đảm bảo hiển thị type monitor)
iw dev wlan7
```

### Bước 3.3: Khởi cấu hình Kismet quét trên Card mạng ảo
Khởi động Kismet daemon và chỉ định nguồn bắt gói tin là card `wlan7` vừa cấu hình:
```bash
sudo kismet -c wlan7 --no-sqlite
```
*Lưu ý:* Tham số `--no-sqlite` giúp Kismet chạy nhẹ hơn trong môi trường Lab ảo hóa bằng cách giảm thiểu ghi đĩa không cần thiết, chỉ tập trung xử lý trong RAM và đẩy ra API.

### Bước 3.4: Chạy Cầu Nối API Đồng Bộ Log [kismet_to_elk.py](file:///home/ph4n10m/Code/wireless-mobile-network-security-project/src/kismet_to_elk.py)
Khởi chạy script cầu nối mà chúng tôi đã xây dựng sẵn cho bạn tại thư mục `src/`:
```bash
python3 src/kismet_to_elk.py
```
Script này hoạt động như một daemon liên tục giám sát Kismet API (mặc định tại cổng `2501`) và tự động ghi nhận log vào `/var/log/virtual-wips/wips-alerts.json` bất cứ khi nào Kismet phát hiện mối đe dọa không dây thực tế.

---

## ⚠️ Những Thử Thách Cần Lưu Ý Khi Dùng Kismet (Rất Quan Trọng cho Demo)

> [!WARNING]
> Nếu bạn thay hoàn toàn bằng Kismet, bạn **phải chủ động thực hiện hành vi tấn công thật** thì Kibana mới hiển thị cảnh báo. Kismet không tự sinh dữ liệu giả.

### Cách tạo các cuộc tấn công thật để kích hoạt Kismet:
1. **Tấn công Deauthentication Flood**:
   Mở một terminal mới trên Kali Host, sử dụng công cụ `aireplay-ng` bắn các gói tin hủy xác thực giả mạo vào các Client ảo của Mininet-WiFi:
   ```bash
   # Gửi deauth flood liên tục tới client ảo sta1 qua card monitor wlan7
   sudo aireplay-ng -0 100 -a 00:00:00:00:01:00 -c DE:AD:BE:EF:00:01 wlan7
   ```
   *Kismet sẽ lập tức bắt được các khung hình Deauth này và phát ra cảnh báo `DEAUTH_FLOOD`.*

2. **Tấn công Rogue AP / Evil Twin**:
   Khi bạn chạy file `dense_wifi_topology.py`, Mininet-WiFi tự động khởi chạy node `rogueap` phát SSID `Company-WiFi` nhưng dùng mã hóa open trái phép. 
   *Kismet khi quét qua kênh 11 sẽ phát hiện AP này trùng SSID với AP1/AP2 hợp lệ nhưng sai cấu hình bảo mật/BSSID và lập tức kích hoạt cảnh báo loại `ROGUE_AP`.*

---

## 🎯 Đánh Giá và Lời Khuyên Cho Lần Bảo Vệ Đồ Án
* **Phương án an toàn nhất (Khuyên dùng)**: Khi thuyết trình trước Hội đồng, hãy chuẩn bị **cả 2 phương án**. 
  * Hãy bắt đầu demo bằng `virtual_wips_detector.py` để đảm bảo kịch bản chạy mượt mà, trơn tru từ đầu đến cuối và show toàn bộ Dashboard Kibana lung linh.
  * Sau đó, mở slide giải thích kiến trúc và tự tin tuyên bố: *"Hệ thống này hoàn toàn có thể tích hợp trực tiếp với WIDS Kismet thực tế bằng cách lắng nghe qua interface ảo monitor mode và đồng bộ API"* và thực hiện demo nhanh bằng `kismet_to_elk.py` để tạo sự bất ngờ và thuyết phục điểm số tuyệt đối từ Hội đồng chấm thi!
