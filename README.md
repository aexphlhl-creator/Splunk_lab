Splunk + Sysmon Detection Lab — Điều tra log Windows trên Splunk
Lab tự dựng để thực hành công việc của một SOC Analyst: thu thập log Windows bằng Sysmon và Splunk Universal Forwarder, điều tra sự kiện trên Splunk Enterprise bằng SPL, và viết detection cho hành vi PowerShell mã hóa.
Nguyên tắc xuyên suốt của lab: mỗi kết luận đều tách rõ ba mức — điều log ghi trực tiếp, suy luận từ nhiều bằng chứng, và phần chưa thể xác minh. Không kết luận vượt quá bằng chứng.
Kiến trúc lab
Thành phần
Chi tiết
Splunk Server
Ubuntu 24.04, máy zabbix, IP 192.168.1.179
Splunk Enterprise
10.6.2.5, web port 8000, receiving port 9997, index lab
Máy Windows
Windows Server 2019, hostname DC01, IP 192.168.1.54
Sysmon
v15.22, cấu hình SwiftOnSecurity (sysmonconfig-export.xml)
Universal Forwarder
Gửi Windows Security và Sysmon Operational về index lab
Atomic Red Team
Module invoke-atomicredteam 2.3.0 đã cài trên máy Windows
Windows Server 2019 (DC01)
  Sysmon + Windows Security logs
        |
        v
Splunk Universal Forwarder  --->  TCP 9997  --->  Splunk Enterprise (Ubuntu 24.04)
                                                      index: lab
                                                      Web UI: port 8000
Các bước dựng lab
Chuẩn bị máy Splunk Server: kiểm tra tài nguyên, nâng RAM từ 3,8 GiB lên 7,8 GiB (8 CPU, 84 GB đĩa trống).
Chuyển bộ cài splunk-10.6.2.5-linux-amd64.deb lên server bằng scp và cài bằng dpkg -i.
Khởi động Splunk lần đầu với --run-as-root, đặt tài khoản admin, bật boot-start.
Tạo index lab và mở cổng nhận log 9997 (Receiving Port, trạng thái Enabled).
Cài Sysmon v15.22 trên máy Windows với cấu hình SwiftOnSecurity.
Cài Splunk Universal Forwarder, trỏ Receiving Indexer về 192.168.1.179:9997.
Cấu hình inputs.conf với 4 kênh log — Application, Security, System và Microsoft-Windows-Sysmon/Operational — đều vào index lab, rồi khởi động lại service SplunkForwarder.
Xác nhận pipeline: index lab nhận 27,1K events, sự kiện mới nhất cách thời điểm kiểm tra vài giây — log chảy theo thời gian thực.
Cài module Atomic Red Team invoke-atomicredteam 2.3.0 trên máy Windows để chuẩn bị cho các bài test mô phỏng tấn công.
Sau giai đoạn dựng ban đầu, Splunkd trên Linux được chuyển sang systemd và sửa quyền các thư mục /opt/splunk/var, /opt/splunk/etc cho tài khoản splunk; trạng thái xác nhận là active và enabled, truy vấn từ DC01 vẫn trả về log Security và Sysmon bình thường.
Sự cố đã gặp và cách xử lý
Điền nhầm địa chỉ Splunk vào ô Deployment Server thay vì Receiving Indexer khi cài Forwarder — đã xóa trống Deployment Server và điền đúng ở Receiving Indexer.
Dán nội dung inputs.conf vào Command Prompt thay vì PowerShell — làm lại trong PowerShell.
Cài NuGet provider bị treo nhiều phút — khởi động lại máy Windows thì cài được NuGet 2.8.5.208 và module Atomic Red Team.
Lệnh Install-AtomicRedTeam báo not recognized — hàm này đã bị bỏ ở module bản 2.x; hàm chính hiện tại là Invoke-AtomicTest. Lưu ý: báo cáo lab chưa ghi nhận một bài test Atomic cụ thể đã chạy.
Phương pháp điều tra
Các truy vấn giới hạn theo index=lab, host=DC01, nguồn log và khoảng thời gian. Các loại sự kiện chính được dùng:
Sysmon Event 1 — tạo tiến trình: Image, ParentImage, CommandLine, ProcessGuid, ParentProcessGuid.
Windows Security 4624 / 4634 — tạo và kết thúc phiên đăng nhập, đối chiếu bằng Logon ID trên cùng host.
Sysmon Event 15 — tạo luồng dữ liệu có tên (NTFS ADS): TargetFilename, Contents, ProcessGuid.
Kiểm tra bổ sung: chữ ký số Authenticode, SHA256, Test-Path và cấu hình Sysmon — mỗi phép kiểm tra có phạm vi riêng.
Phát hiện chính
Tệp cập nhật Microsoft Antimalware
Sysmon Event 1 ghi wuauclt.exe tạo AM_Delta_Patch_1.463.399.0.exe trong SoftwareDistribution. Tệp còn tồn tại lúc kiểm tra, chữ ký Authenticode hợp lệ (Microsoft Corporation) và SHA256 tính lại trùng giá trị Sysmon ghi. Bằng chứng phù hợp với hoạt động cập nhật — nhưng chữ ký hợp lệ và hash trùng không tự chứng minh mọi hành vi của tệp đều an toàn.
Chuỗi PowerShell mã hóa
Cây tiến trình ngày 21/11: explorer.exe → PowerShell → cmd.exe → PowerShell thứ hai với tham số -e và Base64, dưới tài khoản LAB\Administrator. Giải mã Base64 theo UTF-16LE cho thấy biểu thức dựng iex và lệnh Write-Host in lời chào. Chuỗi này đáng triage vì bị mã hóa và làm rối, nhưng nội dung đã giải mã không cung cấp bằng chứng mã độc. Tên tài khoản trong log cũng không xác định được người thực sự điều khiển phiên.
Phiên đăng nhập Windows
Event 4624 loại 2 phản ánh phiên tương tác, không xác nhận chủ tài khoản trực tiếp thao tác. Một cặp 4624 và 4634 loại 3 của tài khoản máy DC01$ có cùng Logon ID 0x2CA25F; RecordNumber liên tiếp 22733 và 22734 chỉ xác định thứ tự sự kiện, không đo được thời lượng phiên chính xác.
NTFS Alternate Data Stream (ADS)
Lúc 23:00:38.559 ngày 21/11, hai Sysmon Event 15 cùng ProcessGuid ghi nhận tệp chính và luồng NTFS_ADS.txt:streamCommand, với Contents là Write-Host "Stream Data Executed". Đây là bằng chứng chuỗi đã được lưu trong ADS tại thời điểm log — không phải bằng chứng chuỗi đã được thực thi.
Kiểm tra sau đó cho Test-Path False tại đường dẫn tệp. Trong 7 ngày, Splunk không có Event 23/26 trên toàn DC01, và cấu hình Sysmon hiện tại có FileCreateStreamHash nhưng không có FileDelete / FileDeleteDetected. Vì vậy chưa xác định được nguyên nhân tệp biến mất.
Dòng thời gian điều tra
Thời gian
Nguồn
Bằng chứng và giới hạn
21/11 21:27:59
Sysmon 1
explorer.exe → powershell.exe; chưa xác định người trực tiếp thao tác
21/11 22:18:40
Sysmon 1
powershell.exe → cmd.exe → powershell.exe -e Base64; giải mã ra lời chào
21/11 22:50–23:22
Sysmon 1
Lệnh Add-Content và Remove-Item với NTFS_ADS.txt; dòng lệnh không xác nhận kết quả thao tác
21/11 23:00:38.559
Sysmon 15
ADS streamCommand được ghi nhận; Contents chứa Write-Host, chưa xác minh thực thi
22/11 22:16:56.519
Security 4624/4634
Logon ID 0x2CA25F, RecordNumber 22733/22734; không đo chính xác độ dài phiên
Các mốc lấy từ những truy vấn khác nhau. PowerShell mã hóa, ADS và phiên đăng nhập trên DC01 chưa được chứng minh là một chuỗi hành động liên tục hay do cùng một tác nhân.
Detection bằng SPL
PowerShell mã hóa (EncodedCommand)
index=lab host=DC01 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\*powershell.exe" (CommandLine="* -e \*" OR CommandLine="* -enc \*" OR CommandLine="* -EncodedCommand *")
Kết quả trong Last 7 days: 1 event — PowerShell do cmd.exe mở dưới LAB\Administrator. Phân loại: cảnh báo cần điều tra, chưa phải mã độc được xác nhận. Một mẫu duy nhất không đủ để tính tỷ lệ báo động nhầm hay đặt ngoại lệ cho tài khoản, tiến trình cha hay payload cụ thể.
Tìm sự kiện ADS
index=lab host=DC01 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 "NTFS_ADS.txt"
Tìm sự kiện xóa tệp
index=lab host=DC01 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=23 OR EventCode=26)
Kết luận
Event 15 chứng minh luồng ADS streamCommand đã được tạo và trường Contents ghi lại chuỗi Write-Host tại thời điểm đó. Chưa có bằng chứng từ các log đã xem rằng chuỗi ấy được đọc rồi thực thi, và việc tệp không còn được tìm thấy về sau cũng chưa xác định được nguyên nhân xóa.
Giới hạn và hướng cải tiến
Bật thêm FileDelete và FileDeleteDetected trong cấu hình Sysmon để điều tra được trọn vòng đời tệp ở các lần thực hành sau.
Chạy các bài test Atomic Red Team bằng Invoke-AtomicTest và đối chiếu từng kỹ thuật với log Sysmon trong Splunk.
Mở rộng detection: thu thập thêm mẫu trước khi tính tỷ lệ báo động nhầm hoặc đặt ngoại lệ.
Tài liệu tham khảo
Microsoft Sysmon — tài liệu các loại sự kiện Sysmon
Microsoft Windows Security Event 4624 — tài liệu sự kiện đăng nhập
Microsoft PowerShell FileSystem Provider — tài liệu về luồng dữ liệu (stream) trong PowerShell
