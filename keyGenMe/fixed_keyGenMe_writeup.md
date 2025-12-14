<img width="801" height="435" alt="image" src="https://github.com/user-attachments/assets/eb9fb5b8-0707-4b27-a85e-93d8f799f3ae" /><img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/8df8d905-840d-418f-919b-9fa7c29f650d" />

# Mở chương trình để test chức năng

<img width="637" height="376" alt="image" src="https://github.com/user-attachments/assets/1c11c889-9e7f-43da-9de3-64819d246d70" />

Chương bắt mình nhập vào user và serial key để đăng nhập

Mình thử cố tình nhập sai thì nó hiện lên một cái message box thông báo Activation Failed!

<img width="817" height="486" alt="image" src="https://github.com/user-attachments/assets/85010294-85ad-469b-9f53-436b8165e090" />

Còn nếu không nhập gì nó hiện ra message box yêu cầu mình nhập đủ trường thông tin

<img width="621" height="353" alt="image" src="https://github.com/user-attachments/assets/ad36724c-8911-43bf-aa5a-83c8721f81db" />

Mình có thử vứt program vào ghidra để patch nhảy đến chỗ thành công luôn thì hiện ra Activation Success! nhưng không hiện flag. Các anh giấu kĩ quá :P

<img width="801" height="435" alt="image" src="https://github.com/user-attachments/assets/8f5d76f8-c0dd-4368-bd2b-2858f068902d" />

Từ các lần test trên mình đã rút ra vài được hoạt động chính của chương trình:

- Nhập tên người dùng và serial key, nếu sai thì hiện ra một cửa số Activation Failed! Còn nếu đúng thì hiện ra Cửa số Activation Success! kèm flag.
- Không thể patch được => chương trình đã sử dụng user và serial key để có thể giải mã flag.
- Đây là một bài keygen với serial key được xào nấu từ user name đúng.

# Static Analysis

