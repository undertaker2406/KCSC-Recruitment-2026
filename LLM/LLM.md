<img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/6c76dd26-551b-4cb4-b4f7-1b04a1708516" />

# Hoạt động của chương trình

<img width="1309" height="562" alt="image" src="https://github.com/user-attachments/assets/e09fa352-5c30-4e66-9cc2-fdd1ceef6946" />

Chương trình yêu cầu nhập vào 3 giá trị số bất kỳ (không thể nhập kí tự nhập vào là chương trình kết thúc ngay).

Khả năng nếu nhập đúng 3 số đúng thì chương trình sẽ in ra lag

# Câu này e dùng trick lỏ kết hợp AI Gemini và x64dbg để thử và suy đoán các trường hợp bằng cách nhìn vào các giá trị hex thanh ghi trước lệnh nhảy của chương trình. E xin lỗi về sự khôn lỏi của bản, mong các a đọc coi như cho vui cũng được :]]]]]

Đầu tiên e vẫn mở ghidra như bình thường, do psuedo code khá rối và e cũng khá lười nên e vứt cho AI đọc qua thì e biết được các thông tin như sau
- Đây là chương trình dùng linked list 2 chiều để mô phỏng một hàm đa thức f(x).
- E có mở hàm tạo linked list trên ghidra thì thấy hàm có 4 biến để chứa 4 giá trị, 2 giá trị để chứa địa chỉ đầu và địa chỉ đuôi của một node. 2 biến còn lại chắc chứa hệ số và số mũ của. 
- Các đối số mình nhập vào khả năng là các hằng số bên trong đa thức
- Thế là e đưa cho các vùng data cần thiết để AI ra được đáp án thì nó trả về 3 số: 37,97 và  3589 = 37x97 =)))

# Test và bruteforce đáp án

## Bước dò lệnh nhảy kết quả

<img width="714" height="489" alt="image" src="https://github.com/user-attachments/assets/a6dbaa66-1072-4946-8497-13c486fb4310" />

Hiển nhiên là AI không ra đáp án =.=, thế là e nghĩ ra một phương pháp đó là vứt vào trình debug để xem giá trị so sánh như thế nào

Mở x64dbg:

<img width="1917" height="1138" alt="image" src="https://github.com/user-attachments/assets/b13ca59f-268d-4c70-a31f-8127a8640d39" />

Continue liên tục cho đến khi chương trình dừng và trên cửa sổ console xuất hiện chuỗi "Enter key to get flag!". Sau đó đặt breakpoint ngay tại trước hàm in ra chuỗi để dừng chương trình

Sau đó chạy lại chương trình đến khi chương trình chạm breakpoint:

<img width="1067" height="340" alt="image" src="https://github.com/user-attachments/assets/8e02a141-3742-4a4a-aa99-c51d15b9ca2a" />

Sau đó mình sử dụng lệnh next instruction bằng cách nhấn nút F8 đến khi chương trình bắt mình nhập giá trị, làm liên tục cho đến khi nhập đủ giá trị 37,97, 5389

<img width="1165" height="396" alt="image" src="https://github.com/user-attachments/assets/5cac8c5e-156f-4f57-8fb5-ee6f7f9e5856" />

Sau khi nhập đủ 3 giá trị thì ta lại F8 và kéo xuống cho đến khi trên cửa sổ chương trình xuất hiện các chuỗi kết quả : "Correct!", "Wrong!" và "Flag: %s"

<img width="1001" height="546" alt="image" src="https://github.com/user-attachments/assets/6062acaf-ab49-4f2a-b466-d97e9a0aa648" />

## Bước brute force kết quả

Thử nhảy đến kết quả thì không ổn vì có vẻ các giá trị nhập vào để giải mã flag

<img width="753" height="135" alt="image" src="https://github.com/user-attachments/assets/f71f2e17-befc-472d-ada0-68168dbe14ea" />

Đặt break point vào lệnh cmp trước lệnh jne, ta thấy 



