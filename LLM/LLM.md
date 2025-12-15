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

Đặt break point vào lệnh cmp trước lệnh jne, ta thấy chương trình so sánh rax với qword ptr ss: [rsp + 48]:

<img width="1583" height="502" alt="image" src="https://github.com/user-attachments/assets/ea362fe0-c88f-4614-9e95-456fd11629ee" />

Follow địa chỉ [rsp + 48] trong memory dump: 

<img width="518" height="169" alt="image" src="https://github.com/user-attachments/assets/b8c51db1-3518-4ec7-a3cc-bf4a4c0d55af" />

Dễ dàng thấy rax = D427202CB4B2 và giá trị đã tính toán được lưu vào [rsp + 48] = D42723958A82 (little edian). Em thấy 2 bytes đầu trùng nhau nên suy đoán khả năng số 37 là đúng. Lặp lại các bước trên với key0 = 37 thì đều thấy 2 bytes đầu đều là D427.

Khả năng cao các số mình nhập vào là hệ số của của một đa thức f(x) với key0 là hệ số của số mũ cao nhất, key1 là hệ số của số mũ cao thứ 2 và và key2 là hệ số của số mũ thấp nhất. Để kiểm chứng uy nghĩ này em so sánh 2 giá trị của rax và [rsp + 48] là D427202CB4B2 < D42723958A82. 2 bytes tiếp theo của chuỗi được tính toán có vẻ đang lớn hơn của rax.

Nên có bước thử như sau khá giống với binary search:
- Chia số đã thử với 2 rồi lấy phần nguyên.
- Thử số đó vào chương trình nếu 2 bytes tiếp theo của chuỗi mình tính toán mà lớn hơn 2 bytes tiếp theo của rax thì lấy (số cũ - phần nguyên của số thử / 2), còn nếu nhỏ hơn (số cũ + phần nguyên của số thử / 2)
- Lặp lại các bước đến khi khoảng cần thử nhỏ hơn 10 thì thử lần lượt giá trị để tìm ra được kết quả là 2 bytes tiếp theo của [rsp + 48] trùng với 2 bytes tiếp theo của rax.

Sau khi làm các bước ở trên e tìm được ***key1*** cần tìm là ***35***

<img width="231" height="89" alt="image" src="https://github.com/user-attachments/assets/f61ec1d9-c21e-4a84-a077-6fc5eed9552a" />

<img width="516" height="138" alt="image" src="https://github.com/user-attachments/assets/ea9b0f93-9d33-40e4-b104-5733699d5819" />


Để tìm ***key3*** ý tưởng của e tương tự nhưng có dựa vào gợi ý của kết quả của gemini với 3 số là 37, 97, 3589 = 37x97. Nên số bắt đầu thử của e là 1295.

Thực hiện liên tục các bước tương tự ở đoạn tìm ***key1*** e tìm ra được số ***605***

<img width="235" height="92" alt="image" src="https://github.com/user-attachments/assets/0aeeec5f-c0af-46c5-aa65-49cff0b158ec" />

memory dump:

<img width="197" height="16" alt="image" src="https://github.com/user-attachments/assets/02c82a63-637d-481f-8d27-9eb266225820" />

rax:

<img width="129" height="19" alt="image" src="https://github.com/user-attachments/assets/b1bc52bf-2588-4c5f-8276-1e03a451c7d1" />

Ta đặt thêm break point ở trước hàm in flag rồi F8 đến khi flag hiện ra

Flag: KCSC{You_have_passed_the_DSA_final_exam!!!}
