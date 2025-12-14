
<img width="400" height="600" alt="image" src="https://github.com/user-attachments/assets/fe0703dd-8f45-48fd-936e-27458f31af5f" />

Cái hidden message chỉ cần dùng cyberchef fromhex để có được chuỗi base64. sau đó decode base64 nhiều lần chúng ta sẽ có được thông điệp flag{thuuuuuuuuuuuuwwwwwwww vuuuuuuuuuuuu phuuuuuuuuuuuu chuuuuuuuuuuaaaaaaaa???????}

Gợi ý bài này có liên quan đến base64 hoặc base gì đó mà chúng ta sẽ khám phá ở phía dưới

# Mở thử phần mềm và xem qua phần mềm làm gì

Challenge đã có fix nên chúng ta sẽ tải file ***fixed_Just_EzReversing.exe***

<img width="600" height="400" alt="image" src="https://github.com/user-attachments/assets/c46b91d8-9fd2-41fb-a570-5ea8373e91ae" />

Chương trình yêu cầu chúng ta nhập vào flag(có kiểm tra độ dài) và in ra kết quả xem chuỗi flag chúng ta nhập vào có đúng không.

# Static analyst

Ở đây mình dùng ghidra để có psuedocde từ file .exe

<img width="1596" height="851" alt="image" src="https://github.com/user-attachments/assets/958c7565-002c-470e-a324-357795deb747" />

Vào phần Defined Strings xong gõ vào ô filter chữ Flag. Ghidra sẽ cho ta biết chuỗi ***Enter the flag:*** ở đâu để chúng ta có thể đến được code của chương trình

<img width="1267" height="613" alt="image" src="https://github.com/user-attachments/assets/526dc276-fa23-479f-a98b-d4caae261eed" />

Chúng ta có thể thấy chuỗi "Enter the flag: " được gọi bởi hàm ***FUN_140002934***. Click đúp vô đó chúng ta sẽ tới được hàm chạy cần tìm. Ta có thể coi nó là hàm main cũng được vì nó thực hiện các logic chính của chương trình

Psuedo code của chương trình
```c

undefined8
FUN_140002934(undefined8 param_1,undefined8 param_2,undefined8 param_3,ULONG_PTR *param_4)

{
  int iVar1;
  FILE *_File;
  size_t sVar2;
  char *_Str;
  longlong lVar3;
  undefined *puVar4;
  undefined8 uVar5;
  double dVar6;
  int local_2c;
  
  FUN_14000e1f7();
  FUN_140018900("%s",2.6525493942246e-314,param_3,param_4);
  _File = (FILE *)__acrt_iob_func(0);
  fgets(&DAT_1400260a0,100,_File);
  sVar2 = strcspn(&DAT_1400260a0,"\n");
  (&DAT_1400260a0)[sVar2] = 0;
  sVar2 = strlen(&DAT_1400260a0);
  dVar6 = (double)FUN_140019f60(6,2);
  if ((double)sVar2 == dVar6) {
    sVar2 = strlen(&DAT_1400260a0);
    _Str = (char *)FUN_1400027a8(0x1400260a0,sVar2,1,param_4);
    for (local_2c = 0; sVar2 = strlen(_Str), (ulonglong)(longlong)local_2c < sVar2;
        local_2c = local_2c + 2) {
      strncpy(&DAT_140026104,_Str + local_2c,2);
      FUN_140002753(&DAT_140026104,0x140026120);
      uVar5 = DAT_140026128;
      lVar3 = (longlong)DAT_1400263a0;
      *(undefined8 *)(&DAT_1400261a0 + lVar3) = DAT_140026120;
      *(undefined8 *)(&DAT_1400261a8 + lVar3) = uVar5;
      DAT_1400263a0 = DAT_1400263a0 + 0x10;
    }
    uVar5 = 0x200;
    puVar4 = &DAT_14001b040;
    iVar1 = memcmp(&DAT_1400261a0,&DAT_14001b040,0x200);
    if (iVar1 == 0) {
      FUN_140018900("Correct!\n",(double)puVar4,uVar5,param_4);
      uVar5 = 1;
    }
    else {
      FUN_140018900("Incorrect!\n",(double)puVar4,uVar5,param_4);
      uVar5 = 0;
    }
  }
  else {
    FUN_140018900("Incorrect length!\n",0.0,_File,param_4);
    uVar5 = 0;
  }
  return uVar5;
}

```

## Phân tích flow của chương trình

Do có %s kèm địa chỉ chuỗi "Enter the flag: " nên chúng ta biết được ***FUN_140018900*** là hàm printf(). ***DAT_1400260a0*** là vùng data lưu giá trị chuỗi của người dùng nhập vào. Sau đó thông qua hàm strcspn và hàm strlen tính toán độ dài rồi lưu độ dài của chuỗi vừa nhập vào biến sVar2. Hàm ***FUN_140019f60*** có 2 tham số vào là 6 và 2, click vô đó ta thấy được hàm pow(), sau đó gán kết quả vào biến dVar6

Câu lệnh điều kiện kiểm tra sVar2 có bằng dVar6 hay không? Nếu đúng thì thực hiện khối lệnh bên trong. Nếu không thì sẽ in ra chuỗi ***"Incorrect length!\n"*** rồi return. Suy ra chuỗi người dùng nhập vào phải có đủ 6^2 = 36 kí tự.

Phân tích khối lệnh bên trong ta thấy biến _str được gán cho con trỏ kiểu char là giá trị trả về của hàm ***FUN_1400027a8*** với 3 tham số lần lượt là: địa chỉ của vùng data chứa chuỗi người dùng nhập, sVar2 = 36, param4. Mình đoán đây là một hàm mã hóa gì đó với đầu vào là chuỗi người dùng nhập vào và trả về kết quả là chuỗi được mã hóa gán vào biến _str. Click đúp vô hàm để xem mã giả của nó:

```c

longlong FUN_1400027a8(longlong param_1,ulonglong param_2,undefined8 param_3,ULONG_PTR *param_4)

{
  undefined1 auVar1 [16];
  undefined1 auVar2 [16];
  longlong lVar3;
  undefined8 uVar4;
  ulonglong local_28;
  int local_20;
  uint local_1c;
  ulonglong local_18;
  ulonglong local_10;
  
  auVar1._8_8_ = 0;
  auVar1._0_8_ = param_2 + 4;
  uVar4 = SUB168(auVar1 * ZEXT816(0xcccccccccccccccd),8);
  local_10 = (param_2 + 4) / 5 << 3;
  if ((char)param_3 != '\x01') {
    local_10 = param_2 * 8 + 4;
    auVar2._8_8_ = 0;
    auVar2._0_8_ = local_10;
    uVar4 = SUB168(auVar2 * ZEXT816(0xcccccccccccccccd),8);
    local_10 = local_10 / 5;
  }
  lVar3 = thunk_FUN_140019fd0(local_10 + 1,uVar4,param_3,param_4);
  local_18 = 0;
  local_1c = 0;
  local_20 = 0;
  for (local_28 = 0; local_28 < param_2; local_28 = local_28 + 1) {
    local_1c = (uint)*(byte *)(local_28 + param_1) | local_1c << 8;
    for (local_20 = local_20 + 8; 4 < local_20; local_20 = local_20 + -5) {
      *(char *)(local_18 + lVar3) =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[local_1c >> ((char)local_20 - 5U & 0x1f) & 0x1f];
      local_18 = local_18 + 1;
    }
  }
  if (0 < local_20) {
    *(char *)(local_18 + lVar3) =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[local_1c << (5U - (char)local_20 & 0x1f) & 0x1f];
    local_18 = local_18 + 1;
  }
  if ((char)param_3 != '\0') {
    while ((local_18 & 7) != 0) {
      *(undefined1 *)(local_18 + lVar3) = 0x3d;
      local_18 = local_18 + 1;
    }
  }
  *(undefined1 *)(local_18 + lVar3) = 0;
  return lVar3;
}

```

Thông qua chuỗi đáng ngờ "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" và hidden message của đề bài thì mình nghĩ nó có liên quan đến mã hóa base64. Mình có vứt qua cho AI xem mã giả thì biết được đây là hàm mã hóa base32.

Quay lại hàm ***FUN_140002934***, sau khi mã hóa chuỗi cần tìm ta bắt gặp một vòng lặp for chạy từ 0 đến strlen(_str) và bước là 2 đơn vị. Sau vòng for ta bắt gặp một hàm ***memcmp*** so sánh 0x200 = 512 bytes của 2 địa chỉ ***DAT_1400261a0*** và ***DAT_14001b040***. Nếu giống nhau thì trả về giá trị 0 gán vào iVar1. Nếu iVar1 == 0 thì chạy hàm ***FUN_140018900*** để in ra chuỗi "Correct!\n", Nêu iVar1 khác 0 thì in ra chuỗi "Incorrect!\n"

Mình có check thử 2 địa chỉ ***DAT_1400261a0*** và ***DAT_14001b040*** thì thấy ***DAT_14001b040*** trỏ tới vùng data chứa 512 bytes đáng ngờ và ***DAT_1400261a0*** là vùng data sẽ được can thiệp và thay đổi giá trị trong vòng lặp for ở bên trên. Nêu chúng ta sẽ đi sâu vào vòng lặp for này.

```c
    for (local_2c = 0; sVar2 = strlen(_Str), (ulonglong)(longlong)local_2c < sVar2;
        local_2c = local_2c + 2) {
      strncpy(&DAT_140026104,_Str + local_2c,2);
      FUN_140002753(&DAT_140026104,0x140026120);
      uVar5 = DAT_140026128;
      lVar3 = (longlong)DAT_1400263a0;
      *(undefined8 *)(&DAT_1400261a0 + lVar3) = DAT_140026120;
      *(undefined8 *)(&DAT_1400261a8 + lVar3) = uVar5;
      DAT_1400263a0 = DAT_1400263a0 + 0x10;
    }
```

Ta có thể dễ dàng thấy được vòng lặp chạy từ 0 đến strlen(_str) và bước nhảy là 2. Với mỗi lân lặp nó thực hiện những việc sau đây:

- copy 2 bytes của _str vào ***DAT_140026104***
- Gọi hàm ***FUN_140002753*** với 2 tham số ***&DAT_140026104*** và ***0x140026120***. Vô hàm ***FUN_140002753*** phân tích các dấu hiệu và nhờ AI diễn giải code và các dấu hiệu bên dưới thì ta biết được hàm ***FUN_140002753*** là hàm hash ***MD5*** với đầu vào là 2 byte từ ***DAT_140026104*** và đầu ra là địa chỉ ***0x140026120***
  
  hình 1:
  
  <img width="402" height="362" alt="image" src="https://github.com/user-attachments/assets/2587a22b-b510-410e-b0a4-c7201f851603" />

  hình 2:

  <img width="396" height="388" alt="image" src="https://github.com/user-attachments/assets/0d74cc08-0b3c-4c03-926f-d19982fdbeb4" />

- Do hàm MD5 trả về 16 bytes, nên khi lưu vào địa chỉ 0x140026120 sẽ bị phân thành 2 đoạn 8 bytes kề nhau như hình 1. Sau đó lưu từng đoạn 8 bytes đó vào 2 đoạn địa chỉ kề nhau là ***&DAT_1400261a0*** và ***&DAT_1400261a8*** như hình 2 với offset được cộng dồn vào iVar3 16 đơn vị thông qua dòng code:
  ```c
      *(undefined8 *)(&DAT_1400261a0 + lVar3) = DAT_140026120;
      *(undefined8 *)(&DAT_1400261a8 + lVar3) = uVar5;
      DAT_1400263a0 = DAT_1400263a0 + 0x10;
  ```

==> Từ những phân tích phía trên ta có thể đoán được rằng flag đã được mã hóa base32 sau rồi lấy tuần tự 2 bytes để cho vào hàm băm MD5. Chuỗi băm đó được lưu vào vùng data ***DAT_14001b040*** để so sánh với chuỗi người dùng nhập.

Để kiểm chứng, mình dùng format flag của cuộc thi là KCSC{...} để tạo flag giả là KCSC{aaaaaaaaaaaaaaaaaaa đủ 36 kí tự sau đó đưa vào base32 encode online. Lấy 2 bytes đầu của kết quả đưa vào hàm băm MD5 cuối cùng được chuỗi hex là ***d9b252866a25986fd8ec8a6c9bded275*** so sánh với từng bytes của ***DAT_14001b040*** thì thấy trúng khớp 16 bytes đầu tiên => Suy luận đúng

# Hướng khai thác

Điểm yếu của chương trình này nằm ở hàm băm MD5. Do chỉ băm có 2 bytes 1 lượt nên thời gian để tìm được 2 bytes đó thông qua bruteforce khá là nhanh. Ở đây mình dùng AI gen luôn script bruteforce đơn giản để tìm ra đoạn mã base32.

```python
import hashlib

cipher = b'\xd9\xb2\x52\x86\x6a\x25\x98\x6f\xd8\xec\x8a\x6c\x9b\xde\xd2\x75\xc7\x9b\xda\x0e\x66\xf0\x7b\xee\x66\x2a\x68\x40\xb9\x07\xbf\x39\x8d\x36\xb3\x61\xa4\x79\x44\x22\xc7\x06\x81\x58\x6a\x95\x73\x50\x18\x2b\xe0\xc5\xcd\xcd\x50\x72\xbb\x18\x64\xcd\xee\x4d\x3d\x6e\xac\xcb\x66\xf0\xec\xd8\x26\xaa\xc8\x90\x65\x99\x0e\x1d\xa9\x7f\x56\x9b\x3c\xed\x35\x55\xbf\xae\x63\xca\xdb\x65\x58\xa6\xfc\xbe\x33\xd2\xa0\x8e\xee\x4c\x17\x81\x19\x40\xfe\xfb\xc4\xe0\x97\x78\x6b\xa8\x9a\xb4\x18\x23\xaf\x9b\x65\xea\x5d\x23\x30\x31\xb9\xf8\xe4\xa5\x9d\xf8\xb9\x72\x06\x10\x9e\xb4\xb7\xf2\xfe\x52\x8a\x4d\xad\x44\xac\x8c\x02\x28\x5f\x6b\x91\x64\xa0\x84\x92\xa7\x8f\x92\x0a\x5b\x65\x72\x5f\x6a\x3b\xa9\x58\x21\xce\xc6\x1d\xbb\x46\xd3\x2f\xf2\xd4\x5e\x98\x3c\x58\xe9\x6c\x9b\xa3\x3d\x69\x72\x1c\xe8\x51\xf5\x81\x93\x77\x65\x89\x0f\x2a\x70\x6c\x77\xea\x8a\xf3\xcc\xa3\x6c\x71\xeb\x23\x9a\x02\x31\xba\x0c\x6e\x7a\x45\x90\xf0\x62\x42\xad\xc7\x77\xf3\xc2\xc9\x70\x05\x15\x0c\xb7\xb8\x61\x65\xb6\xc2\x3f\xa9\x99\x69\x25\xb6\x10\x71\x0d\x93\xe2\x8c\x59\xa3\xe2\xd5\xc4\x42\x58\xd5\x16\x59\xf9\x62\x79\xc4\x70\xce\x81\x85\xdc\x6e\x02\x9f\xbf\xa8\x17\xdf\xc4\x58\x59\x8a\x5d\x38\xa6\x75\x5f\x7c\x78\xeb\xb4\xc2\x23\xc9\x6f\x8e\x6c\xcc\x29\xf7\x3c\xc2\x8e\x76\xaa\x96\x36\x9a\xbb\xba\x52\xe6\x21\xbf\xa8\x3d\xa8\xe6\x4f\xba\x7d\x08\x34\xd2\x3b\x91\x50\x4b\xed\x68\x59\x01\xdc\x3a\xc5\x38\xf9\x9a\xbb\xc1\xd3\x39\xc2\x77\xc0\x66\x9e\x7b\xc3\x73\xc0\x0a\x5b\x65\x72\x5f\x6a\x3b\xa9\x58\x21\xce\xc6\x1d\xbb\x46\xd3\x85\x3b\xc5\x5c\x10\x41\xf2\x4b\x93\x92\x06\x93\x31\xe6\x53\x36\xf2\x14\xa7\xd4\x2e\x0d\xe5\x87\x5d\x55\x18\x9e\x01\xe2\xe1\x87\x7b\x7c\xd2\x4e\xa6\xf0\x8b\x71\x1c\xf4\x05\x3b\xea\xc4\x3c\xc5\x64\xf3\xbd\x17\x41\xab\x8d\x6b\xa5\x45\xa1\xae\x09\xbb\x87\x28\x8a\x6b\x17\x8d\x3a\xf0\xa5\xa9\xb2\x74\x4c\xa3\x19\x21\xd5\xe2\xbf\xd2\x34\x39\x10\x37\x8a\x1b\x53\x7c\x3c\x80\x36\xa5\xc0\x7e\x20\x63\x84\x97\x17\xd3\x2d\xd1\x9e\x53\x4b\x77\xca\xba\xc5\x17\x20\x63\x84\x97\x17\xd3\x2d\xd1\x9e\x53\x4b\x77\xca\xba\xc5\x17\x20\x63\x84\x97\x17\xd3\x2d\xd1\x9e\x53\x4b\x77\xca\xba\xc5\x17'

def brute_md5_2bytes(digest):
    for x in range(0x10000):
        data = x.to_bytes(2, 'little')  # đổi thành 'big' nếu cần
        if hashlib.md5(data).digest() == digest:
            return data
    return None

result = b''

for i in range(0, len(cipher), 16):
    block = cipher[i:i+16]
    plain = brute_md5_2bytes(block)
    if plain is None:
        print(f"[!] Fail at block {i//16}")
        break
    result += plain
    print(f"[+] Block {i//16}: {plain.hex()}")

print("\nRecovered bytes:", result)

```

RESULT = "JNBVGQ33GN5F6YTSOU3TGX3NMQ2V6NDOMRPWIM3DN5SDGX3CGRZTGMZSPU======"

FLAG = KCSC{3z_bru73_md5_4nd_d3cod3_b4s332}
