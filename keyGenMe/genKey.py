import sys

# 1. Username bắt buộc (đã fix cứng trong code shellcode)
username_str = "kmar3v3r5!n9"
username = [ord(c) for c in username_str] # Chuyển sang mảng số nguyên

# 2. Giá trị Hash khởi tạo (Initial Seed)
current_hash = 0x1337

# 3. Target Hash Table (Dữ liệu từ DAT_140016520)
# Mảng này chứa các giá trị 32-bit (DWORD) mong muốn sau mỗi vòng lặp
target_table = [
    0x1350, 0x13E9, 0x13FC, 0x1400, 0x1453, 0x1489, 0x14F7, 0x1529, 
    0x15A0, 0x15DF, 0x166D, 0x1677, 0x169B, 0x1733, 0x17B8, 0x1803, 
    0x1875, 0x1858, 0x188D, 0x18F3, 0x1905, 0x199D, 0x1A39, 0x1AC8, 
    0x1AC1, 0x1AB9, 0x1B23, 0x1B6E, 0x1B9A, 0x1C2F, 0x1CBB, 0x1D36, 
    0x1DA8, 0x1E02, 0x1EA2, 0x1EFF, 0x1F27, 0x1F90, 0x1FEC, 0x201E, 
    0x20D9, 0x20BB, 0x212D, 0x212E, 0x21A4, 0x2200, 0x228D, 0x2366, 
    0x239F
]

serial_key = []

print(f"[-] Username: {username_str}")
print("[-] Bruteforcing Serial Key characters...")

for i in range(len(target_table)):
    target_val = target_table[i]
    
    # Lấy ký tự A và B từ Username
    char_a = username[current_hash % 12]
    char_b = username[i % 12]
    
    found_char = None
    
    # --- BRUTE FORCE TỪNG KÝ TỰ ---
    # Thử tất cả các ký tự in được (ASCII 32 đến 126)
    # Để xem ký tự nào thỏa mãn công thức gốc
    for k in range(32, 127):
        # Công thức gốc trong C++:
        # NewHash = CharA + (CharB ^ KeyChar ^ OldHash)
        # Lưu ý: Phải dùng & 0xFFFFFFFF để giả lập tràn số 32-bit của C++
        
        xor_part = char_b ^ k ^ current_hash
        calculated_hash = (char_a + xor_part) & 0xFFFFFFFF
        
        if calculated_hash == target_val:
            found_char = chr(k)
            break
    
    if found_char:
        serial_key.append(found_char)
        # Cập nhật hash để tính ký tự tiếp theo
        current_hash = target_val
    else:
        # Trường hợp không tìm thấy ký tự in được (có thể là ký tự đặc biệt hoặc dữ liệu sai)
        print(f"[!] Khong tim thay ky tu in duoc tai index {i}. Target: {hex(target_val)}")
        # Cố gắng tìm bằng toán học đảo ngược thuần túy để debug
        # K = (Target - A) ^ B ^ Old
        term1 = (target_val - char_a) & 0xFFFFFFFF
        k_raw = term1 ^ char_b ^ current_hash
        k_byte = k_raw & 0xFF
        print(f"    -> Gia tri Hex tim duoc: {hex(k_byte)} (Ky tu: {repr(chr(k_byte))})")
        
        serial_key.append(chr(k_byte)) # Vẫn thêm vào để chạy tiếp
        current_hash = target_val

final_key = "".join(serial_key)
print("\n" + "="*50)
print(f"[+] COMPLETE KEY: {final_key}")
print("="*50)
