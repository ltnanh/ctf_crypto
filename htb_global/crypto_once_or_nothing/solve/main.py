#Just use AI to convert from main.rs to python , I'm not a rust developer:v 

import hashlib
import secrets

N = 256
TARGET_MSG = "d9_netadmin"

class AuthKey:
    def __init__(self):
        # Tạo 256 cặp số bí mật ngẫu nhiên (mỗi số 32 bytes / 256 bits)
        self.key_pairs = [
            (int.from_bytes(secrets.token_bytes(32), 'big'), 
             int.from_bytes(secrets.token_bytes(32), 'big'))
            for _ in range(N)
        ]

class AuthPub:
    def __init__(self, auth_key: AuthKey):
        # Tạo khóa công khai bằng cách băm SHA-256 từng số bí mật
        self.commitments = [
            (hash_digest(s0), hash_digest(s1))
            for (s0, s1) in auth_key.key_pairs
        ]


def hash_digest(number: int) -> bytes:
    """Chuyển số thành 32 bytes dữ liệu lớn (big-endian) rồi băm SHA-256"""
    block = number.to_bytes(32, byteorder='big')
    return hashlib.sha256(block).digest()


def to_bits(msg_bytes: bytes) -> list[bool]:
    """Chuyển mảng bytes thành một mảng gồm 256 bit Boolean (True/False)"""
    # Đệm thêm các byte 0 vào phía trước cho đủ 32 bytes (256 bits)
    padded = msg_bytes.rjust(32, b'\x00')
    # Lấy 32 bytes cuối cùng nếu chuỗi dài hơn 32 bytes
    padded = padded[-32:]
    
    bits = []
    for byte in padded:
        for i in range(7, -1, -1):
            bits.append(((byte >> i) & 1) == 1)
    return bits


def issue_token(msg_bytes: bytes, auth_key: AuthKey) -> list[int]:
    """Hàm ký tên: Chọn số bí mật dựa trên các bit của tin nhắn"""
    hash_bits = to_bits(msg_bytes)
    token = []
    for i in range(N):
        zero_key, one_key = auth_key.key_pairs[i]
        # Nếu bit là 1 chọn số bên phải (one_key), nếu là 0 chọn số bên trái (zero_key)
        if hash_bits[i]:
            token.append(one_key)
        else:
            token.append(zero_key)
    return token


def validate_token(msg_bytes: bytes, token: list[int], auth_pub: AuthPub) -> bool:
    """Hàm xác thực: Băm các số trong token rồi so sánh với khóa công khai"""
    hash_bits = to_bits(msg_bytes)
    
    for i in range(N):
        zero_pub, one_pub = auth_pub.commitments[i]
        # Lấy mã băm công khai mục tiêu dựa trên bit của tin nhắn
        expected_hash = one_pub if hash_bits[i] else zero_pub
        # Băm số trong token của người dùng gửi lên
        actual_hash = hash_digest(token[i])
        # Nếu sai bất kỳ vị trí nào, token không hợp lệ
        if actual_hash != expected_hash:
            return False
    return True


def main():
    # Khởi tạo hệ thống khóa
    auth_key = AuthKey()
    auth_pub = AuthPub(auth_key)
    
    print("--- D9 Authentication Gateway (Python Version) ---")
    print("Issuing access tokens for Korvia's infrastructure nodes. Use wisely.")
    
    while True:
        print("\n1. Issue authentication token")
        print("2. Validate authentication token")
        print("3. Abort session")
        choice = input("> ").strip()
        
        if choice == "1":
            hex_input = input("Enter credential payload in hex: ").strip()
            if not hex_input:
                continue
                
            try:
                msg_bytes = bytes.fromhex(hex_input)
            except ValueError:
                print("ERROR: Invalid hex input!")
                continue
                
            # Kiểm tra xem chuỗi nhập vào có chứa cụm từ bị cấm không
            if TARGET_MSG.encode() in msg_bytes:
                print("ERROR: [REJECTED] Target admin token is restricted.")
            else:
                token = issue_token(msg_bytes, auth_key)
                # In token dưới dạng danh sách các số Hex cho gọn
                token_hex = [hex(x) for x in token]
                print(f"Token issued: {token_hex}")
                
        elif choice == "2":
            msg = input("Enter admin message to validate: ").strip()
            sig_input = input("Enter token segments (comma-separated hex): ").strip()
            
            try:
                token_array = [int(s.strip(), 16) for s in sig_input.split(",") if s.strip()]
                if len(token_array) != N:
                    print(f"ERROR: Expected exactly 256 parts, got {len(token_array)}!")
                    continue
            except ValueError:
                print("ERROR: Invalid token format!")
                continue
                
            verified = validate_token(msg.encode(), token_array, auth_pub)
            if verified:
                if msg == TARGET_MSG:
                    # Giả lập đọc file flag.txt
                    try:
                        with open("flag.txt", "r") as f:
                            print(f.read().strip())
                    except FileNotFoundError:
                        print("HTB{f4ke_fl4g_f0r_t3st1ng}")
                else:
                    print("[AUTH GRANTED] Token validated. Access permitted.")
            else:
                print("ERROR: [AUTH FAILED] Invalid token. Intrusion logged.")
                
        elif choice == "3":
            print("Session terminated.")
            break
        else:
            print("Unknown option!")

if __name__ == "__main__":
    main()