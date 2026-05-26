import hashlib
from pwn import *

p = 2**49 * 3**36 - 1
Fp = GF(p)
R_poly.<x> = PolynomialRing(Fp)
K.<i> = GF(p**2, modulus=x**2 + 1)

# =========================================================================
# 2. CÁC HÀM BỔ TRỢ TOÁN HỌC & MÔ PHỎNG XUÔI DÒNG
# =========================================================================
def deterministic_sqrt(val):
    return min(val.sqrt(all=True))

def next_curve_test(A, alpha, b):
    """Mô phỏng 1 bước đi xuôi để làm bộ lọc cho bước đi lùi"""
    xi = alpha**2
    zeta = 3 * xi + A
    eta = deterministic_sqrt(zeta)
    lambda0 = alpha + 2 * eta
    lambda1 = alpha - 2 * eta
    if b:
        return max(lambda0, lambda1)
    else:
        return min(lambda0, lambda1)

def data_to_bits(data):
    """
    [!] CẢNH BÁO: Phải khớp 100% với hàm của Server.
    Đang giả định chuỗi 64 ký tự Hex được đổi thành 512 bits 
    (mỗi ký tự -> 8 bits theo mã ASCII).
    """
    return [int(b) for c in data for b in format(ord(c), '08b')]

# =========================================================================
# 3. HÀM TÍNH TOÁN GIẬT LÙI (BACKTRACKING)
# =========================================================================
def prev_curve(A_new, alpha_new, b):
    R_K.<z> = PolynomialRing(K)
    
    f = 4*(z**2) - 2*alpha_new*z + (alpha_new**2 + A_new)
    
    candidates = [root[0] for root in f.roots()]
    
    for alpha_old_cand in candidates:
        A_old_cand = (-A_new - 15 * (alpha_old_cand**2)) / 4
        try:
            alpha_new_test = next_curve_test(A_old_cand, alpha_old_cand, b)
            if alpha_new_test == alpha_new:
                return A_old_cand, alpha_old_cand
        except ValueError:
            continue
            
    return None, None

def get_parts(val):
    """Tách phần thực (a_0) và ảo (a_1) từ số phức K(a*i + b)"""
    coeffs = val.polynomial().list()
    part0 = int(coeffs[0]) if len(coeffs) > 0 else 0
    part1 = int(coeffs[1]) if len(coeffs) > 1 else 0
    return part0, part1

# =========================================================================
# 4. KỊCH BẢN TẤN CÔNG (EXPLOIT)
# =========================================================================
def main():
    # Chọn hòn đảo đích j = 1728
    credential = hashlib.sha256(b"1728").hexdigest()
    bits = data_to_bits(credential)
    
    # Bước 511: Xác định điểm tựa để đi lùi tại Đích
    A_511 = K(11/16)
    alpha_511_sq = K(-1/4)
    alpha_511_candidates = alpha_511_sq.sqrt(all=True) # Có 2 nhánh

    found = False
    E0_final, A0_final, B0_final = None, None, None

    # Thử lần lượt 2 nghiệm của a511
    for i, alpha_511 in enumerate(alpha_511_candidates):
        print(f"\n[*] Đang thử Nhánh {i+1} (alpha_511 = {alpha_511})")
        
        A_curr = A_511
        alpha_curr = alpha_511
        valid_path = True
        
        # Đi lùi từ bit cuối cùng về bit 1 (bỏ qua bit[0] của select0)
        for idx, b in enumerate(reversed(bits[1:])):
            A_curr, alpha_curr = prev_curve(A_curr, alpha_curr, b)
            if A_curr is None:
                valid_path = False
                print(f"[-] Nhánh {i+1} bị gãy giữa đường (sau {idx} bước lùi)!")
                break
                
        if not valid_path:
            continue
            
        print(f"[+] Nhánh {i+1} đã về tới vạch xuất phát an toàn!")
        A0 = A_curr
        alpha0 = alpha_curr
        
        # Tính B0 từ A0 và alpha0
        B0 = -(alpha0**3) - A0*alpha0
        E0 = EllipticCurve(K, [A0, B0])
        
        # Kiểm tra bước select0 (Validate)
        torsion_points = sorted([root[0] for root in E0.torsion_polynomial(2).roots(multiplicities=False)])
        b0 = bits[0]
        alpha_test = torsion_points[-1] if b0 == 1 else torsion_points[1]
        
        if alpha_test == alpha0:
            print("[+] TUYỆT VỜI! E0 thỏa mãn hàm select0. Đã tìm ra Payload chuẩn!")
            A0_final, B0_final = A0, B0
            found = True
            break
        else:
            print("[-] Cảnh báo: Lệch vị trí chọn nghiệm ở select0. Thử nhánh tiếp theo...")

    if not found:
        print("Not found E0") 
        return

    # =========================================================================
    # 5. GỬI PAYLOAD LÊN SERVER QUA PWNTOOLS
    # =========================================================================
    print("\n[*] Chuẩn bị kết nối và Gửi Payload...")
    
    a4_0, a4_1 = get_parts(A0_final)
    a6_0, a6_1 = get_parts(B0_final)
    
    # Kết nối localhost:1337
    r = remote('127.0.0.1', 1337)
    
    # Nộp Credential (nếu server đòi credential trước, sửa thứ tự tùy theo prompt)
    # Ví dụ prompt server là: "credential > "
    # Lưu ý: Cần chỉnh các b"..." bên dưới cho khớp với chuỗi Server in ra
    r.sendlineafter(b"> ", credential.encode()) 
    
    r.sendlineafter(b"> ", str(a4_0).encode())
    r.sendlineafter(b"> ", str(a4_1).encode())
    r.sendlineafter(b"> ", str(a6_0).encode())
    r.sendlineafter(b"> ", str(a6_1).encode())
    
    print("[*] Đã nộp xong! Chờ nhận Flag...")
    r.interactive()

if __name__ == "__main__":
    main()