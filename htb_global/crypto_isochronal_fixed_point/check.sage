from sage.all import GF, EllipticCurve
import hashlib
import random

# --- Khởi tạo trường nền siêu dị kỳ ---
p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()

# Khởi tạo đa thức ẩn y phục vụ giải phương trình bậc 2 đi lùi
P_y = K['y']
y = P_y.gen()

def deterministic_sqrt(val):
    return min(val.sqrt(all=True))

def select0(E0, b0):
    torsion_points = sorted(E0.torsion_polynomial(2).roots(multiplicities=False))
    if b0:
        return torsion_points[-1], torsion_points[1]
    else:
        return torsion_points[1], torsion_points[-1]

def select(lambda0, lambda1, b):
    if b:
        return max(lambda0, lambda1)
    else:
        return min(lambda0, lambda1)

def next_curve(A, alpha, b):
    xi = alpha**2
    zeta = 3 * xi + A
    eta = deterministic_sqrt(zeta)
    new_A = -(4 * A + 15 * xi)
    lambda0 = alpha + 2 * eta
    lambda1 = alpha - 2 * eta
    new_alpha = select(lambda0, lambda1, b)
    return new_A, new_alpha

def data_to_bits(data):
    bits = [int(b) for c in data.encode() for b in "{:08b}".format(c)]
    assert bits and all(b in (0, 1) for b in bits)
    return bits

# --- Thuật toán Backtrack đếm toàn bộ cấu trúc gốc E0 ---
def backtrack_all(A_curr, alpha_curr, bit_idx, bits, stats):
    # Khi về tới bit đầu tiên (bit_idx == 0)
    if bit_idx == 0:
        B0 = -alpha_curr**3 - A_curr * alpha_curr
        E0 = EllipticCurve(K, [A_curr, B0])
        
        alpha_test, _ = select0(E0, bits[0])
        if alpha_test == alpha_curr:
            stats['count'] += 1  # Ghi nhận thêm 1 gốc E0 hợp lệ
            return [E0]
        return []

    # Hiển thị tiến trình log ở các tầng sâu
    depth = (len(bits) - 1) - bit_idx
    if depth % 100 == 0 and depth > 0:
        print(f"    [..] Đang quét nhánh ở độ sâu: {depth}/{len(bits)} bits...")

    b = bits[bit_idx]
    
    # Phương trình bậc 2 tìm alpha_old: 4*y^2 - 2*alpha_curr*y + (alpha_curr^2 + A_curr) = 0
    eq = 4*(y**2) - 2*alpha_curr*y + (alpha_curr**2 + A_curr)
    candidates = eq.roots(multiplicities=False)
    
    found_E0s = []
    
    for alpha_old_cand in candidates:
        A_old_cand = (-A_curr - 15 * (alpha_old_cand**2)) / 4
        try:
            t_A, t_alpha = next_curve(A_old_cand, alpha_old_cand, b)
            if t_A == A_curr and t_alpha == alpha_curr:
                # Gom toàn bộ kết quả từ các nhánh con thay vì return sớm
                branch_results = backtrack_all(A_old_cand, alpha_old_cand, bit_idx - 1, bits, stats)
                found_E0s.extend(branch_results)
                    
        except ValueError:
            continue
            
    return found_E0s


def run_survey():
    attempts = 0
    print("[*] Khởi động chương trình khảo sát cấu trúc đồ thị CGL...")
    
    while True:
        attempts += 1
        print(f"\n[*] Lần thử thứ {attempts}: Đang sinh 1 điểm đích ngẫu nhiên...")
        
        # Đi ngẫu nhiên 30 bước để tạo một đường cong đích siêu dị kỳ ngẫu nhiên
        A = K(1)
        E = EllipticCurve(K, [A, 0])
        alpha, _ = select0(E, 0)
        for _ in range(30):
            b = random.choice([0, 1])
            A, alpha = next_curve(A, alpha, b)
           
        xi = alpha**2
        target_A = -(4 * A + 15 * xi)
        target_B = -alpha * (8 * A + 22 * xi)
        E_final = EllipticCurve(K, [target_A, target_B])

        # Giả lập chuỗi Credential Quine dài 528 bits cho bài Revenge
        j_inv = str(E_final.j_invariant()).encode()
        hsh = hashlib.sha256(j_inv).hexdigest()
        payload = f"'{hsh}'"
        bits = data_to_bits(payload)
        
        # Tìm các ứng viên alpha_527 từ phương trình đuôi curve đích
        eq_tail = 8*y**3 + 2*target_A*y - target_B
        roots_alpha_target = eq_tail.roots(multiplicities=False)
        
        all_valid_E0s = []
        stats = {'count': 0} # Khởi tạo dictionary đếm toàn cục cho lần thử này
        
        for alpha_target in roots_alpha_target:
            A_target = (-target_A - 15*alpha_target**2)/4
            
            # 528 bits tương ứng index cuối cùng chạy từ 527 về 0
            results = backtrack_all(A_target, alpha_target, len(bits) - 1, bits, stats)
            all_valid_E0s.extend(results)
            
        if len(all_valid_E0s) > 0:
            print("-" * 60)
            print(f"[+] THÀNH CÔNG TÌM ĐƯỢC ĐƯỜNG ĐI SAU {attempts} LẦN THỬ ĐÍCH!")
            print(f"[+] Đã bẻ gãy chuỗi bit Quine độ dài: {len(bits)} bits.")
            print(f"[+] TỔNG SỐ ĐƯỜNG CONG E0 ĐƯỢC PHÁT HIỆN: {stats['count']}")
            print("-" * 60)
            
            # In thử thông số đường cong E0 đầu tiên tìm được
            E0 = all_valid_E0s[0]
            print(f"Ví dụ E0 Tìm Được:")
            print(f" -> a4: {E0.a4()}")
            print(f" -> a6: {E0.a6()}")
            break
        else:
            print(f" [!] Đích này bị cụt nhánh giữa đường. Thử lại...")

# Chạy khảo sát
if __name__ == "__main__":
    run_survey()