from sage.all import GF, EllipticCurve
import hashlib
import random
from itertools import product

# --- Khởi tạo môi trường trường nền siêu dị kỳ ---
p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()

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
    # data ở đây là bytes
    bits = [int(b) for c in data for b in "{:08b}".format(c)]
    assert bits and all(b in (0, 1) for b in bits)
    return bits

def cgl_forward(E_start, bits):
    """Đi xuôi đồ thị để tìm đường cong đích."""
    A_curr = E_start.a4()
    alpha_curr, _ = select0(E_start, bits[0])
    for b in bits[1:]:
        A_curr, alpha_curr = next_curve(A_curr, alpha_curr, b)
    
    xi = alpha_curr**2
    new_A = -(4 * A_curr + 15 * xi)
    new_B = -alpha_curr * (8 * A_curr + 22 * xi)
    return EllipticCurve(K, [new_A, new_B])

def backtrack(A_curr, alpha_curr, bit_idx, bits):
    """Hàm đi lùi tìm gốc E0 (tối ưu hóa phương trình bậc 2)."""
    if bit_idx == 0:
        B0 = -alpha_curr**3 - A_curr * alpha_curr
        E0 = EllipticCurve(K, [A_curr, B0])
        alpha_test, _ = select0(E0, bits[0])
        if alpha_test == alpha_curr:
            return E0
        return None

    b = bits[bit_idx]
    eq = 4*(y**2) - 2*alpha_curr*y + (alpha_curr**2 + A_curr)
    candidates = eq.roots(multiplicities=False)
    
    for alpha_old_cand in candidates:
        A_old_cand = (-A_curr - 15 * (alpha_old_cand**2)) / 4
        try:
            t_A, t_alpha = next_curve(A_old_cand, alpha_old_cand, b)
            if t_A == A_curr and t_alpha == alpha_curr:
                result = backtrack(A_old_cand, alpha_old_cand, bit_idx - 1, bits)
                if result is not None:
                    return result
        except ValueError:
            continue
    return None

def find_bridge_bfs(E_forward, E_split, max_bytes=3):
    """
    BFS để tìm chuỗi đệm nối từ E_forward quay về E_split (tạo thành chu trình).
    """
    print(f"    [*] Đang chạy BFS tìm cầu nối độ dài {max_bytes} bytes...")
    target_A = E_split.a4()
    
    # Duyệt qua các tổ hợp byte đệm
    for pad_bytes in product(range(256), repeat=max_bytes):
        # Loại trừ \n và \r để không làm gãy cấu trúc comment của Python
        if 0x0a in pad_bytes or 0x0d in pad_bytes:
            continue
            
        pad_bits = data_to_bits(bytes(pad_bytes))
        
        try:
            E_test = cgl_forward(E_forward, pad_bits)
            if E_test.a4() == target_A:
                return bytes(pad_bytes)
        except Exception:
            continue
            
    return None

def exploit():
    attempts = 0
    while True:
        attempts += 1
        print(f"\n[+] Lần thử thứ {attempts}: Tìm E_split và E0...")
        
        # 1. Khởi tạo một điểm chốt E_split ngẫu nhiên
        A = K(1)
        E = EllipticCurve(K, [A, 0])
        alpha, _ = select0(E, 0)
        for _ in range(40):
            b = random.choice([0, 1])
            A, alpha = next_curve(A, alpha, b)
           
        xi = alpha**2
        E_split = EllipticCurve(K, [-(4 * A + 15 * xi), -alpha * (8 * A + 22 * xi)])
        
        # 2. Xây dựng Payload 1 (Quine) từ E_split
        j_inv = str(E_split.j_invariant()).encode()
        hsh = hashlib.sha256(j_inv).hexdigest()
        
        payload1 = f"'{hsh}'".encode('latin-1')
        bits1 = data_to_bits(payload1)
        
        # 3. Đi lùi để tìm E0
        target_A = E_split.a4()
        target_B = E_split.a6()
        eq_tail = 8*y**3 + 2*target_A*y - target_B
        roots_alpha_target = eq_tail.roots(multiplicities=False)
        
        E0 = None
        for alpha_target in roots_alpha_target:
            A_target = (-target_A - 15*alpha_target**2)/4
            E0 = backtrack(A_target, alpha_target, len(bits1) - 1, bits1)
            if E0 is not None:
                break
                
        if E0 is None:
            continue
            
        print(f"    [+] Đã tìm thấy gốc E0 thành công! Bắt đầu tạo chu trình RCE...")
        
        # 4. Xây dựng nhánh rẽ cho Payload 2
        # Cấu trúc: '<hash>' and print(...) # <bridge>
        # Vì python cho phép AND logic, đoạn lệnh print sẽ được thực thi
        suffix_rce = b" and print(open('flag.txt').read()) #"
        
        # Đi xuôi từ E_split qua đoạn mã độc để lấy điểm E_forward
        E_forward = cgl_forward(E_split, data_to_bits(suffix_rce))
        
        # 5. BFS để bẻ cong đường đi từ E_forward về lại E_split
        # Thực tế, việc tìm cycle độ dài 3 bytes (24 bits) đòi hỏi sự may mắn.
        # Nếu không tìm thấy, ta bỏ E_split này và thử lại từ đầu.
        bridge = find_bridge_bfs(E_forward, E_split, max_bytes=3)
        
        if bridge is not None:
            payload2 = payload1 + suffix_rce + bridge
            print("\n" + "="*60)
            print("[🏆] KHAI THÁC THÀNH CÔNG!")
            print(f"E0 a4: {E0.a4()}")
            print(f"E0 a6: {E0.a6()}")
            print(f"Payload 1 (Choice 1): {payload1.hex()}")
            print(f"Payload 2 (Choice 2): {payload2.hex()}")
            print("="*60)
            return E0, payload1, payload2

if __name__ == "__main__":
    exploit()