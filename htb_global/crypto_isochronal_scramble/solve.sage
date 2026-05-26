from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from Crypto.Util.number import *
import os
os.environ["TERM"] = "xterm"
os.environ["PWNLIB_NOTERM"] = "1"
from factordb.factordb import FactorDB
from pwn import *


#!/usr/bin/env sage

from sage.all import *
from pwn import *
import random
from hashlib import sha256

# ================= MATH CỐT LÕI =================

p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()
P_y = K['y']
y_var = P_y.gen()

def deterministic_sqrt(val):
    return min(val.sqrt(all=True))

def select0(E0, b0):
    torsion_points = sorted(E0.torsion_polynomial(2).roots(multiplicities=False))
    if b0:
        return torsion_points[-1], torsion_points[1]
    else:
        return torsion_points[1], torsion_points[-1]

def select(lambda0, lambda1, b):
    if b: return max(lambda0, lambda1)
    else: return min(lambda0, lambda1)

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
    return bits

# Hàm tạo một đường cong supersingular ngẫu nhiên làm "Đích đến"
def get_random_target():
    # Bắt đầu từ đường cong supersingular mặc định (y^2 = x^3 + x)
    A = K(1)
    E = EllipticCurve(K, [A, 0])
    alpha, _ = select0(E, 0)
    
    # Đi bừa vài chục bước để giấu vết
    for _ in range(10):
        b = random.choice([0, 1])
        A, alpha = next_curve(A, alpha, b)
        
    xi = alpha**2
    new_A = -(4 * A + 15 * xi)
    new_B = -alpha * (8 * A + 22 * xi)
    return EllipticCurve(K, [new_A, new_B])

# Hàm đi lùi (backtrack) từ đích về E0
def backtrack(target_A, target_B, bits):
    # Tìm alpha của bước cuối cùng (giải pt bậc 3)
    # 8*alpha^3 + 2*target_A*alpha - target_B = 0
    roots_alpha = (8*y_var**3 + 2*target_A*y_var - target_B).roots(multiplicities=False)
    
    for alpha_last in roots_alpha:
        A_prev = (-target_A - 15*alpha_last**2)/4
        
        # Stack DFS lưu: (A_hiện_tại, alpha_hiện_tại, index_bit_vừa_dùng)
        stack = [(A_prev, alpha_last, len(bits)-1)]
        
        while stack:
            curr_A, curr_alpha, b_idx = stack.pop()
            
            if b_idx == 0:
                # Bú! Đã lùi về đến bước 0
                B0 = -curr_alpha**3 - curr_A * curr_alpha
                E0 = EllipticCurve(K, [curr_A, B0])
                # Double check bước 0
                if select0(E0, bits[0])[0] == curr_alpha:
                    return E0
                continue
            
            # bit dùng ở bước này là bits[b_idx]
            bit = bits[b_idx]
            
            # Giải PT bậc 2 đi lùi: y^2 + curr_alpha*y + (curr_alpha^2 + curr_A) = 0
            eq = y_var**2 + curr_alpha*y_var + (curr_alpha**2 + curr_A)
            for root_y in eq.roots(multiplicities=False):
                prev_alpha = (curr_alpha + root_y) / 2
                prev_A = (-curr_A - 15*prev_alpha**2) / 4
                
                # Check ngược lại bằng hàm forward xem có khớp bit không
                t_A, t_alpha = next_curve(prev_A, prev_alpha, bit)
                if t_A == curr_A and t_alpha == curr_alpha:
                    stack.append((prev_A, prev_alpha, b_idx - 1))
    return None

def solve():
    log.info("Đang đi lùi tìm E0... Đi đái 1 cái vào là có!")
    attempts = 0
    while True:
        attempts += 1
        print(attempts)
        E_final = get_random_target()
        j_inv = str(E_final.j_invariant()).encode()
        credential = sha256(j_inv).hexdigest()
        bits = data_to_bits(credential)
        
        # Bắt đầu đi lùi
        E0 = backtrack(E_final.a4(), E_final.a6(), bits)
        if E0:
            log.success(f"Ngon! Phá trinh thành công sau {attempts} lần thử.")
            return E0, credential


# ================= PWNTOOLS INTERACTION =================

def pwn_server():
    # Đổi cmn tên biến thành 'io' cho khỏi đụng chạm họ hàng nhà SageMath
    # io = process(['sage', 'b.sage'])
    io = remote('localhost',1337)
    
    # Nếu đánh giải thì comment dòng trên lại, xài dòng dưới:
    # io = remote('127.0.0.1', 1337)
    
    E0, credential = solve()

    # Tách hệ số và ép chết mẹ nó về kiểu int() của Python
    a4_0 = int(E0.a4()[0])
    a4_1 = int(E0.a4()[1])
    a6_0 = int(E0.a6()[0])
    a6_1 = int(E0.a6()[1])

    log.info("Đang đút parameters vào server...")
    io.sendlineafter(b"a4.0 > ", str(a4_0).encode())
    io.sendlineafter(b"a4.1 > ", str(a4_1).encode())
    io.sendlineafter(b"a6.0 > ", str(a6_0).encode())
    io.sendlineafter(b"a6.1 > ", str(a6_1).encode())

    io.sendlineafter(b"data > ", credential.encode())

    log.success("Đút vào thành công, húp cờ đi con zai!")
    io.interactive()

if __name__ == '__main__':
    pwn_server()

