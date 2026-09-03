from sage.all import *
from pwn import *
import hashlib
import random

p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()

P_y = K['y']
y = P_y.gen()#old_alpha variable 

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


def backtrack(A_curr, alpha_curr, bit_idx, bits):
    if bit_idx == 0:
        B0 = -alpha_curr**3 - A_curr * alpha_curr
        E0 = EllipticCurve(K, [A_curr, B0])
        
        alpha_test, _ = select0(E0, bits[0])
        if alpha_test == alpha_curr:
            return E0
        return None

    depth = 511 - bit_idx
    if depth % 50 == 0:
        log.info(f"Depth : {depth}/511...")

    b = bits[bit_idx]
    
    # PT bậc 2: 4*y^2 - 2*alpha_curr*y + (alpha_curr^2 + A_curr) = 0
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



def solve():
    attempts = 0
    while True:
        attempts += 1
        print(f"\n[*] Lần thử thứ {attempts}: đang đi đến 1 đích ngẫu nhiên")
        
        # Tạo điểm đích ngẫu nhiên
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

        
        # Tính credential và bits từ cái đích này
        j_inv = str(E_final.j_invariant()).encode()
        credential = hashlib.sha256(j_inv).hexdigest()
        bits = data_to_bits(credential)
        
        #Tính A511 , alpha511 
        eq_tail = 8*y**3 + 2*target_A*y - target_B
        # Bỏ [root[0] for root in...] đi
        roots_alpha_511 = eq_tail.roots(multiplicities=False)
        
        for alpha_511 in roots_alpha_511:
            A_511 = (-target_A - 15*alpha_511**2)/4
            
            E0 = backtrack(A_511, alpha_511, 511, bits)
            if E0 is not None:
                log.success(f"tìm thấy gốc E0 sau {attempts} lần thử.")
                return E0, credential


def main():
    E0, credential = solve()
    io = remote("localhost", 1337)

    def get_parts(val):
        coeffs = val.polynomial().list()
        part0 = int(coeffs[0]) if len(coeffs) > 0 else 0
        part1 = int(coeffs[1]) if len(coeffs) > 1 else 0
        return part0, part1

    a4_0, a4_1 = get_parts(E0.a4())
    a6_0, a6_1 = get_parts(E0.a6())
    
    io.sendlineafter(b"a4.0 > ", str(a4_0).encode())
    io.sendlineafter(b"a4.1 > ", str(a4_1).encode())
    io.sendlineafter(b"a6.0 > ", str(a6_0).encode())
    io.sendlineafter(b"a6.1 > ", str(a6_1).encode())
    
    io.sendlineafter(b"data > ", credential.encode())
    io.interactive()

if __name__ == "__main__":
    main()