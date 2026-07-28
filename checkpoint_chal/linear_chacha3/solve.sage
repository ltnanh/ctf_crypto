import time
import sys
import random as py_random  
from sage.all import *




#INPUT DATA  
IV1_HEX = "71736bbba6e0556da341a2ac"
IV2_HEX = "3de7b19e9c6ae9f39ecc8130"
CIPHERTEXT_FULL_HEX = "0e44a40c68080704a0400c200ca12a4808f604489ca14c483c0056c409010011a00058c008011c48412700110492498085028038131b106002660844308009200042871c8010a004205000202409204d08470400cc2808282c84666c0019061880404200282142002464101217803240a1026530731158008b408409658922a285468610281935098012082a20a1024e08d065401ca04908200476e4080a1a03a0804a404804560100450010019063c84102c630500b004100520e015580bb227a6ac07f136593b5df6c396c61e8f0186b5c157b643462803cfb6d195d4738767fb366df13923fbc17716d"
TARGET_KS_HEX = CIPHERTEXT_FULL_HEX[:192*2] 




#Utility functions to represent ks bit to linear equatitons 
def rotl_sym(w, n):
    return w[32-n:] + w[:32-n]

def xor_sym(w1, w2):
    return [a + b for a, b in zip(w1, w2)]

def qr_sym(x, a, b, c, d):
    x[a] = xor_sym(x[a], x[b]); x[d] = xor_sym(x[d], x[a]); x[d] = rotl_sym(x[d], 16)
    x[c] = xor_sym(x[c], x[d]); x[b] = xor_sym(x[b], x[c]); x[b] = rotl_sym(x[b], 12)
    x[a] = xor_sym(x[a], x[b]); x[d] = xor_sym(x[d], x[a]); x[d] = rotl_sym(x[d], 8)
    x[c] = xor_sym(x[c], x[d]); x[b] = xor_sym(x[b], x[c]); x[b] = rotl_sym(x[b], 7)

def get_sym_word(val, is_key=False, key_idx=0):
    res = []
    for i in range(32):
        v = vector(GF(2), 257)
        if is_key:
            v[key_idx * 32 + i] = 1 
        else:
            v[256] = (val >> i) & 1 
        res.append(v)
    return res

def generate_symbolic_equations(iv_hex):
    iv_bytes = bytes.fromhex(iv_hex)
    iv_words = [int.from_bytes(iv_bytes[i:i+4], 'little') for i in range(0, 12, 4)]
    
    eqs = []
    counter = 1
    for _ in range(0, 192, 64): # Sinh 3 Blocks
        state = [
            get_sym_word(0x61707865), get_sym_word(0x3320646e),
            get_sym_word(0x79622d32), get_sym_word(0x6b206574)
        ]
        for i in range(8): state.append(get_sym_word(0, is_key=True, key_idx=i))
        state.append(get_sym_word(counter))
        for w in iv_words: state.append(get_sym_word(w))
        
        init_state = [w[:] for w in state]
        for _ in range(10):
            qr_sym(state, 0, 4, 8, 12); qr_sym(state, 1, 5, 9, 13)
            qr_sym(state, 2, 6, 10, 14); qr_sym(state, 3, 7, 11, 15)
            qr_sym(state, 0, 5, 10, 15); qr_sym(state, 1, 6, 11, 12)
            qr_sym(state, 2, 7, 8, 13); qr_sym(state, 3, 4, 9, 14)
            
        for k in range(16):
            state[k] = xor_sym(state[k], init_state[k])
            
        for w in state: eqs.extend(w)
        counter += 1
    return eqs

def vec_to_int(vec):
    res = 0
    for i, bit in enumerate(vec):
        if int(bit) == 1: res |= (1 << i)
    return res




#REPRESENTS BITS IN EACH KEYSTREAM AS LINEAR EQUATIONS 
print("[*]Representing keystream bits as linear equations\n")
eqs1 = generate_symbolic_equations(IV1_HEX)
eqs2 = generate_symbolic_equations(IV2_HEX)

A_matrix = matrix(GF(2), 1536, 256)
C1 = vector(GF(2), 1536)
C2 = vector(GF(2), 1536)

for i in range(1536):
    for j in range(256): A_matrix[i, j] = eqs1[i][j]
    C1[i] = eqs1[i][256]
    C2[i] = eqs2[i][256]





# PARSE AND FILTER INDEX (MOD 512)
ks_bytes = bytes.fromhex(TARGET_KS_HEX)
ks_bits = [(b >> j) & 1 for b in ks_bytes for j in range(8)]
target_Z_int = vec_to_int(ks_bits)

used_mod512 = set()
idx_1_chosen = []

#Lấy các vị trí bit 1 duy nhất theo mod 512 để lập hệ chính
for i, b in enumerate(ks_bits):
    if b == 1 and (i % 512) not in used_mod512:
        idx_1_chosen.append(i)
        used_mod512.add(i % 512)

rank_1 = len(idx_1_chosen)
num_missing = 256 - rank_1

print("[*]Filtering unique positions of bit 1 (mod 512) in keystream")
print(f"  -Number of unique bit 1 positions (for main system): {rank_1}")
print(f"  -Number of bit 0 positions needed (to complete system): {num_missing}\n")






#SOLVE FOR UNCOMPLETED SYSTEM EQUATION (BIT 1 EQNS)
print("[*]Buil system of",rank_1,"equations and find solution space\n")
A_base = matrix(GF(2), rank_1, 256)
b1_base = vector(GF(2), rank_1)
b2_base = vector(GF(2), rank_1)

for r, idx in enumerate(idx_1_chosen):
    A_base[r] = A_matrix[idx]
    b1_base[r] = 1 + C1[idx]
    b2_base[r] = 1 + C2[idx]

xp = A_base.solve_right(b1_base)
yp = A_base.solve_right(b2_base)
V_basis = A_base.right_kernel().basis_matrix().transpose()





#BUILD MATRIX M AND FIND INV OF IT 
#Randomly choose num_missing positions of bit 0 (mod 512) that not overlap idx_1_chosen and the matrix M is invertible
cand_0 = {}
for i, b in enumerate(ks_bits):
    m = i % 512
    if b == 0 and m not in used_mod512 and m not in cand_0:
        cand_0[m] = i
cand_0_list = list(cand_0.values())

while True:
    idx_0_chosen = py_random.sample(cand_0_list, num_missing)
    # Lập ma trận M từ tập đã chọn
    M_rows = []
    for idx in idx_0_chosen:
        M_rows.append(A_matrix[idx] * V_basis)
    M = matrix(GF(2), num_missing, num_missing, M_rows)

    # check if M is invertible 
    if M.rank() == num_missing:
        print(f"[*]Found invertible matrix M (rank={M.rank()}).\n")
        M_inv = M.inverse()
        break
    





#PRECOMPUTING DELTAS
print("[*]Initializing Delta XOR (OOM Safe)\n")
AV = A_matrix * V_basis 
A_new_xp_C1 = vector(GF(2), num_missing, [(A_matrix[idx]*xp + C1[idx]) for idx in idx_0_chosen])
A_new_yp_C2 = vector(GF(2), num_missing, [(A_matrix[idx]*yp + C2[idx]) for idx in idx_0_chosen])

c1_base = M_inv * A_new_xp_C1
c2_base = M_inv * A_new_yp_C2
KS1_base_int = vec_to_int(A_matrix * xp + C1 + AV * c1_base)
KS2_base_int = vec_to_int(A_matrix * yp + C2 + AV * c2_base)

KS_deltas = []
for i in range(num_missing):
    e_i = vector(GF(2), num_missing)
    e_i[i] = 1
    KS_deltas.append(vec_to_int(AV * (M_inv * e_i)))

def get_ks(rhs_val, base_int):
    res = base_int
    for i in range(num_missing):
        if (rhs_val >> i) & 1:
            res = res^^KS_deltas[i]   
    return res





#SUPER PRUNING & BRUTE-FORCE
#with each idx in idx_0_chosen , a case(a,b) in 3 cases is valid if ks[idx+512] and ks[idx+1024] are both 0 
print("[*]Applying Super Pruning to reduce search space")
valid_branches = []
for j in idx_0_chosen:
    c1_d512 = C1[j] + C1[j+512]
    c2_d512 = C2[j] + C2[j+512]
    c1_d1024 = C1[j] + C1[j+1024]
    c2_d1024 = C2[j] + C2[j+1024]
    
    branches_for_j = []
    # Test 3 trường hợp (a,b) cho (KS1[j], KS2[j])
    for a, b in [(0,0), (0,1), (1,0)]:
        # Kiểm tra điều kiện ở block 2 và 3
        if ((a + c1_d512) * (b + c2_d512)) == 0 and \
           ((a + c1_d1024) * (b + c2_d1024)) == 0:
            branches_for_j.append((a,b))
    valid_branches.append(branches_for_j)

total_cases = 1
for branches in valid_branches:
    total_cases *= len(branches)
print(f"  -Search space reduced from 3^{num_missing} to {total_cases} cases.\n")





#BRUTE FORCE TO SOLVE FOR KEYS
print(f"[*]Starting brute-force ")

start_time = time.time()
last_log_time = start_time
cases_tested = 0 

def solve_pruned(depth, current_rhs1, current_rhs2):
    global cases_tested, last_log_time

    # Điều kiện dừng đệ quy: đã có đủ 22 bit
    if depth == num_missing:
        cases_tested += 1
        
        # Log
        if cases_tested % 2000000 == 0:
            current_time = time.time()
            elapsed = current_time - start_time
            print(f"Tried {cases_tested:^12} / {total_cases} | Time: {elapsed:.2f}s | Rate: {cases_tested/elapsed:.2f} cases/s")
            last_log_time = current_time


        ks1_full = get_ks(current_rhs1, KS1_base_int)
        ks2_full = get_ks(current_rhs2, KS2_base_int)
        
        if (ks1_full & ks2_full) == target_Z_int:

            c1_final = M_inv * (vector(GF(2), num_missing, [(current_rhs1 >> i) & 1 for i in range(num_missing)]) + A_new_xp_C1)
            c2_final = M_inv * (vector(GF(2), num_missing, [(current_rhs2 >> i) & 1 for i in range(num_missing)]) + A_new_yp_C2)
            k1_vec = xp + V_basis * c1_final
            k2_vec = yp + V_basis * c2_final

            k1_bytes = int(vec_to_int(k1_vec)).to_bytes(32, 'little')
            k2_bytes = int(vec_to_int(k2_vec)).to_bytes(32, 'little')
            
            print(f"\n[+]FOUND KEYS!")
            print(f"  -Key 1: {k1_bytes.hex()}")
            print(f"  -Key 2: {k2_bytes.hex()}")
            
            sys.exit(0) 
        return 


    # Bước đệ quy: thử các nhánh hợp lệ cho vị trí 'depth'
    for a, b in valid_branches[depth]:
        next_rhs1 = current_rhs1 | (a << depth)
        next_rhs2 = current_rhs2 | (b << depth)
        solve_pruned(depth + 1, next_rhs1, next_rhs2)

solve_pruned(0, 0, 0)
print("No valid keys found")