import time
import sys
from sage.all import *

#INPUT DATA
IV1_HEX = "686b0a2d909abbb27736541d"
IV2_HEX = "f8a377f6a7685c6c6020f095"
CIPHERTEXT_FULL_HEX = "144080a5010800200f18400011260102444001a45018624a81092310948cc2084a4000b001860c590900000680491449800a1c40841701b9220000914810c4123a42a0f7430205101c00401020860a0604c011210004222a029002108dc480401200803121ce50172043208d19492008a4021949809108cb3e8860d60b1184109c09f37402706c026379724d074a6b372636147a617f3e3e7f2a713068f3c5"
TARGET_KS_HEX = CIPHERTEXT_FULL_HEX[:128*2] 




# Utility functions to represent ks bit to linear equations
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
    for _ in range(0, 128, 64):
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

A_matrix = matrix(GF(2), 1024, 256)
C1 = vector(GF(2), 1024)
C2 = vector(GF(2), 1024)

for i in range(1024):
    for j in range(256): A_matrix[i, j] = eqs1[i][j]
    C1[i] = eqs1[i][256]
    C2[i] = eqs2[i][256]




# PHASE1 : SOLVE FOR UNCOMPLETED SYSTEM EQUATION (BIT 1 EQNS)
print("[*] Phase 1: Solving from KS=1 positions")

#parse and filter index( mod 512) 
ks_bytes = bytes.fromhex(TARGET_KS_HEX)
ks_bits = [(b >> j) & 1 for b in ks_bytes for j in range(8)]

used_mod512 = set()
idx_1_chosen = []

for i, b in enumerate(ks_bits):
    if b == 1 and (i % 512) not in used_mod512:
        idx_1_chosen.append(i)
        used_mod512.add(i % 512)

rank_1 = len(idx_1_chosen)
print("[*]Filtering unique positions of bit 1 (mod 512) in keystream")
print(f"  -Number of unique bit 1 positions (for main system): {rank_1}")




# solve for uncompleted system equation (bit 1 eqns) 
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
num_ns = V_basis.rank()
print("  -Rank of system:",A_base.rank())
print("  -Dim of solution space:",num_ns,"\n")










# PHASE 2 : SOLVE FOR d = c1 + c2 FROM delta_C = (1,1) POSITIONS
print("[*] Phase 2: Solving d = c1 + c2 from delta_C = (1,1) positions")

AV = A_matrix * V_basis

delta_C = {}
for j in range(512):
    if j not in used_mod512:
        delta_C[j] = C1[j] + C1[j+512]

# Build sys eqns p2_Matrix.d = p2_Vector 
p2_Matrix = []
p2_Vector = []
for j in range(512):
    if j not in used_mod512 and delta_C[j] == 1:
        row = AV[j]
        # KS1_j + KS2_j = 1
        # AV_j * d = 1 + C1_j + C2_j + A_j * (xp + yp)
        rhs = 1 + C1[j] + C2[j] + A_matrix[j] * (xp + yp)
        p2_Matrix.append(row)
        p2_Vector.append(rhs)
print(f"  - Found {len(p2_Matrix)} equations for d\n")

p2_Matrix = matrix(GF(2), p2_Matrix)
p2_Vector = vector(GF(2), p2_Vector)

d = p2_Matrix.solve_right(p2_Vector)
    






    

# PHASE 3: SOLVE FOR c1 FROM alpha = beta POSITIONS
print("[*] Phase 3: Solving c1 from alpha = beta")

p3_Matrix = []
p3_Vector = []
    
for i in range(1024):
    if i % 512 in used_mod512:
        continue
        
    alpha = A_matrix[i] * xp + C1[i]
    beta = A_matrix[i] * yp + C2[i] + AV[i] * d
        
    if alpha == beta:
        # KS1 * KS2 = 0 => AV_i * c1 = alpha
        p3_Matrix.append(AV[i])
        p3_Vector.append(alpha)

print(f"  - Found {len(p3_Matrix)} equations for c1\n") 
p3_Matrix = matrix(GF(2), p3_Matrix)
p3_Vector = vector(GF(2), p3_Vector)
c1 = p3_Matrix.solve_right(p3_Vector)
c2 = c1 + d
        





k1_vec = xp + V_basis * c1
k2_vec = yp + V_basis * c2
        
ks1 = A_matrix * k1_vec + C1
ks2 = A_matrix * k2_vec + C2
        
ks_test = vector(GF(2), [(ks1[i] * ks2[i]) for i in range(1024)])

valid = True #test for valid of key pair founded 
for i in range(1024):
    if ks_test[i] != ks_bits[i]:
        valid = False 
        print("Invalid key pair")
        break
                
if valid:
    k1_bytes = int(vec_to_int(k1_vec)).to_bytes(32, 'little')
    k2_bytes = int(vec_to_int(k2_vec)).to_bytes(32, 'little')
    print("[+] KEYS FOUND")
    print(f"Key 1: {k1_bytes.hex()}")
    print(f"Key 2: {k2_bytes.hex()}")
           

    
