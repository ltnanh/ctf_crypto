from pwn import *
import os

F.<x> = GF(2^128, name = 'x' , modulus = x^128 + x^7 + x^2 +x +1)


def bytes_to_F(block):
    res = F(0)
    bits = bin(int.from_bytes(block, 'big'))[2:].zfill(128)
    for i in range(128):
        if bits[i] == '1':
            res += x^i  
    return res

def F_to_bytes(f_elem):
    coeffs = f_elem.list()
    coeffs = coeffs + [0] * (128 - len(coeffs))
    bit_string = "".join(str(int(c)) for c in coeffs)
    return int(bit_string, 2).to_bytes(16, 'big')


def F_to_vec(f_elem):
    coeffs = f_elem.list()
    coeffs = coeffs + [0] * (128 - len(coeffs))
    return vector(GF(2), coeffs)

def vec_to_F(vec):
    return F(list(vec))


def ghash(ct, H):
    padded_ct = ct.ljust((len(ct) + 15) // 16 * 16, b'\x00')
    blocks = [padded_ct[i:i+16] for i in range(0, len(padded_ct), 16)]
    
    L_block = (len(ct) * 8).to_bytes(16, 'big')
    blocks.append(L_block)
    
    res = F(0)
    for b in blocks:
        b_F = bytes_to_F(b)
        res = (res + b_F) * H
    return res



# Ms: Matrix for f(X) = X^2 in GF(2^128)
Ms_rows = []
for i in range(128):
    basis_elem = x^i          
    sq_elem = basis_elem^2    
    Ms_rows.append(F_to_vec(sq_elem))
Ms = Matrix(GF(2), Ms_rows).transpose()

# MD: Matrix for f(X) = D*X in GF(2^128) where D is a constant
def build_MD(D):
    rows = []
    for i in range(128):
        basis_elem = x^i     
        res = D * basis_elem  
        rows.append(F_to_vec(res))
    return Matrix(GF(2), rows).transpose()



r = remote('127.0.0.1', 1337)

r.recvuntil(b"Select: ")
r.sendline(b"1")
r.recvuntil(b"Nonce: ")
nonce_hex = r.recvline().strip().decode()
r.recvuntil(b"CT: ")
ct_hex = r.recvline().strip().decode()
r.recvuntil(b"Tag: ")
tag_hex = r.recvline().strip().decode()

print(f"Client Nonce: {nonce_hex}")
print(f"Client CT: {ct_hex}")
print(f"Client Tag: {tag_hex}")

ct = bytes.fromhex(ct_hex)
C1 = ct[:16]
C2 = ct[16:32].ljust(16, b'\x00')

L_old = (len(ct) * 8).to_bytes(16, 'big')  
L_new = (64 * 8).to_bytes(16, 'big')  

# D1_constant = L_new XOR L_old
D1 = bytes_to_F(L_new) + bytes_to_F(L_old) 
MD1_matrix = build_MD(D1)

equations = []
success_count = 0
TARGET_SUCCESS = 18 
trial = 0 


# Collecting equations from Oracle
print(f"Starting Oracle Mining Phase (Target: {TARGET_SUCCESS} successes)")

while success_count < TARGET_SUCCESS:
    trial += 1

    #generate random (maybe forge) cpt 
    B4 = b'\x00' * 16
    B3 = os.urandom(16)
    B2 = C1
    B1 = os.urandom(16)
    
    ct_new = B4 + B3 + B2 + B1

    # different between new tag and origin tag 
    D4 = bytes_to_F(B3)
    D2 = bytes_to_F(B1) + bytes_to_F(C2)
    
    r.recvuntil(b"Select: ")
    r.sendline(b"2")
    r.sendlineafter(b"Nonce (hex): ", nonce_hex.encode())
    r.sendlineafter(b"CT (hex): ", ct_new.hex().encode())
    r.sendlineafter(b"Tag (hex)(1 byte): ", tag_hex[:2].encode()) 
    
    res = r.recvline().decode()
    
    if "Valid" in res:
        success_count += 1
        print(f"Oracle Success {success_count}/{TARGET_SUCCESS} at Trial {trial}!")
        
        MD4 = build_MD(D4)
        MD2 = build_MD(D2)
        # for a valid tag we achieve 8 equations about H 
        AD = MD4 * (Ms * Ms) + MD2 * Ms + MD1_matrix

        for row_idx in range(8):
            equations.append(AD[row_idx])



# Solve to find H 
print("Solving system of equations")
M_final = Matrix(GF(2), equations)
kernel = M_final.right_kernel()

if kernel.dimension() == 0:
    print("No solution found")
    exit()

H = kernel.basis()[0]
H = vec_to_F(H) 
print(f"Found H: {F_to_bytes(H).hex()}")




# Compute valid tag for forged plt 
print("Forging Admin Command")
original_plt = b"Giao dich 1001: Chuyen 10 USD"
target_plt = b"Give me flag"

keystream = xor(ct[:len(original_plt)], original_plt)
forged_ct = xor(target_plt, keystream)

# compute K0 = Enc(nonce) 
tag_original = bytes_to_F(bytes.fromhex(tag_hex))
S_mask_F = tag_original + ghash(ct, H)

# Compute forged tag for target plt 
forged_tag = ghash(forged_ct, H) + S_mask_F
forged_tag_bytes = F_to_bytes(forged_tag)

print(f"Forged CT: {forged_ct.hex()}")
print(f"Forged Tag: {forged_tag_bytes.hex()}")


r.recvuntil(b"Select: ")
r.sendline(b"3")
r.sendlineafter(b"Nonce (hex): ", nonce_hex.encode())
r.sendlineafter(b"CT (hex): ", forged_ct.hex().encode())
r.sendlineafter(b"Tag (hex)(16 byte): ", forged_tag_bytes.hex().encode())

print(r.recvline().decode().strip())
