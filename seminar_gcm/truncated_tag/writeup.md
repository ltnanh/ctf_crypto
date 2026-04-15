# Truncated tag 

## 1,Challenge overview 

- code server 
```python 
import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
ORIGINAL_PLT = b"Giao dich 1001: Chuyen 10 USD"
KEY_PLT = b"Give me flag"
FLAG = "FLAG{GCM_Trunc4t3d_M4c_1s_D4ng3r0us}"


def gf_mult(x, y):
        R = 0xE1000000000000000000000000000000
        Z, V = 0, x
        for i in range(128):
            if (y >> (127 - i)) & 1: Z ^= V
            V = (V >> 1) ^ R if V & 1 else V >> 1
        return Z


def get_client_data():
    nonce = os.urandom(12)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(ORIGINAL_PLT)
    
    return {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex() 
    }



def oracle_verify(nonce, ct, tag):
    nonce = bytes.fromhex(nonce)
    ct = bytes.fromhex(ct)
    user_tag = bytes.fromhex(tag)
    
    H_bytes = AES.new(KEY, AES.MODE_ECB).encrypt(b'\x00'*16)
    H = int.from_bytes(H_bytes, 'big')
    
    cipher_mask = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    _, mask_bytes = cipher_mask.encrypt_and_digest(b"")
    mask = int.from_bytes(mask_bytes, 'big')
    
    blocks = [int.from_bytes(ct[i:i+16], 'big') for i in range(0, len(ct), 16)]
    blocks.append(len(ct) * 8) 
    
    actual_tag = 0
    for b in blocks:
        actual_tag = gf_mult(actual_tag ^ b, H)

    actual_tag = (actual_tag ^ mask).to_bytes(16, 'big')
    
    return user_tag[:1] == actual_tag[:1]



def admin_verify(nonce, ct, tag):
    nonce = bytes.fromhex(nonce)
    ct = bytes.fromhex(ct)
    user_tag = bytes.fromhex(tag)
    
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    
    try:
        plt = cipher.decrypt_and_verify(ct, user_tag)
        if KEY_PLT in plt:
            return f"SUCCESS: {FLAG}"
        return "Authenticated, but unknown command."
    except ValueError:
        return "FAILED: Invalid MAC."



if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(line_buffering=True) 
    
    intercepted = False
    
    while True:
        print("\n1. Client  |  2. Oracle  |  3. Admin  |  4. Exit")
        try:
            choice = input("Select: ").strip()
            
            if choice == '1':
                if not intercepted:
                    data = get_client_data()
                    print(f"Nonce: {data['nonce']}\nCT: {data['ciphertext']}\nTag: {data['tag']}")
                    intercepted = True
                else:
                    print("You already intercepted the data!")
                    
            elif choice == '2':
                nonce = input("Nonce (hex): ")
                ct = input("CT (hex): ")
                tag = input("Tag (hex)(1 byte): ")
                
                try:
                    if oracle_verify(nonce, ct, tag):
                        print("Valid Tag!")
                    else:
                        print("Invalid Tag!")
                except Exception as ex:
                    print(f"SERVER CRASHED: {ex}")
                    
            elif choice == '3':
                nonce = input("Nonce (hex): ")
                ct = input("CT (hex): ")
                tag = input("Tag (hex)(16 byte): ")
                
                print(f"{admin_verify(nonce, ct, tag)}")
                
            elif choice == '4':
                break
        except Exception as e:
            print(f"Bad input: {e}")

```
- There are 3 object client (decyrpt and digest) , oracle (truncate verify) , admin (verify)
- Each of them has the key of AES

### Contact with server
- Option 1 : Get Client data:
  - get the ciphertext ,nonce and tag of a known plaintex **"Giao dich 1001: Chuyen 10 USD"**
  - Can only contact with client for 1 time 
- Option 2:  Oracle verify 
  - The oracle verify the ciphertext with truncated 1 byte tag ( only compare first 8 bit of the input tag and true tag)
  - Can interact many time 
- Option 3: Admin verify 
  - The admin verify the ciphertext with full tag 
  - If send the valid tag for the plaintext **"Give me flag"** => get the flag 


## 2, Atack strategy 
### 2.1 , Linear property of $GF(2^{128})$
### Multplication with a constant C in GF is a linear mapping 
- The function :$X \mapsto C \cdot X$ can be represent by 
$$
\overline{C \cdot X} = M_C  \overline{X}
$$
- Where :
  - $\overline{C \cdot X}$ and $\overline{X}$ is 128 bit vector of $C \cdot X$ andf $X$
  - $M_C$ is a 128x128 matrix 
- We can compute $M_C$ for a constant C 
  

### Square in GF is a linear mapping
- The function :$X \mapsto X^2$ can be represent by 
$$
\overline{X^2} = M_S  \overline{X}
$$
- Where :
  - $M_S$ is a 128x128 matrix and is identified for $GF(2^{128})$ 
- We achieve that: 
$$
\overline{X^{2^k}} = M_S^k \cdot \overline{X} 
$$

### 2.2 , Attack Idea 
- Assume the tag we get from client:
$$
T = K_0 + \sum_{i=1}^{n} C_i H^i
$$
  
### use oracle to verify truncate tag 

- Gen random a new cpt to ask for verify this cpt with same nonce and origin tag that we get from client 
  - We gen a random set of ${C'_1,C'_2,....,C'_n}$ such that $C'_i$ is block in new cpt 
  - Let $D_i = C'_i - C_i =>$ We get a error polynomial of the origin tag of client and new tag of random cpt 
$$
Error = tag' - tag =  \sum_i D_i \cdot H^i
$$

- Because the tag is truncated to only 8 bit => we can pass if first 8 bit of $tag$ and $tag'$ is the same , or first 8 bit of $Error$ is 0 =>  We can achieve a pass after a few hundred of trial 

### Trick to linear the Error 
- From the linear properties of multiplication and square in GF 
  - If we choose D such that:
$$
\begin{cases}
D_i \neq 0 & \text{if } i = 2^k \\
D_i = 0 & \text{else }
\end{cases}
$$
$$
=> Error = \sum_{k=0}^{m} D_{2^k} \cdot H^{2^k}
$$
$$
<=> \overline{Error} = \sum_{k=0}^{m} M_{D_i} \cdot M_S^k \cdot \overline{H}
$$
Let $\sum_{k=0}^{m} M_{D_i} \cdot M_S^k = M_a$ , we can easily compute $M_a$ (a 128x128 matrix), then $\overline{Error} = M_a \cdot \overline{H}$ ,which represent a system of equations
$$
\begin{cases}
m_{0,0}h_0 + m_{0,1}h_0 + .... + m_{0,127}h_0 = E_0 \\
m_{1,0}h_0 + m_{1,1}h_0 + .... + m_{1,127}h_0 = E_1 \\
....... \\
m_{127,0}h_0 + m_{127,1}h_0 + .... + m_{127,127}h_0 = E_{127}
\end{cases}
$$

- **=>      We only need to collect $E_i$ to solve for H**

### oreacle + linear trick
- when we get a pass for a random cpt that we choose follow the linear trick => first 8 bit of $Error$ is 0 
=> We get 8 equation 
$$
\begin{cases}
m_{0,0}h_0 + m_{0,1}h_0 + .... + m_{0,127}h_0 = 0 \\

....... \\
m_{7,0}h_0 + m_{7,1}h_0 + .... + m_{7,127}h_0 = 0
\end{cases}
$$

=> If we have 16 pass cpt => we get 128 equations , enough to solve for $H$ 
### last forgery 
- After find H :
  - Compute $K_0$
  - Find the ciphertext of **"Give me flag"** 
  - Gen valid tag for the ciphertext 


### 2,3 Exploit 

- Here the sage script to exploit 
```python
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
```
