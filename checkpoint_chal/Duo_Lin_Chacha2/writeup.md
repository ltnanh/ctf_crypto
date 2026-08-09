# Duo_bitwise_chacha2

- Category: Crypto 
- Difficulty : Medium

## 0.Intro 

As I stated from the previous write up of challenge `Duo_bitwise_chacha` , this challenge almost has the same logic . the only difference to the previous chal is that the ouput that I give the user will be much harder , there are only 1024 known keystream , lead to the dim of the null space to brute force is larger ( 57 in this chal ) , and the approach from the previous write up will definitely broken . And in this write up , there will be more linear algebraic applied , result in amazing solution for this chal . Moreover , the solution in this write up (in sagemath) will find the true key pair in less than 0.5s 

## 1.Chal Overview 

```python 
import os

def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def words_to_bytes(w):
    return b''.join([i.to_bytes(4, 'little') for i in w])

def rotate(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


class LinearChaCha20:
    def __init__(self):
        self._state = []
        self._initial_state = []

    def _quarter_round(self, x, a, b, c, d):
        x[a] ^= x[b]; x[d] ^= x[a]; x[d] = rotate(x[d], 16)
        x[c] ^= x[d]; x[b] ^= x[c]; x[b] = rotate(x[b], 12)
        x[a] ^= x[b]; x[d] ^= x[a]; x[d] = rotate(x[d], 8)
        x[c] ^= x[d]; x[b] ^= x[c]; x[b] = rotate(x[b], 7)

    def _inner_block(self, state):
        self._quarter_round(state, 0, 4, 8, 12)
        self._quarter_round(state, 1, 5, 9, 13)
        self._quarter_round(state, 2, 6, 10, 14)
        self._quarter_round(state, 3, 7, 11, 15)
        self._quarter_round(state, 0, 5, 10, 15)
        self._quarter_round(state, 1, 6, 11, 12)
        self._quarter_round(state, 2, 7, 8, 13)
        self._quarter_round(state, 3, 4, 9, 14)

    def generate_keystream(self, length, key, iv):
        c = b''
        counter = 1
        for i in range(0, length, 64):
            state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
            state.extend(bytes_to_words(key))
            state.append(counter)
            state.extend(bytes_to_words(iv))
            
            initial_state = state[:]
            
            for _ in range(10):
                self._inner_block(state)
            
            for k in range(16):
                state[k] ^= initial_state[k]
            
            c += words_to_bytes(state)
            counter += 1
            
        return c[:length]


class DoubleLinearCipher:
    def __init__(self, key1, key2, iv1, iv2):
        self.k1 = key1
        self.k2 = key2
        self.iv1 = iv1
        self.iv2 = iv2
        self.cipher = LinearChaCha20()

    def generate_keystream(self, length):
        ks1 = self.cipher.generate_keystream(length, self.k1, self.iv1)
        ks2 = self.cipher.generate_keystream(length, self.k2, self.iv2)
        return bytes([a & b for a, b in zip(ks1, ks2)])

    def encrypt(self, m):
        ks = self.generate_keystream(len(m))
        return xor_bytes(m, ks)

    def decrypt(self, c):
        return self.encrypt(c)

def bytes_to_bits(b):
    return [(byte >> i) & 1 for byte in b for i in range(8)]

if __name__ == '__main__':
    
    k1 = os.urandom(32)
    k2 = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(12)

    flag = b"BKSEC{?????}"
    known_len = 128 
    plaintext = b'\x00' * known_len + flag
    
    cipher = DoubleLinearCipher(k1, k2, iv1, iv2)
    ciphertext = cipher.encrypt(plaintext)


    print(f"iv1 = {iv1.hex()}")
    print(f"iv2 = {iv2.hex()}")
    print(f"ciphertext = {ciphertext.hex()}")

```

Like the previous chal , a `DoubleLinearCipher` , a stream cipher that its keystream is multiplication bitwise of keystream1 and keystream2 from 2 cipher components `LinearChaCha20` (chacha20 that all integer modulo operation is replaced by XOR)

Known plaintext cryptanalysis with len of known keystream is 128 bytes , mean 2 keystream blocks (less 1 block compare to the previous chal)

## 2.Linear properties 
Here I will recall some lienar properties from that I stated in the previous chapter 
### 2.1 Linear expression 
For each LinearChacha20 , we can represent every single bit of KS1 and KS2 as a linear expression from bits of cipher's key (key_1 and key_2) as variables . call the transformation is $L$

$$S_0 = const \oplus key \oplus ctr \oplus IV$$

$$=> KS = L(S_0) = const \oplus key \oplus ctr \oplus IV$$

$$KS = \underbrace{L(key)}_{Unkownkey} \oplus \underbrace{L(const) \oplus  L(ctr) \oplus L(IV)}_{Known bits}$$

Let $L(key) = A . key$ and $L(const) \oplus  L(ctr) \oplus L(IV) = C$

=> We can represent 2 keystream 
$$ \begin{cases}
KS1 = A .key_1 + C1 \\
KS2 = A.key_2 + C2
\end{cases}$$

Where
- $KS1,KS2,C1,C2$ is 1536 x 1 vectors , A is 1536x256 matrix , $key_1,key_2$ is 256x1 vector of bit vars
- 2 keystream have same matrix A , C1 and C2 is different 


### 2.2 $\Delta C_1 = \Delta C_2$ prop 

**Prop:** Let $C1_1 , C1_2$ are 2 block keystream(block 512 bits) of $KS1$ and so as to $C2_1 , C2_2$ . We have: 

-    >    $\Delta C_1 = \Delta C_2$

- With $\Delta C_1 = C1_1 + C1_2$  and $\Delta C_2 = C2_1 + C2_2$  

## 3. Attack and Implementation 

Compute known keystream first 
```python
#INPUT DATA
IV1_HEX = "686b0a2d909abbb27736541d"
IV2_HEX = "f8a377f6a7685c6c6020f095"
CIPHERTEXT_FULL_HEX = "144080a5010800200f18400011260102444001a45018624a81092310948cc2084a4000b001860c590900000680491449800a1c40841701b9220000914810c4123a42a0f7430205101c00401020860a0604c011210004222a029002108dc480401200803121ce50172043208d19492008a4021949809108cb3e8860d60b1184109c09f37402706c026379724d074a6b372636147a617f3e3e7f2a713068f3c5"
TARGET_KS_HEX = CIPHERTEXT_FULL_HEX[:128*2] 
```

Then , represent each keystream as a linear expression of the cipher's key . We will extract matrix A and $C1,C2$
```python
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
```


### 3.1 Phase1 : Use bit 1 in final keystream to build system of equations
This phase is the same as in the previous write up 

We need to solve for $key_1$ and $key_2$
- Equations system (1) : $A . key_1 + C1 = KS1$
- Equations system (2) : $A . key_2 + C2 = KS2$

From the prop $1 \land 1 = 1$ => from each bit 1 in  KS , we know that the bit in this position in KS1 and KS2 is 1 => each system (1) and (2) have 1 more equation . And as I proved ,2 equations from 2 bit 1 in KS is only independent to each other <=> 2 bit have different position in corespond keystream block : $idx_1 \neq idx2 \pmod {512}$. The rank we can achieve from the keystream is the number of unique positions of bit 1 (mod 512) in keystream. 

For the implementation , we choose the unique bit 1 positions first , and it is almost the rank of system we can achieve 

```python 
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
```
```
[*] Phase 1: Solving from KS=1 positions
[*]Filtering unique positions of bit 1 (mod 512) in keystream
  -Number of unique bit 1 positions (for main system): 199
```


Then , we build the system of equations and solve to find solution spaces of the 2 keys . I call matrix of chosen idx1 is $A_{base}$ . We will have 2 systems with 199 equations. Use right kernel of A and particular solution to represent solution space os key pair . 

- Find the right kernel V of matrix $A_{base}$ and particular solution $x_p,y_p$ of each system , we have :
    - $key_1 = x_p + V. c_1$
    - $key_2 = y_p + V. c_2$
- Where V is 256x57 right null space , $c_1,c_2$ is two 57x1 coes vector that we need to find to complete 2 keys 

```python 
## solve for uncompleted system equation (bit 1 eqns) 
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
```

```bash
-Rank of system: 199
-Dim of solution space: 57 
```

We can see that solution space dimension is 57 . If we use the $\Delta C$ trick , the search space reduce to $2^{57}$ and it still be impossible to brute force . 

### 3.2 Phase 2: Solving $d = c_1 + c_2$ from $\Delta C = (1,1)$ positions
To find 2 coe vectors $c_1,c_2$ , in phase 2 we will find vector (57x1) $d$ is the difference between $c_1$ and $c_2$ : $d = c_1 \oplus c_2$

We will find $d$ based on the remain positions on keystream that bit is 0 , for a position i we have:
$$ \begin{cases}
KS1_i = A_i(x_p + V.c_1) + C1_i \\
KS2_i = A_i(y_p + V.c_2) + C2_i
\end{cases}$$


$$ <=> \begin{cases}
KS1_i = \underbrace{A_i.x_p + C1_i}_{const1_i} + AV_i .c_1 \\
KS2_i = \underbrace{A_i.y_p + C2_i}_{const2_i} + AV_i .c_2
\end{cases}$$

And we will find all the positions i that $\Delta C_1 = \Delta C_2 =1$:
- At the previous write up , I have proved that if $\Delta C_1 = \Delta C_2 = 1$ $=> KS1_i \oplus KS2_i = 1$ . From that 

$$<=> const1_i + AV_i . c_1 = const2_i + AV_i . c_2 $$
$$AV_i . (c_1 + c_2) = AV_i . d = 1 + const1_i + const2_i = rhs_i$$

- This mean that if we can collect $\geq$ 57 position i like that , we can build the system eqns $AV_i .d = rhs_i$ to find d


```python
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
```
```bash 
[*] Phase 2: Solving d = c1 + c2 from delta_C = (1,1) positions
  - Found 128 equations for d
```

### 3.3 Phase 3: Find $c_1, c_2$

We found $d$ , now we have 
$$ \begin{cases}
KS1_i =  const1_i+ AV_i .c_1\\
KS2_i = const2_i + AV_i .(c_1 + d) = (const2_i + AV_i .d) + AV_i .c_1 
\end{cases}$$

Let $AV_i .c_1 = u_i$ , $const1_i = \alpha_i$ , $const2_i + AV_i .d = \beta_i$
$$ \begin{cases}
KS1_i =  \alpha_i + u_i\\
KS2_i = \beta_i + u_i
\end{cases}$$


And from property on $GF(2)$ is $x^2 = x$ , we will find the way to solve for exact value of $c_1$:
- We still based on positions i that bit in keystream is 0 , we have:
    KS1_i . KS2_i = 0$$
    $$<=> (\alpha_i + u_i) (\beta_i + u_i) = 0$$
    $$<=> \alpha_i \beta_i + u_i(\alpha_i + \beta_i) + u_i^2 = 0$$
    $$<=> \alpha_i \beta_i + u_i(\alpha_i + \beta_i +1)  = 0$$


    - If $\alpha_i \neq \beta_i$ : $2 u_i = 0$
    - If $\alpha_i = \beta_i$ : $\alpha_i + u_i = 0 $ or $\alpha_i = u_i$

- So that , for all positions i that $\alpha_i = \beta_i$ , we will know value of $u_i$ is $\alpha_i$ in that position 
$$AV_i .c_1 = \alpha_i$$

- We will find all positions like that and build the system of equations $AV_i .c_1 = \alpha_i$ , if more than 57 equations ,we can find $c_1$ , then recover $c_2$

```python 
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
```
```
[*] Phase 3: Solving c1 from alpha = beta
  - Found 122 equations for c1
```
### 3.4 Recover key 
The last step is recover key pair from $c_1, c_2 $ , founded , then decrypt to find flag 
```python 
     
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
```

```
[+] KEYS FOUND
Key 1: 7f8f18236b9319c8be9bce65cafe5f5cd6f3c62ae6a2e793ce42247e977f18d1
Key 2: 381661edc957be621356654ea84b88bf70e2d4e50df6581af0afed5c051a8a83
```

Decrypt the ciphertext , we achieve the flag 
```
Decrypted flag: BKSEC{l1n3r_4lg3br4_1s_4w3s0m3}
```