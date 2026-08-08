# Duo_bitwise_chacha

- Category: Crypto 
- Difficulty : Medium

## 0.Intro 

From the previous challenge about linear chacha20 , I want to build a harder chal based on this idea , and of course nonlinearity should be applied for this chal . My idea is to use 2 linear Chacha20 (linear bitwise for all the gen keystream phase) to combine to 1 stream cipher duolinear chacha20 ( by multiply 2 keystream from 2 cipher bitwise to gen the final keystream for encryption) . The multiplication (AND) between 2 keystream form a nonlinear property for the cipher , but all the operations still be bitwise , the bits in final keystream can be representd by bits in 2 key (quadratic expression) . The relationship between bits of the ouput keystream and 2 keys is exactly the thing we will exploit to solve this challenge. 

The first idea to solve this challenge that I have is to use the prop `1*1 = 1` , then give the player the ouput that make the known plaintext atttack more interesting . However , in the process of solving my own challenge , I explored many interesting thing about linear algebra ,applied to this duo linear chacha20 cipher , which I will express in this write up and the next chal `Duo_bitwise_chacha2`

With me ,The final solution for this challenge is actually hard to come up with, cause this approach mainly applies linear algebra (and I'm not good in this thing).  Therefore , the final solution will be used for the write up of the 3rd chal  `Duo_bitwise_chacha2` , which have much harder ouput compare to this challenge . And for this challenge , I have considered the ouput of the chal carefully to ensure that the player can apply brute force approach ( of course with some optimization stragety) to solve the challenge , the idea that I think many player ( include me) think about when face a chal like this . The reason I use a quite easy ouput for this challenge is to ensure that player can apply many strageties to solve , making the chal not to be very hard compare to `Duo_bitwise_chacha2`, which has harder ouput to enforce player analyse more about linear properties . 






## 1.Chal Overview 


```python 
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
```

Similar to the previous chal , the chal give me a stream cipher based on Chacha20 :
- The integer modulo operations were replaced by xor bitwise 
- There is one change to the previous chal's linear chacha20 . The last step (integer modular addition of state20 and initial state) was replaced by XOR `for k in range(16):state[k] ^= initial_state[k]`, neccessary change or the chal can't be solved ( with me)

```python 
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
```

The main cipher is `DuoLinearCipher` :
- Include 2 linear chacha20 (different key and IV)
- Stream cipher , the final keystream is the bitwise multiplication of the 2 keystream gen by 2 linear chacha components 

```python 
if __name__ == '__main__':
    k1 = os.urandom(32)
    k2 = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(12)

    flag = b"BKSEC{???????}"
    plaintext = b'\x00' * 192 + flag
    
    cipher = DoubleLinearCipher(k1, k2, iv1, iv2)
    ciphertext = cipher.encrypt(plaintext)

    print(f"iv1 = {iv1.hex()}")
    print(f"iv2 = {iv2.hex()}")
    print(f"ciphertext = {ciphertext.hex()}")
```

The main function is a clear suggestion about known plaintext attack. 
- We know the first 192 bytes (1536 bits) of the final keystream , and we need to find the 2 keys of duo cipher to recover the rest of the keystream to recover flag 

## 2.Linear properties 

`DuoLinearCipher` consist of 2 `LinearChaCha20` . The linear properties in $GF(2)$ of the 2 `LinearChaCha20` and the relations between 2 of them are the key properties to solve this challenge . Here I will express the props that will be useful to my approach . I use $KS1$ , $key_1$ and $KS2$, $key_2$ to represent keystream and key of the 2 linear chacha cipher 
### 2.1 Linear expression 
For each LinearChacha20 , we can represent every single bit of KS1 and KS2 as a linear expression from bits of cipher's key (key_1 and key_2) as variables 

- XOR ($\oplus$): addition in  $GF(2)$.
- Rotate Left ($\lll$): bit permutation, also linear expression in $GF(2)$.

We can perform 20 round and final xor as a linear transformation , we call the transformation is $L$

Moreover , when divide $S_0$ into 4 parts (padded by bit $0$ at bit positions that not belong to):

$$S_0 = const \oplus key \oplus ctr \oplus IV$$

$$=> KS = L(S_0) = const \oplus key \oplus ctr \oplus IV$$

$$KS = \underbrace{L(key)}_{Unkownkey} \oplus \underbrace{L(const) \oplus  L(ctr) \oplus L(IV)}_{Known bits}$$

$\rightarrow L(key)$ is a linear combination of bit variables in key $L(key) = A . key$ 

$\rightarrow L(const) \oplus  L(ctr) \oplus L(IV)$ is excutable bit vector: $L(const) \oplus  L(ctr) \oplus L(IV) = C$

=> We can represent 2 keystream 
$$ \begin{cases}
KS1 = A .key_1 + C1 \\
KS2 = A.key_2 + C2
\end{cases}$$

Where
- $KS1,KS2,C1,C2$ is 1536 x 1 vectors , A is 1536x256 matrix , $key_1,key_2$ is 256x1 vector of bit vars
- 2 keystream have same matrix A , C1 and C2 is different 

Seperate the transfromation into $A.key$ and $C$ will be useful in brute force implementation 

### 2.2 $\Delta C_1 = \Delta C_2$ prop 

**Consider KS1** , divide A into 3 512x256 matrix coresponding to 3 block keystream => the 3 matrix will be the same 

=> The difference between blocks in a keystream only depend on the differences between vectors $C1_i$

- Moreover , take a deeper analyze , consider block keystream 1 and 2 of KS1 :
    - Let $\Delta C1 = C1_1 + C1_2 = (L(const)  \oplus L(IV)\oplus  L(ctr1)) \oplus (L(const)  \oplus L(IV)\oplus  L(ctr2))$ 
    - <=> $\Delta C1 = C1_1 + C1_2 = L(ctr1) \oplus L(ctr2)$ (1)

- => We can see that the differences only depends on $L(ctr1), L(ctr2)$

**Simmilar to KS2** : consider $\Delta C2 = C2_1 + C2_2$ => $\Delta C2 = L(ctr1) \oplus L(ctr2) $ (2)

**Prop:** From (1) and (2), we have a props of relation between 2 keystream 

-    >    $\Delta C_1 = \Delta C_2$

- With $\Delta C_1 = C1_i + C1_j$  and $\Delta C_2 = C2_i + C2_j$  (i,j in 1,2,3)

- This property will be a key to prunning the total cases of brute force 



## 3. Attack and Implementation 

First , of course we will compute knonw keystream 
```python 
#INPUT DATA  
IV1_HEX = "61307e136d4e91b164f64305"
IV2_HEX = "9e4ba797f244f1a25f57ba9e"
CIPHERTEXT_FULL_HEX = "e09027862008500300e2412201100b00125005100840400c3da07222a902a444a042d981007e4218c201464549410001046010508700b20444600003c2389444cc9014840000d1335056682200a0400012e1051c68d1000cac2442029012a12088024144221610108b02d68490416c80226010518300d114d14a40008075dc462888050a2008401c4034012c05004202127624182851420ca0a65212380584f2a0c2c804003100108b03460000402820806010518030008550404002824c0447d2932145637bdfa23a794d316e2322784de51172609e31e27d35476094ee7abf19e62af0599960bb3474a5337c"
TARGET_KS_HEX = CIPHERTEXT_FULL_HEX[:192*2] 
```

Then , for each Linear chacha20 ,consider its key is 256x1 vector of bit variables , run the key gen phase , represent each keystream as a linear expression of the cipher's key . We will extract matrix A and $C1,C2$

```python 
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
    for _ in range(0, 192, 64): # Gen 3 Blocks
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
```


### 3.1 Use bit 1 in final keystream to build system of equations 
To solve for $key_1$ and $key_2$ , we need to know at least 256 bit of each KS1 and KS2 , but for this chal , the final keystream is the multiplication bitwise of the 2 keystream $KS = KS1 \land KS2$
- Equations system (1) : $A . key_1 + C1 = KS1$
- Equations system (2) : $A . key_2 + C2 = KS2$



From the prop $1 \land 1 = 1$ => from each bit 1 in  KS , we know that the bit in this position in KS1 and KS2 is 1 => each system (1) and (2) have 1 more equation
- => With 1536 bit KS , from the AND operation , about 25% of the bits are 1 => We almost have enough equations to solve for  key1 and key2

I also think like that at first , but everything is not easy like that . After trying to solve the system , I found that 256 equations are not enough , because of the property below that I realized when solving the chal 
- Let i is the position in final keystream that $KS_i =1$ => $KS1_i = 1$ => We have $A_i . key_1 + C1_i = 1$
    -   But we know that $A_i = A_{i+512} = A_{i+1024}$ (same position in 3 block keystream)
    - => 3 equation $A_i . key_1 + C1_i = 1$, $A_{i+512} . key_1 + C1_{i+512} = KS1_{i+512}$ and $A_{i+1024} . key_1 + C1_{i+1024} = KS1_{i+1024}$ are the same ( linear dependent)

- => 2 equations from 2 bit 1 in KS is only independent to each other <=> 2 bit have different position in corespond keystream block : $idx_1 \neq idx2 \pmod {512}$

From this property , The true rank we can achive from the keystream is not the number of bit 1 in keystream , it is the number of unique positions of bit 1 (mod 512) in keystream . And this is the reason why I give the player 1536 bits , cause I was choose 1024 bits at first , and I see that the dim of the solution space is too big to brute force .

For the implementation , I think we should choose the unique bit 1 positions first , and it is almost the rank of system we can achieve 

```python 
# PARSE AND FILTER INDEX (MOD 512)
ks_bytes = bytes.fromhex(TARGET_KS_HEX)
ks_bits = [(b >> j) & 1 for b in ks_bytes for j in range(8)]
target_Z_int = vec_to_int(ks_bits)

used_mod512 = set()
idx_1_chosen = []

for i, b in enumerate(ks_bits):
    if b == 1 and (i % 512) not in used_mod512:
        idx_1_chosen.append(i)
        used_mod512.add(i % 512)

rank_1 = len(idx_1_chosen)
num_missing = 256 - rank_1

print("[*]Filtering unique positions of bit 1 (mod 512) in keystream")
print(f"  -Number of unique bit 1 positions (for main system): {rank_1}")
```

```bash
[*]Filtering unique positions of bit 1 (mod 512) in keystream
  -Number of unique bit 1 positions (for main system): 232
```

I have run the chal many time , and number 232 is actually a lucky one , and I choose this for the possibility of optimized brute force 

Then , we need to build the system of equations and solve to find solution spaces of the 2 keys . I call matrix of chosen idx1 is $A_{base}$ . We will have 2 systems of rank 232 (solution space dimension is 24). It is better to use the same matrix $A_{base}$ of the 2 systems for less computation . Here I use right kernel of A and particular solution : 

- Find the right kernel V of matrix $A_{base}$ and particular solution $x_p,y_p$ of each system , we have :
    - $key_1 = x_p + V. c_1$
    - $key_2 = y_p + V. c_2$
- Where V is 256x24 right null space , $c_1,c_2$ is two 24x1 coes vector that we need to find to complete 2 keys 

```python 
#SOLVE FOR UNCOMPLETED SYSTEM EQUATION (BIT 1 EQNS)
print("[*]Buil system of equations and find solution space")
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

print("  -Rank of system:",A_base.rank())
print("  -Dim of solution space:",V_basis.rank())
```

```bash
[*]Buil system of equations and find solution space
  -Rank of system: 232
  -Dim of solution space: 24
```

### 3.2 Brute force more 24 bits of each keystream and solve for key 

### 3.2.1 Solve for complete key pair with a brute force case 
For the next step , we need to choose 24 bit 0 from the final keystream (different idx mod 512) .For each bit 0 , try the coresponding 2 bits in 2 keystream ($KS1_i \land KS2_i = 0 $) , then complete the system of equations . The exact case of 24 bit in keystream 1 and 24 bit in keystream 2 will result in true key1 and key2 


-  From 24 position of bit 0 are chosen we have :
    - $A_{chosen}$ : 24x256 matrix 
    - $C1_{chosen} , C2_{chosen}$ : 24x1 vector 
- A brute force case we have :
    - $KS1_{trial} , KS2_{trial}$ : 24x1 vector (based on 24 chosen position)

As I said above , we need to find 2 coe vector $c_1,c_2$ .For each case , we will do it like this:

$$ \begin{cases}
A_{chosen}. key_1 +  C1_{chosen} = KS1_{trial}\\
A_{chosen}. key_2 +  C2_{chosen} = KS2_{trial}
\end{cases}$$

$$
\Leftrightarrow \begin{cases} 
A_{chosen}. (x_p + V. c_1) +  C1_{chosen} = KS1_{trial}\\
A_{chosen}. (y_p + V. c_2) +  C2_{chosen} = KS2_{trial}
\end{cases}
$$

- Let $A_{chosen} . V = M$ , we have :
$$ \begin{cases}
M .c_1  = KS1_{trial} +  C1_{chosen} + A_{chosen}.x_p = b_1\\
M .c_2  = KS2_{trial} + C2_{chosen} + A_{chosen}.y_p = b_2
\end{cases}$$

$$
\Leftrightarrow \begin{cases} 
c_1 = M^{-1} .b_1\\
c_2 = M^{-1} .b_2
\end{cases}
$$

- After computed $c_1,c_2$ , we only need to recover KS1 and KS2 , and if $KS1 \land KS2 = KS$ , we find the true key $key_1, key_2$

But for the implementation , do so much step in a iter$ation (compute c , compute key , compute keystream) in a brute force stragety is terrible , we need to pre compute something before the loop . The goal for each case is to compute $KS1$ and $KS2$ , and here how I implement :
- Consider keystream 1 , we have :
    $$c_1 = M^{-1}.(KS1_{trial} +  C1_{chosen} + A_{chosen}.x_p ) $$
    $$= M^{-1} .(C1_{chosen} + A_{chosen}.x_p ) +M^{-1}.KS1_{trial}$$
    $$= c_{1base} + c_{1delta}$$

    - From that, and let $A.V = AV$ we have :
    $$KS1 = A . (x_p + V . c_1) + C1$$
    $$= \underbrace{AV.c_{1delta}}_{KS1_{delta}} + \underbrace{AV.c_{1base} + A . x_p + C1}_{KS1_{base}} $$
    $$= KS1_{base} + KS1_{delta}$$


- Similar with keystream 2 : $KS2 = KS2_{base} + KS2_{delta}$

- From above expression 
    - we can precompute $KS1_{base}$ and $KS2_{base}$ before the loop
    - We pre compute $B = AV . M^{-1}$ too 
    - => In the backtrack phase ,for a case , we only need to compute :

$$ \begin{cases}
KS1  = B . KS1_{trial} +  KS1_{base}\\
KS2  = B . KS2_{trial} +  KS2_{base}
\end{cases}$$

And here, code to choose idx bit 0 and compute $M^{-1}$

```python
#BUILD MATRIX M AND FIND INV OF IT 
#Randomly choose num_missing positions of bit 0 (mod 512) that not overlap idx_1_chosen and the matrix M is invertible
cand_0 = {}
for i, b in enumerate(ks_bits):
    m = i % 512
    if b == 0 and m not in used_mod512 and m not in cand_0:
        if C1[m] + C1[m+512] == 1:
            cand_0[m] = i
cand_0_list = list(cand_0.values())

while True:
    idx_0_chosen = py_random.sample(cand_0_list, num_missing)
    M_rows = []
    for idx in idx_0_chosen:
        M_rows.append(A_matrix[idx] * V_basis)
    M = matrix(GF(2), num_missing, num_missing, M_rows)

    # check if M is invertible 
    if M.rank() == num_missing:
        print(f"\n[*]Found invertible matrix M (rank={M.rank()}).\n")
        M_inv = M.inverse()
        break
```
```
[*]Found invertible matrix M (rank=24).
```
The step to choose `cand_0_list` is strange ? It is a great trick to prunning total cases that I will introduce soon 

And here is precompute phase 
```python
#PRECOMPUTING DELTAS
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

#compute KS with rhs is KS_trial , base_int is KS_base 
def get_ks(rhs_val, base_int):
    res = base_int
    for i in range(num_missing):
        if (rhs_val >> i) & 1:
            res = res^^KS_deltas[i]   
    return res
```

### 3.2.2 $\Delta C$ trick reduce $3^n$ to $2^n$

For the brute force , in general , each bit 0 value in the final keystream will lead to 3 case of $KS1_i ,KS2_i$ are (0,0) , (0,1) , (1,0)
=> we have 3^24 cases , and we will need days  of running the code to get the true keys . And the $\Delta C_1 = \Delta C_2$ prop I said above will lead to a trick to reduce the search space significantly . 
- We know that $\Delta C_1 = \Delta C_2$ with $\Delta C_1 = C1_i + C1_j$  and $\Delta C_2 = C2_j + C2_j$  (i,j in 1,2,3) . It means that :
    - $KS1_i + KS1_{i+512} = KS2_i + KS2_{i+512}$ or they can be both 1,1 or 0,0 . 
- For the case 1,1 :

    $$ \begin{cases}
    KS1_i + KS1_{i+512} = 1\\
    KS2_i + KS2_{i+512} = 1
    \end{cases}$$
    - If $KS1_i , KS2_i = (0,0)$ = > $KS1_{i+512},KS2_{i+512} = (1,1)$ => Invalid because $KS1_{i+512}\land KS2_{i+512} = 0$
    - => Only 2 case (0,1) and (1,0) left for pair $KS1_i , KS2_i$ 

- From that prop , we can choose only the idx i that $\Delta C_1 = \Delta C_2 = 1$ , so total cases from $3^{24}$ reduce to $2^{24}$ , Sage math can brute all in 1-2 minutes.

And this is why i implement choosing `cand_0_list` before choosing `idx_0_chosen` in the code above 

Then the code below is to prune the search space 
```python
print("[*]Applying Delta C = (1,1) Trick to reduce search space")
valid_branches = []
for j in idx_0_chosen:
    valid_branches.append([(0,1), (1,0)])

total_cases = 1
for branches in valid_branches:
    total_cases *= len(branches)
print(f"  -Search space reduced from 3^{num_missing} to {total_cases} cases.\n")
```
```bash
[*]Applying Delta C = (1,1) Trick to reduce search space
  -Search space reduced from 3^24 to 16777216 cases.
```

### 3.2.3 Implement brute force 
From set `valid_branches` we achieved , implement backtracking , and we will achieve the 2 keys in about 1 min 

```python
#BRUTE FORCE TO SOLVE FOR KEYS
print(f"[*]Starting brute-force ")

start_time = time.time()
last_log_time = start_time
cases_tested = 0 

def solve_pruned(depth, current_rhs1, current_rhs2):
    global cases_tested, last_log_time


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


    for a, b in valid_branches[depth]:
        next_rhs1 = current_rhs1 | (a << depth)
        next_rhs2 = current_rhs2 | (b << depth)
        solve_pruned(depth + 1, next_rhs1, next_rhs2)

solve_pruned(0, 0, 0)
print("No valid keys found")
```
```bash
[*]Starting brute-force 
Tried   2000000    / 16777216 | Time: 11.33s | Rate: 176555.70 cases/s
Tried   4000000    / 16777216 | Time: 22.97s | Rate: 174177.41 cases/s
Tried   6000000    / 16777216 | Time: 34.51s | Rate: 173869.29 cases/s
Tried   8000000    / 16777216 | Time: 45.93s | Rate: 174193.42 cases/s
Tried   10000000   / 16777216 | Time: 57.37s | Rate: 174308.31 cases/s
Tried   12000000   / 16777216 | Time: 68.85s | Rate: 174283.39 cases/s
Tried   14000000   / 16777216 | Time: 80.29s | Rate: 174358.91 cases/s

[+]FOUND KEYS!
  -Key 1: 49d2b29a159fd608d584109c137ac6f1d1c3c24af02aba2375a70b0fa8d09666
  -Key 2: ae185b8d7e85b10f90d8dff33788d7f48fae5a3422ad88a1a3ef6cd0281abf68
```



Last step , use the key pair to decrypt ciphertext and get flag 
```bash
BKSEC{N0n_L1n3ar_w1th_1nt3gr4l_M0d_1s_b3tt3r}
```
