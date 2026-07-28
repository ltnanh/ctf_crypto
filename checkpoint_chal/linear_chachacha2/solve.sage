import operator
import itertools




#LINEAR CHACHA20 
def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def words_to_bytes(w):
    return b''.join([i.to_bytes(4, 'little') for i in w])

def rotate(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

def xor_bytes(a, b):
    return bytes([operator.xor(x, y) for x, y in zip(a, b)])

class LinearChaCha20:
    def __init__(self):
        self._state = []
        self._initial_state = [] 

    def _quarter_round(self, x, a, b, c, d):
        x[a] = operator.xor(x[a], x[b]); x[d] = operator.xor(x[d], x[a]); x[d] = rotate(x[d], 16)
        x[c] = operator.xor(x[c], x[d]); x[b] = operator.xor(x[b], x[c]); x[b] = rotate(x[b], 12)
        x[a] = operator.xor(x[a], x[b]); x[d] = operator.xor(x[d], x[a]); x[d] = rotate(x[d], 8)
        x[c] = operator.xor(x[c], x[d]); x[b] = operator.xor(x[b], x[c]); x[b] = rotate(x[b], 7)

    def _inner_block(self, state):
        self._quarter_round(state, 0, 4, 8, 12); self._quarter_round(state, 1, 5, 9, 13)
        self._quarter_round(state, 2, 6, 10, 14); self._quarter_round(state, 3, 7, 11, 15)
        self._quarter_round(state, 0, 5, 10, 15); self._quarter_round(state, 1, 6, 11, 12)
        self._quarter_round(state, 2, 7, 8, 13); self._quarter_round(state, 3, 4, 9, 14)

    def _setup_state(self, key, iv):
        self._state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        self._state.extend(bytes_to_words(key))
        self._state.append(self._counter)
        self._state.extend(bytes_to_words(iv))
        self._initial_state = self._state[:] 

    def encrypt(self, m, key, iv):
        c = b''
        self._counter = 1
        for i in range(0, len(m), 64):
            self._setup_state(key, iv)
            for j in range(10):
                self._inner_block(self._state)
            for k in range(16):
                self._state[k] = (self._state[k] + self._initial_state[k]) % (2 ** 32)
            c += xor_bytes(m[i:i+64], words_to_bytes(self._state))
            self._counter += 1
        return c

    def decrypt(self, c, key, iv):
        return self.encrypt(c, key, iv)

        





# 2. KHAI THÁC PEELING ATTACK
iv_hex = "d3625de0954c28169de78289"
ct_hex = "6f0c65d849f87310e629a94056fe5081ca89b896c2ca69f011c4c59b01e22922e98c21227562e6f9d7617c840ed38a62c3d20c0da9d744bf2a62364177db7a660f3fb7bdbedbbbc4b9c6c2736260aede391358f2005302a54f5cd6371d044bb4856c80520d68201f4125c2d7"
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

known_pt = b'A' * 64
block1_ct = ct[:64]
ks_block1 = xor_bytes(block1_ct, known_pt)
ks_words = bytes_to_words(ks_block1)


initial_state_vals = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] #Const 
initial_state_vals.extend([0]*8) # Key
initial_state_vals.append(1)     # Counter 
initial_state_vals.extend(bytes_to_words(iv)) # IV 

# State20 = (Keystream - InitialState) % 2^32
target_state20_words = {}
known_indices = [0, 1, 2, 3, 12, 13, 14, 15]

for i in known_indices:
    target_state20_words[i] = (ks_words[i] - initial_state_vals[i]) % (2**32)


    
print("[*] Building State 20 (Vector 257)")
V = VectorSpace(GF(2), 257)

def int_to_vecs(n):
    vecs = []
    for i in range(32):
        v = V(0)
        v[256] = (n >> i) & 1  
        vecs.append(v)
    return vecs

def key_var_vecs(word_idx):
    vecs = []
    for i in range(32):
        v = V(0)
        v[word_idx * 32 + i] = 1 
        vecs.append(v)
    return vecs

def rotl_vecs(w, n):
    return w[32-n:] + w[:32-n]

def xor_vecs_sym(w1, w2):
    return [v1 + v2 for v1, v2 in zip(w1, w2)] 

# DỰNG STATE BAN ĐẦU
state = []
state.append(int_to_vecs(0x61707865)); state.append(int_to_vecs(0x3320646e))
state.append(int_to_vecs(0x79622d32)); state.append(int_to_vecs(0x6b206574))
for i in range(8): state.append(key_var_vecs(i))
state.append(int_to_vecs(1)) 
iv_words = [int.from_bytes(iv[i:i+4], 'little') for i in range(0, 12, 4)]
for w in iv_words: state.append(int_to_vecs(w))

# CHẠY 20 ROUND 
def qr_sym(x, a, b, c, d):
    x[a] = xor_vecs_sym(x[a], x[b]); x[d] = xor_vecs_sym(x[d], x[a]); x[d] = rotl_vecs(x[d], 16)
    x[c] = xor_vecs_sym(x[c], x[d]); x[b] = xor_vecs_sym(x[b], x[c]); x[b] = rotl_vecs(x[b], 12)
    x[a] = xor_vecs_sym(x[a], x[b]); x[d] = xor_vecs_sym(x[d], x[a]); x[d] = rotl_vecs(x[d], 8)
    x[c] = xor_vecs_sym(x[c], x[d]); x[b] = xor_vecs_sym(x[b], x[c]); x[b] = rotl_vecs(x[b], 7)

for _ in range(10):
    qr_sym(state, 0, 4, 8, 12); qr_sym(state, 1, 5, 9, 13)
    qr_sym(state, 2, 6, 10, 14); qr_sym(state, 3, 7, 11, 15)
    qr_sym(state, 0, 5, 10, 15); qr_sym(state, 1, 6, 11, 12)
    qr_sym(state, 2, 7, 8, 13); qr_sym(state, 3, 4, 9, 14)








# 3. LẬP MA TRẬN TỪ 8 WORDS ĐÃ BIẾT (256 PT x 256 ẨN)
A = Matrix(GF(2), 256, 256)
b = vector(GF(2), 256)

row_idx = 0
for idx in known_indices:
    target_val = target_state20_words[idx]
    
    for bit_pos in range(32):
        v = state[idx][bit_pos]
        target_bit = (target_val >> bit_pos) & 1
        
        for j in range(256):
            A[row_idx, j] = v[j]
            
        b[row_idx] = (target_bit + int(v[256])) % 2
        row_idx += 1


try:
    print("[*] Solving 256x256 matrix")
    K_part = A.solve_right(b)
    
    # Find Null Space 
    NS = A.right_kernel().basis()
    print(f"[*] Null space dimension: {len(NS)}")
    
    print("[*] Brute-forcing null space variants")
    
    found_key = None
    
    # Vét cạn tất cả các tổ hợp tuyến tính của Null Space
    for coeffs in itertools.product([0, 1], repeat=len(NS)):
        K_cand = vector(GF(2), K_part)
        
        for c, vec in zip(coeffs, NS):
            if c:
                K_cand += vec
             
        #Check candidate key
        key_bytes = bytearray()
        for i in range(8):
            word_val = sum(int(K_cand[i*32 + j]) << j for j in range(32))
            key_bytes.extend(word_val.to_bytes(4, 'little'))
            
        cipher_test = LinearChaCha20()
        test_ct = cipher_test.encrypt(known_pt, bytes(key_bytes), iv)
        
        if test_ct == block1_ct:
            print(f"[+] found exact key: {key_bytes.hex()}")
            found_key = bytes(key_bytes)
            break
            
    if found_key:
        cipher = LinearChaCha20()
        decrypted_msg = cipher.decrypt(ct, found_key, iv)
        print(f"[+] FLAG: {decrypted_msg[64:].decode('utf-8', errors='ignore')}")
    else:
        print("[-] Brute-force failed")
        
except ValueError:
    print("[-] Matrix has no solution")