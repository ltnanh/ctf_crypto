import operator




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

        





#INPUT 
iv_hex = "30b7ac37064ab6f51a137577"
ct_hex = "a724b57d6a8076bd190984634b797f7025a7441d8f9ab1113a58e4ba0fa529e07848eef656d656c308213ffd653e9a3f6db4f22e0b417eb6d1495e5141fd5e8b560f72aef2d1bc8549b021407cf10a4941e28a47811bc6ee2af81acc05e9d599c3bb4d9a96dd8fc406d49e56b2ed"
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

#Compute keystream via known plaintext 
known_pt = b'A' * 64
block1_ct = ct[:64]
ks_block1 = xor_bytes(block1_ct, known_pt)
ks_words = bytes_to_words(ks_block1)

#State0 
initial_state_vals = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] #Const 
initial_state_vals.extend([0]*8) # Key
initial_state_vals.append(1)     # Counter 
initial_state_vals.extend(bytes_to_words(iv)) # IV 


# State20 = (Keystream - State0) % 2^32
target_state20_words = {}
known_indices = [0, 1, 2, 3, 12, 13, 14, 15]

for i in known_indices:
    target_state20_words[i] = (ks_words[i] - initial_state_vals[i]) % (2**32)




 
# BUILD STATE 20 FROM 256 VARIABLES OF KEY 
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


print("[*] Building State 20 (Vector 512)")
# state0 
state = []
state.append(int_to_vecs(0x61707865))
state.append(int_to_vecs(0x3320646e))
state.append(int_to_vecs(0x79622d32))
state.append(int_to_vecs(0x6b206574))

for i in range(8): 
    state.append(key_var_vecs(i))

state.append(int_to_vecs(1)) 

iv_words = [int.from_bytes(iv[i:i+4], 'little') for i in range(0, 12, 4)]
for w in iv_words: 
    state.append(int_to_vecs(w))

# 20 round 
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








# BUIL MATRIX 256X256 OF EQN SYSTEM AND SOLVE 
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
    key_bits_vec = A.solve_right(b)

    key_bytes = bytearray()
    for i in range(8):
        word_val = sum(int(key_bits_vec[i*32 + j]) << j for j in range(32))
        key_bytes.extend(word_val.to_bytes(4, 'little'))

    found_key = bytes(key_bytes)
    print(f"[+] Found key: {found_key.hex()}")

    cipher = LinearChaCha20()
    decrypted_msg = cipher.decrypt(ct, found_key, iv)
    print(f"[+] FLAG: {decrypted_msg[64:].decode('utf-8', errors='ignore')}")

        
except ValueError:
    print("[-] Matrix has no solution")