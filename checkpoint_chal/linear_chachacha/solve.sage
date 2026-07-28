import operator


# 1. THUẬT TOÁN LINEAR CHACHA20 
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
        self._quarter_round(state, 0, 4, 8, 12)
        self._quarter_round(state, 1, 5, 9, 13)
        self._quarter_round(state, 2, 6, 10, 14)
        self._quarter_round(state, 3, 7, 11, 15)
        self._quarter_round(state, 0, 5, 10, 15)
        self._quarter_round(state, 1, 6, 11, 12)
        self._quarter_round(state, 2, 7, 8, 13)
        self._quarter_round(state, 3, 4, 9, 14)

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
                self._state[k] = operator.xor(self._state[k], self._initial_state[k])

            c += xor_bytes(m[i:i+64], words_to_bytes(self._state))
            self._counter += 1
        return c

    def decrypt(self, c, key, iv):
        return self.encrypt(c, key, iv)
    


# 2. XÂY DỰNG MA TRẬN BẰNG VECTOR TRÊN GF(2)
iv_hex = "40932cb9c92cab7e39d52af1"
ct_hex = "54968e342fe8d5fce7a560fa6331adcc8831f9eea7b96414c27cc72e2a33f2f4e92d985b3e807730dce5d88ed02a9eb3930b9d5a503debfa46d439553c4c19d178a5ba5cfcda5da8142ac3cb77efd2ea7ba8f50be53887403effd5b2267596aab54d28ae06ca9b6680834659"
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

known_pt = b'A' * 64
ks_block1 = xor_bytes(ct[:64], known_pt)

ks_bits = []
for i in range(0, 64, 4):
    word = int.from_bytes(ks_block1[i:i+4], 'little')
    for j in range(32):
        ks_bits.append((word >> j) & 1)




print("[*] Building state 0")

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


# DỰNG STATE 0
state = []
state.append(int_to_vecs(0x61707865)); state.append(int_to_vecs(0x3320646e))
state.append(int_to_vecs(0x79622d32)); state.append(int_to_vecs(0x6b206574))

for i in range(8):
    state.append(key_var_vecs(i))
    
state.append(int_to_vecs(1)) 

iv_words = [int.from_bytes(iv[i:i+4], 'little') for i in range(0, 12, 4)]
for w in iv_words:
    state.append(int_to_vecs(w))

initial_state = [word[:] for word in state]



# CHẠY ROUND
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

for i in range(16):
    state[i] = xor_vecs_sym(state[i], initial_state[i])

state_bits_vecs = [bit for word in state for bit in word]



# RÁP VÀO MA TRẬN
print("[*] Solving 512x256 matrix")
A = Matrix(GF(2), 512, 256)
b = vector(GF(2), 512)

for i in range(512):
    v = state_bits_vecs[i]
    for j in range(256):
        A[i, j] = v[j]

    b[i] = (ks_bits[i] + int(v[256])) % 2

K_sol = A.solve_right(b)

key_bytes = bytearray()
for i in range(8):
    word_val = sum(int(K_sol[i*32 + j]) << j for j in range(32))
    key_bytes.extend(word_val.to_bytes(4, 'little'))

print(f"[+] found key: {key_bytes.hex()}")


# 3. DECRYPT MESSAGE AND EXTRACT FLAG
cipher = LinearChaCha20()
decrypted_msg = cipher.decrypt(ct, bytes(key_bytes), iv)

print(f"[+] FLAG: {decrypted_msg[64:].decode('utf-8')}")