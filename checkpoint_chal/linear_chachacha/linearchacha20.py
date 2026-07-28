
from os import urandom

def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def rotate(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

def words_to_bytes(w):
    return b''.join([i.to_bytes(4, 'little') for i in w])

def xor(a, b):
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])


class LinearChaCha20:
    def __init__(self):
        self._state = []
        self._initial_state = [] 

    def _inner_block(self, state):
        self._quarter_round(state, 0, 4, 8, 12)
        self._quarter_round(state, 1, 5, 9, 13)
        self._quarter_round(state, 2, 6, 10, 14)
        self._quarter_round(state, 3, 7, 11, 15)
        self._quarter_round(state, 0, 5, 10, 15)
        self._quarter_round(state, 1, 6, 11, 12)
        self._quarter_round(state, 2, 7, 8, 13)
        self._quarter_round(state, 3, 4, 9, 14)

    def _quarter_round(self, x, a, b, c, d):
        x[a] ^= x[b]; x[d] ^= x[a]; x[d] = rotate(x[d], 16)
        x[c] ^= x[d]; x[b] ^= x[c]; x[b] = rotate(x[b], 12)
        x[a] ^= x[b]; x[d] ^= x[a]; x[d] = rotate(x[d], 8)
        x[c] ^= x[d]; x[b] ^= x[c]; x[b] = rotate(x[b], 7)
    
    def _setup_state(self, key, iv):
        self._state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        self._state.extend(bytes_to_words(key))
        self._state.append(self._counter)
        self._state.extend(bytes_to_words(iv))
        
        self._initial_state = self._state[:] 

    def decrypt(self, c, key, iv):
        return self.encrypt(c, key, iv)

    def encrypt(self, m, key, iv):
        c = b''
        self._counter = 1

        for i in range(0, len(m), 64):
            self._setup_state(key, iv)
            
            # Chạy 20 vòng xáo trộn tuyến tính
            for j in range(10):
                self._inner_block(self._state)
            
            for k in range(16):
                self._state[k] ^= self._initial_state[k]

            c += xor(m[i:i+64], words_to_bytes(self._state))

            self._counter += 1
        
        return c



if __name__ == '__main__':
    FLAG = b'CTF{linear_algebra_is_fun_but_breaks_crypto}'
    msg = b'A'*64 + FLAG 
    
    key = urandom(32)
    iv = urandom(12)

    cipher = LinearChaCha20()
    flag_enc = cipher.encrypt(msg, key, iv)

    print(f"Nonce (IV)  : {iv.hex()}")
    print(f"Ciphertext  : {flag_enc.hex()}")