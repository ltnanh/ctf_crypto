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



