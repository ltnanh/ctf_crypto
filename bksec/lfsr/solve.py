import time
import numpy as np
import galois



# --- CÁC HẰNG SỐ CỦA BÀI (Rút gọn để test) ---
Ns = [14, 32, 24, 48, 8, 8, 8, 8, 10]
MASKS = [1959, 3487505359, 12175963, 144894747199363, 39, 101, 99, 43, 579]
FILTERS = [
    43673535323473607050899647551732188151,
    69474900172976843852504521249820447513188207961992185137442753975916133181030,
    28448620439946980695145546319125628439828158154718599921182092785732019632576,
    16097126481514198260930631821805544393127389525416543962503447728744965087216,
    7283664602255916497455724627182983825601943018950061893835110648753003906240,
    55629484047984633706625341811769132818865100775829362141410613259552042519543,
    4239659866847353140850509664106411172999885587987448627237497059999417835603,
    106379335904610565198575784689340408012917012758379923896044369424798179675586
]
E0 = [5, 9, 1, 0, 4, 11, 13]
E2 = [20, 2, 16, 11, 1, 23, 22, 8]
E8 = [5, 8, 9, 3, 1, 0, 2, 4]




ct_hex = "be547e84aad5699545f9e2a8aead70b72665b136e05e971a2687ea1cfc564b8aaf639c6fd3b315145348aa65eefb5b69e04d1ee47656497cf994602a7c5ff7b15348bec4a79b4288bc0b6fcc86c437d9dc6be9a71eacb1ef81e8f683123f0e" 
ct_bytes = bytes.fromhex(ct_hex)
known_bits = [(byte >> i) & 1 for byte in ct_bytes[:80] for i in reversed(range(8))]



GF2 = galois.GF(2)



def clock_linear(state_vars, n, mask):
    fb = GF2.Zeros(374)
    for i in range(n):
        if (mask >> i) & 1: fb ^= state_vars[i]
    return state_vars[1:] + [fb]



def gen_raw_stream(n, mask, filter_val, ext_pos, seed, length=640):
    state = seed
    stream = np.zeros(length, dtype=int)
    for i in range(length):
        idx = sum(((state >> p) & 1) << j for j, p in enumerate(ext_pos))
        stream[i] = (filter_val >> idx) & 1
        fb = bin(state & mask).count('1') & 1
        state = (state >> 1) | (fb << (n - 1))
    return GF2(stream)



# L0 và L8 đã có từ MITM
found_0 = 14276 
found_8 = 994 


print("[*] 1. Khởi tạo Ma trận M (374 biến)...")
tt2 = [(FILTERS[1] >> j) & 1 for j in range(256)]
C2_const = tt2[0]
C2_coeffs = [tt2[1 << j] ^ C2_const for j in range(8)]

M = GF2.Zeros((640, 374))
s1 = [GF2.Zeros(374) for _ in range(32)]; [s1[i].__setitem__(i, 1) for i in range(32)]
s2 = [GF2.Zeros(374) for _ in range(24)]; [s2[i].__setitem__(32+i, 1) for i in range(24)]



for i in range(640):
    row = s1[0].copy()
    for j in range(8):
        if C2_coeffs[j]: row ^= s2[E2[j]]
    row[56 + (i % 63)] ^= 1
    row[119 + (i % 255)] ^= 1
    M[i] = row
    s1 = clock_linear(s1, 32, MASKS[1])
    s2 = clock_linear(s2, 24, MASKS[2])




print("[*] 2. Tính toán Vector vế phải (RHS)...")
stream_L0 = gen_raw_stream(14, MASKS[0], FILTERS[0], E0, found_0)
stream_L8 = gen_raw_stream(10, MASKS[8], FILTERS[7], E8, found_8)
RHS = GF2(known_bits) ^ GF2(C2_const) ^ stream_L0 ^ stream_L8



print("[*] 3. Giải hệ bằng Khử Gauss và Trích xuất nghiệm CHUẨN...")
augmented_matrix = np.column_stack((M, RHS))
rref = GF2(augmented_matrix).row_reduce()





X_sol = GF2.Zeros(374)
for i in range(rref.shape[0]):
    # Tìm cột khác 0 đầu tiên (chính là Pivot)
    nonzero_cols = np.nonzero(rref[i, :374])[0]
    if len(nonzero_cols) > 0:
        pivot_idx = nonzero_cols[0]
        # Gán đúng giá trị vế phải cho biến Pivot đó
        X_sol[pivot_idx] = rref[i, 374]


# Tách biến
seed_L1_bits = X_sol[0:32].tolist()
seed_L2_bits = X_sol[32:56].tolist()
v63_buffer = X_sol[56:119].tolist()
v255_buffer = X_sol[119:374].tolist()

s1_val = sum((b << i) for i, b in enumerate(seed_L1_bits))
s2_val = sum((b << i) for i, b in enumerate(seed_L2_bits))




print("[*] 4. Bắt đầu giải mã Token...")
class LazyCipher:
    def __init__(self, s0, s1, s2, s8, v63, v255):
        self.states = [s0, s1, s2, s8]
        self.v63, self.v255 = v63, v255
        self.clock = 0
    def bit(self):
        ext = lambda val, b: sum(((val >> p) & 1) << i for i, p in enumerate(b))
        x = (FILTERS[0] >> ext(self.states[0], E0)) & 1
        y = self.states[1] & 1
        z = (FILTERS[1] >> ext(self.states[2], E2)) & 1
        t = (FILTERS[7] >> ext(self.states[3], E8)) & 1
        wv = self.v63[self.clock % 63]
        u = self.v255[self.clock % 255]
        
        for i, (n, m) in enumerate([(14, MASKS[0]), (32, MASKS[1]), (24, MASKS[2]), (10, MASKS[8])]):
            fb = bin(self.states[i] & m).count('1') & 1
            self.states[i] = (self.states[i] >> 1) | (fb << (n - 1))
        self.clock += 1
        return x ^ y ^ z ^ wv ^ u ^ t

    def decrypt(self, data):
        res = []
        for d in data:
            byte = 0
            for i in reversed(range(8)):
                byte |= (self.bit() << i)
            res.append(d ^ byte)
        return bytes(res)




cipher = LazyCipher(found_0, s1_val, s2_val, found_8, v63_buffer, v255_buffer)
cipher.decrypt(b"\x00" * 80) # Bỏ qua Keystream đã biết
token_bytes = cipher.decrypt(ct_bytes[80:])

print("-" * 55)
print(f"[+] TOKEN (HEX) CHUẨN XÁC: {token_bytes.hex()}")
print("-" * 55)