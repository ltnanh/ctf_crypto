from sage.all import *


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
Z = vector(GF(2), known_bits)



def clock_sym(state, mask):
    fb = sum([state[i] for i in range(len(state)) if (mask >> i) & 1])
    return state[1:] + [fb]



print("[*] BƯỚC 1: Xây dựng Ma trận Tuyến tính (M) cho 374 biến ,640 eqn")
state_L1 = [vector(GF(2), 374, {i: 1}) for i in range(32)]
state_L2 = [vector(GF(2), 374, {32+i: 1}) for i in range(24)]

# Bóc tách cấu trúc tuyến tính của L2
tt2 = [(FILTERS[1] >> j) & 1 for j in range(256)]
C2_const = tt2[0]
C2_coeffs = [tt2[1<<i] ^^ C2_const for i in range(8)]

M = matrix(GF(2), 640, 374)
C2_vec = vector(GF(2), 640)

for i in range(640):
    row = vector(GF(2), 374)
    row += state_L1[0] # L1
    row += sum([C2_coeffs[k] * state_L2[E2[k]] for k in range(8)]) # L2
    C2_vec[i] = C2_const
    row[56 + (i % 63)] = 1 # V63
    row[119 + (i % 255)] = 1 # V255
    
    M[i] = row
    state_L1 = clock_sym(state_L1, MASKS[1])
    state_L2 = clock_sym(state_L2, MASKS[2])






print("[*] BƯỚC 2: Tính Left Null Space (Ma trận H)")
H = M.left_kernel().basis_matrix()
print(f"    -> Đã tạo ma trận H kích thước {H.nrows()} x {H.ncols()}")






# to gen feed forward stream for lfsr 0,8 and 1,2 
def gen_lfsr_stream(n, mask, filter_val, ext_pos, seed):
    state = seed
    stream = vector(GF(2), 640)
    for i in range(640):
        idx = 0
        for j, p in enumerate(ext_pos):
            if (state >> p) & 1: idx |= (1 << j)
        stream[i] = (filter_val >> idx) & 1
        fb = bin(state & mask).count('1') & 1
        state = (state >> 1) | (fb << (n - 1))
    return stream




print("[*] BƯỚC 3: Meet-in-the-Middle")
hash_L0 = {}
for seed0 in range(1, 1 << 14):
    stream0 = gen_lfsr_stream(14, MASKS[0], FILTERS[0], E0, seed0)
    Y0 = H * stream0
    hash_L0[tuple(Y0)] = seed0
print(f"      Đã co hashtable {len(hash_L0)} trạng thái của L0.")



seed_L0, seed_L8 = None, None
T = H * (Z + C2_vec)
for seed8 in range(1, 1 << 10):
    stream8 = gen_lfsr_stream(10, MASKS[8], FILTERS[7], E8, seed8)
    Y8 = H * stream8
    target_Y0 = Y8 + T
    
    if tuple(target_Y0) in hash_L0:
        seed_L0 = hash_L0[tuple(target_Y0)]
        seed_L8 = seed8
        print(f"      Seed L0 = {seed_L0}")
        print(f"      Seed L8 = {seed_L8}")
        break




print("[*] BƯỚC 4: Tạo Keystream L0, L8 và tính Right Hand Side (RHS) của hệ phương trình")

# 1. Sinh lại 2 keystream dài 640 bit từ seed vừa tìm được
stream0 = gen_lfsr_stream(14, MASKS[0], FILTERS[0], E0, seed_L0)
stream8 = gen_lfsr_stream(10, MASKS[8], FILTERS[7], E8, seed_L8)
    
# Trên GF(2), phép cộng chính là XOR
RHS = Z + C2_vec + stream0 + stream8
    




print("[*] BƯỚC 5: Giải hệ phương trình và trích xuất các initial state/period seq")

try:
    # Giải hệ phương trình M * X = RHS trên GF(2)
    X = M.solve_right(RHS)
   
    # 1. Trích xuất Seed L1 (32 bit đầu)
    seed_L1 = sum(int(X[i]) << i for i in range(32))
    
    # 2. Trích xuất Seed L2 (24 bit tiếp theo)
    seed_L2 = sum(int(X[32 + i]) << i for i in range(24))
    
    # 3. Trích xuất chuỗi 63 bit tuần hoàn của L3 ,L4
    seq_63 = [int(X[56 + i]) for i in range(63)]
    
    # 4. Trích xuất chuỗi 255 bit tuần hoàn của L5, L6, L7
    seq_255 = [int(X[119 + i]) for i in range(255)]
    
    print(f"       Seed L1 = {seed_L1}")
    print(f"       Seed L2 = {seed_L2}")
    print("       seq 63 = ",seq_63)
    print("       seq 255 = ",seq_255)

except ValueError:
    print("[!] Lỗi: Hệ phương trình vô nghiệm. Seed L0 và L8 có thể chưa chính xác!")
    sys.exit()






print("[*] BƯỚC 6: Khởi tạo Cipher và giải mã Token...")

extract = lambda x,b: sum(((int(x) >> p) & 1) << i for i, p in enumerate(b))
blur = lambda x,i: (FILTERS[i] >> int(x)) & 1

class LFSR:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = int(key) & ((1 << n) - 1)
        self.mask = int(mask)

    def __call__(self):
        b = self.state & 1
        fb = int(self.state & self.mask).bit_count() & 1
        self.state = (self.state >> 1) | (fb << (self.n - 1))
        return b

class Cipher:
    def __init__(self, s0, s1, s2, s8, seq63, seq255):
        self.lfsr0 = LFSR(Ns[0], s0, MASKS[0])
        self.lfsr1 = LFSR(Ns[1], s1, MASKS[1])
        self.lfsr2 = LFSR(Ns[2], s2, MASKS[2])
        self.lfsr8 = LFSR(Ns[8], s8, MASKS[8])
        
        self.seq63 = seq63
        self.seq255 = seq255
        self.clock = 0

    def bit(self):
        x = blur(extract(self.lfsr0.state, E0), 0)
        y = self.lfsr1.state & 1
        z = blur(extract(self.lfsr2.state, E2), 1)
        t = blur(extract(self.lfsr8.state, E8), 7)
        
        w_v = int(self.seq63[self.clock % 63])
        u = int(self.seq255[self.clock % 255])
        
        self.lfsr0()
        self.lfsr1()
        self.lfsr2()
        self.lfsr8()
        self.clock += 1
        
        return x ^^ y ^^ z ^^ w_v ^^ u ^^ t

    def stream(self):
        while True:
            b = 0
            for i in reversed(range(8)):
                b |= self.bit() << i
            yield b

    def decrypt(self, ct: bytes):
        return bytes([int(c) ^^ int(k) for c, k in zip(ct, self.stream())])

cipher = Cipher(seed_L0, seed_L1, seed_L2, seed_L8, seq_63, seq_255)
decrypted_bytes = cipher.decrypt(ct_bytes)
if decrypted_bytes[:80] == b"\x00" * 80:
    token = decrypted_bytes[80:]
    print(f"FLAG TOKEN : {token.hex()}")
else:
    print("80 bytes đầu không khớp với padding gốc!")