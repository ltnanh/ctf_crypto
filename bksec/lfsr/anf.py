def generate_anf(lfsr_idx, filter_val, extract_positions):
    k = len(extract_positions)
    # 1. Lập bảng chân trị (Truth Table) từ số nguyên Filter
    tt = [(filter_val >> i) & 1 for i in range(1 << k)]
    
    # 2. Thuật toán Fast Möbius Transform để tìm hệ số ANF
    anf = list(tt)
    for i in range(k):
        for j in range(1 << k):
            if (j & (1 << i)) != 0:
                anf[j] ^= anf[j ^ (1 << i)]
                
    print(anf)         
    # 3. Xây dựng phương trình đại số trực quan
    terms = []
    
    # Kiểm tra hệ số tự do
    if anf[0] == 1:
        terms.append("1")
        
    degree = 0 # Lưu bậc cao nhất của đa thức
    
    for j in range(1, 1 << k):
        if anf[j] == 1:
            term_vars = []
            # Đếm xem cụm này có bao nhiêu biến nhân với nhau (bậc của cụm)
            current_degree = bin(j).count('1')
            degree = max(degree, current_degree)
            
            for bit_idx in range(k):
                if (j >> bit_idx) & 1:
                    # Ánh xạ index ngược lại vị trí bit thực tế của LFSR state
                    state_pos = extract_positions[bit_idx]
                    term_vars.append(f"s_{state_pos}")
                    
            # Ghép các biến lại bằng phép nhân (AND logic)
            terms.append(" * ".join(term_vars))
            
    if not terms:
        equation = "0"
    else:
        # Các cụm được nối với nhau bằng phép cộng (XOR logic)
        equation = " +\n ".join(terms)
        
    print(f"[*] LFSR {lfsr_idx} (Trích xuất {k} bits: {extract_positions})")
    print(f"    Bậc đại số cao nhất (Degree): {degree}")
    print(f"    Phương trình: f(S) = {equation}\n")

# --- Dữ liệu từ đề bài ---
Filters = [
    43673535323473607050899647551732188151,
    69474900172976843852504521249820447513188207961992185137442753975916133181030,
    28448620439946980695145546319125628439828158154718599921182092785732019632576,
    16097126481514198260930631821805544393127389525416543962503447728744965087216,
    7283664602255916497455724627182983825601943018950061893835110648753003906240,
    55629484047984633706625341811769132818865100775829362141410613259552042519543,
    4239659866847353140850509664106411172999885587987448627237497059999417835603,
    106379335904610565198575784689340408012917012758379923896044369424798179675586
]

# Các vị trí trích xuất (từ hàm bit)
Extracts = {
    0: [5, 9, 1, 0, 4, 11, 13], # x
    2: [20, 2, 16, 11, 1, 23, 22, 8], # z
    3: [1, 46, 21, 7, 43, 0, 27, 39], # w
    4: [1, 3, 7, 4, 5, 0, 6, 2], # v
    8: [5, 8, 9, 3, 1, 0, 2, 4]  # t
}

print("--- PHÂN TÍCH ĐẠI SỐ HÀM BLUR & EXTRACT ---\n")
for idx, ext_pos in Extracts.items():
    # Lưu ý: Các filter của LFSR 5, 6, 7 (biến u) không dùng extract mà lấy nguyên state
    # nên filter index trong mảng Filters bị lệch một chút so với LFSR index.
    # Trong bài: blur(extract(LFSR0), 0) -> Filter 0
    # blur(extract(LFSR2), 1) -> Filter 1
    # blur(extract(LFSR3), 2) -> Filter 2
    # blur(extract(LFSR4), 3) -> Filter 3
    # blur(extract(LFSR8), 7) -> Filter 7
    
    filter_index_map = {0: 0, 2: 1, 3: 2, 4: 3, 8: 7}
    filter_idx = filter_index_map[idx]
    
    generate_anf(idx, Filters[filter_idx], ext_pos)










