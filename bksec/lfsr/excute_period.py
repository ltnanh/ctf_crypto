import time

Ns = [14, 32, 24, 48, 8, 8, 8, 8, 10]
MASKS = [1959, 3487505359, 12175963, 144894747199363, 39, 101, 99, 43, 579]

def simulate_period(n, mask, timeout=10):
    start_state = 1
    state = start_state
    period = 0
    start_time = time.time()
    
    while True:
        state = (state >> 1) | (((state & mask).bit_count() & 1) << (n - 1))
        period += 1
        
        if state == start_state:
            return period
            
        #  Chỉ check thời gian mỗi 100.000 vòng lặp
        if period % 100000 == 0:
            if time.time() - start_time > timeout:
                return f"Timeout, Đã chạy được {period} bước"


for i, (n, mask) in enumerate(zip(Ns, MASKS)):
    print(f"LFSR {i} (N={n:<2}) ", end=" ", flush=True)
    actual_period = simulate_period(n, mask, 10)
    print(f" => Chu kỳ: {actual_period}")