# LFSR

## 1 Thông tin về thử thách

Challenge Name : ZKRSA Revenger  
Category : Crypto  

---

## 2. Mô tả

files given: `gen.py`

---

## 3 . Phân tích đề bài

Đối tượng mã hóa Cipher bao gồm **9 bộ LFSR với độ dài khác nhau**

với mỗi lfsr gồm :

- state: Trạng thái hiện tại của thanh ghi.
- mask: Xác định các vị trí (taps) để thực hiện phép XOR nhằm tạo ra bit phản hồi.

chu kì của các bộ lfsr này sẽ tạo bit feed back như truyền thống

```python
def __call__(self):
    b = self.state & 1
    self.state = (self.state >> 1) | (
        ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
    )
    return b
```

---

## Tạo keystream phi tuyến tính (hàm bit())

- `extract(x, b)` : Trích xuất các bit tại các vị trí cụ thể `b` từ trạng thái `x` để tạo thành một số nguyên mới.  
- `blur(x, i)` : Sử dụng số nguyên vừa trích xuất làm chỉ số (index) để lấy một bit từ danh sách `Filters`.

với mỗi bộ lfsr tại clock `i` với state tương ứng sẽ thông qua các các hàm này để trích xúât ra một bit tương ứng để tham giá xor tạo feedforward bit

```python
x = blur(extract(self.lfsrs[0].state, [5, 9, 1, 0, 4, 11, 13]), 0)
y = self.lfsrs[1].state & 1
z = blur(extract(self.lfsrs[2].state, [20, 2, 16, 11, 1, 23, 22, 8]), 1)
w = blur(extract(self.lfsrs[3].state, [1, 46, 21, 7, 43, 0, 27, 39]), 2)
v = blur(extract(self.lfsrs[4].state, [1, 3, 7, 4, 5, 0, 6, 2]), 3)
u = blur(self.lfsrs[5].state, 4) ^ blur(self.lfsrs[6].state, 5) ^ blur(self.lfsrs[7].state, 6)
t = blur(extract(self.lfsrs[8].state, [5, 8, 9, 3, 1, 0, 2, 4]), 7)

for lfsr in self.lfsrs:
    lfsr()

return x ^ y ^ z ^ w ^ v ^ u ^ t
```

==> tính phi tuyến của hệ mã

---

## Tương tác với server

server sẽ encrypt 1 token để gửi cho client.

nếu client có thể giải mã ciphertext để lấy token gửi lại cho server, client sẽ lấy được flag nếu token đúng.

```python
print("ct:", cipher.encrypt(b"\x00"*80+tk).hex())

if input("Gimme Token: ") == tk.hex():
    print("Here is your flag:", SECRET_FLAG)
```

---

# 3 , Những điểm quan sát được

## Known plaintext attack

server chèn **80 bytes 00** đầu vào token trước khi giải mã.

với mật mã dòng *(plaintext xor keystream)*:

80 bytes đầu của ciphertext chính là của keystream  
=> manh mối để giải bài toán.

Ta có thể lập **1 hệ phương trình 640 ẩn**.

nếu ta có thể biểu diễn được feed forward của lfsr bằng 1 quan hệ tuyến tính giữa các biến bit  
=> ta có thể giải hệ phương trình tuyến tính bằng **Gauss**

---

## Quan sát chu kì của các bộ lfsr

có state của các bộ lfsr  
=> có đa thức đặc trưng của lfsr  
=> có thể tính toán được chu kì

```python
Ns = [14, 32, 24, 48, 8, 8, 8, 8, 10]
MASKS = [1959, 3487505359, 12175963, 144894747199363, 39, 101, 99, 43, 579]

def get_polynomial(n, mask):
    terms = [f"x^{n}"]
    for i in reversed(range(n)):
        if (mask >> i) & 1:
            if i == 0:
                terms.append("1")
            elif i == 1:
                terms.append("x")
            else:
                terms.append(f"x^{i}")
    return " + ".join(terms)

def simulate_period(n, mask):

    # Chỉ giả lập đếm chu kỳ cho các LFSR có số bit <= 24
    if n > 24:
        return "Quá lớn để giả lập vét cạn (Cần dùng toán học GF(2))"

    start_state = 1
    state = start_state
    period = 0

    while True:

        # Cơ chế LFSR y hệt trong đề bài
        state = (state >> 1) | (((state & mask).bit_count() & 1) << (n - 1))
        period += 1

        if state == start_state:
            break

    return period

print("--- PHÂN TÍCH LFSR ---")

for i, (n, mask) in enumerate(zip(Ns, MASKS)):

    poly = get_polynomial(n, mask)
    max_period = (1 << n) - 1

    print(f"[*] LFSR {i} (N={n})")
    print(f"    Mask: {mask}")
    print(f"    Đa thức: {poly}")
    print(f"    Chu kỳ tối đa (2^{n} - 1): {max_period}")

    actual_period = simulate_period(n, mask)
    print(f"    Chu kỳ thực tế: {actual_period}")

    if actual_period == max_period:
        print("    => Đa thức NGUYÊN THỦY (Primitive Polynomial)")
    elif isinstance(actual_period, int):
        print("    => Đa thức KHÔNG nguyên thủy (Chu kỳ ngắn)")

    print("-" * 50)
```

đoạn code giả lập bộ lfsr để đếm và tìm chu kì.

Ta sẽ quan sát được **1 số lfsr có chu kì ngắn (<640)**

```
[*] LFSR 4 (N=8)
Mask: 39
Đa thức: x^8 + x^5 + x^2 + x + 1
Chu kỳ tối đa (2^8 - 1): 255
Chu kỳ thực tế: 63
=> Đa thức KHÔNG nguyên thủy (Chu kỳ ngắn)
```

---

=> với các bộ lfsr này, **bit forward để xor và bit key cũng sẽ theo chu kì**

Ví dụ với **lfsr 4**

các bit forward tạo thành chu kì

```
f0, f1, … , f63
```

để tạo thành biến trong hệ phương trình **640 ẩn**

vì tại mỗi clock thì **1 trong các biến này sẽ xor tạo key bit**

---

với **lfsr 5,6,7**

có cùng chu kì **255**

bit forward của mỗi cái đều xor với nhau *(tạo thành bit u trong code)* trước khi xor tạo key.

=> bộ 3 này tạo thành **1 chu kì 255 bit**

=> thêm **255 biến trong hệ phương trình**

---

# Biểu diễn đại số cho feedforward của các lfsr

Các con số khổng lồ trong mảng **Filters** trông có vẻ ngẫu nhiên.

Nhưng thực chất chúng chính là **Bảng chân trị (Truth Table)**

- Khi hàm `extract` ghép **8 bit** lại thành số nguyên `X` *(0 → 255)*
- `(Filters[i] >> X) & 1` chính là hành động tra cứu bit thứ `X`

Biến đổi **Möbius (Fast Algebraic Transform)** giúp chuyển bảng chân trị sang **đa thức đại số**

```python
def generate_anf(lfsr_idx, filter_val, extract_positions):

    k = len(extract_positions)

    tt = [(filter_val >> i) & 1 for i in range(1 << k)]

    anf = list(tt)

    for i in range(k):
        for j in range(1 << k):
            if (j & (1 << i)) != 0:
                anf[j] ^= anf[j ^ (1 << i)]

    terms = []

    if anf[0] == 1:
        terms.append("1")

    degree = 0

    for j in range(1, 1 << k):

        if anf[j] == 1:

            term_vars = []

            current_degree = bin(j).count('1')
            degree = max(degree, current_degree)

            for bit_idx in range(k):

                if (j >> bit_idx) & 1:

                    state_pos = extract_positions[bit_idx]
                    term_vars.append(f"s_{state_pos}")

            terms.append(" * ".join(term_vars))

    if not terms:
        equation = "0"
    else:
        equation = " + ".join(terms)

    print(f"[*] LFSR {lfsr_idx}")
    print(f"Degree: {degree}")
    print(f"f(S) = {equation}\n")
```

---

chạy code sẽ ra kết quả với **lfsr 2**

```
[*] LFSR 2
Degree: 1
f(S) = s_20 + s_2 + s_1 + s_23 + s_8
```

=> feedforward có thể **biểu diễn tuyến tính**

=> thêm **24 ẩn bit của lfsr 2 vào hệ phương trình**

---

## Trường hợp đặc biệt

**lfsr 1**

implement theo cách chuẩn của lfsr và lấy bit thấp nhất làm feedforward

=> biểu diễn tuyến tính

=> thêm **32 ẩn bit vào hệ phương trình**

---

# 4 Hướng có thể của bài

với những phân tích trên của hệ

ta đã tạo ra được

```
374 ẩn / 640 phương trình
```

các ẩn còn lại có cấu trúc khá phức tạp.

có thể đặt ẩn:

```
y1 = x1 * x2
```

nhưng sẽ khó khi cập nhật feedback.

---

## Hướng giải

có thể dùng các thuật toán tối ưu

- meet in the middle
- branch and bound

để tìm **keystream trong thời gian cho phép**