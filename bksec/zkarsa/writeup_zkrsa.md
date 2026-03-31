# ZKRSA

## 1 Thông tin về thử thách

* **Challenge Name:** ZKRSA
* **Category:** Crypto

## 2. Mô tả
Files given: `ZKRSA.py`

## 3. Phân tích đề bài
Zero-Knowledge Proof (ZKP). Máy chủ chứng minh rằng nó biết cách phân tích nhân tử của mô-đun RSA $N$ mà không trực tiếp để lộ các số nguyên tố $p, q$ hay giá trị $\phi(N)$.

**Tham số:**
* $A = 2^{1000}$
* $B = 2^{80}$
* $N = p \cdot q$ (Khóa RSA 1024-bit).

**Giao tiếp với serve:**
Có 500 lượt, mỗi lượt client có thể gửi 1 giá trị $e$ tới server và nhận lại giá trị $x, y$:
* $x = z^r \pmod N$
* $y = r + (N - \phi(N)) \cdot e$

($z, r$ là 2 số random tương ứng với mỗi lượt)

## 4. Điểm yếu quan sát được
Ở mỗi vòng lặp, server trả về $y$:

Đặt $S = N - \phi(N) = p + q - 1$.
$$\Rightarrow y = r + S \cdot e$$

Ta thấy rằng, server chỉ cần giá trị $e < B = 2^{80}$ $\Rightarrow$ ta có thể gửi 1 số âm có giá trị tuyệt đối rất lớn.
Ví dụ: gửi $e = -A = -2^{1000}$ $\Rightarrow$ ta sẽ nhận lại $y$ là 1 giá trị âm lớn:
$$y = r - S \cdot A$$
$$\Rightarrow \frac{-y}{A} = S - \frac{r}{A}$$

Vì $r$ thường rất nhỏ so với $A$ $\Rightarrow \frac{r}{A} \approx 0 \Rightarrow \frac{-y}{A} \approx S$.
Vì vậy, ta có thể khôi phục $S$ chính xác 100% bằng cách chia làm tròn lên:
$$S = \left\lceil \frac{-y}{A} \right\rceil$$

## 5. Chiến lược tấn công
- Ở lượt đầu tiên, ta gửi giá trị $e = -A$, từ đó có thể lấy được giá trị của $S$:
$$S = \left\lceil \frac{-y}{A} \right\rceil$$
(Hàm verify ở serve sẽ ném ra lỗi, nhưng giá trị $y$ vẫn được gửi về và vòng lặp vẫn tiếp tục).
- Ở các lượt sau, ta gửi các giá trị tùy ý (1) cho đến khi lấy được ciphertext.

### Khôi phục Khóa (Key Recovery)
Sau khi có được $S$ từ vòng lặp đầu tiên:

1. Tính tổng 2 số nguyên tố: $\Sigma = p + q = S + 1$.
2. $p$ và $q$ là 2 nghiệm của phương trình bậc 2:
   $$X^2 - \Sigma X + N = 0$$
3. Tính : $\Delta = \Sigma^2 - 4N$.
4. Tính nghiệm:
   $$p = \frac{\Sigma + \sqrt{\Delta}}{2}, \quad q = \frac{\Sigma - \sqrt{\Delta}}{2}$$

Có $p, q$, ta dễ dàng tính $\phi(N) = (p-1)(q-1)$ và khóa giải mã $d \equiv 65537^{-1} \pmod{\phi(N)}$.
Giải mã cờ: $m \equiv c^d \pmod N$.

## 6. Code python

```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import math

HOST = '100.64.0.66' 
PORT = 31700        

A = 2**1000

r = remote(HOST, PORT)

r.recvline()
r.recvline()

N = int(r.recvline().strip())
print(f"N: {N}")

malicious_y = 0
enc_flag = 0 

try:
    for i in range(500):
        r.recvuntil(b"CHALLENGE ME!!! ")

        if i == 0:
            e_challenge = -A
        else:
            e_challenge = 1 

        r.sendline(str(e_challenge).encode())

        response = r.recvline().decode().strip().split()

        x_val, e_val, y_val = map(int, response)
        if i == 0:
            malicious_y = y_val

    r.recvuntil(b"Here's your FLAG hehehe\n")
    flag_data = r.recvall().decode().strip() 
    
    if flag_data:
        enc_flag = int(flag_data)
        print(enc_flag) 
    else: 
        print("Không nhận được FLAG!")

except Exception as e:
    print(f"Server đóng kết nối hoặc lỗi: {e}")

finally:
    r.close()

S = (-malicious_y + A - 1) // A
print(S)

p_plus_q = S + 1

delta = p_plus_q**2 - 4 * N

sqrt_delta = math.isqrt(delta)

p = (p_plus_q + sqrt_delta) // 2
q = (p_plus_q - sqrt_delta) // 2

print(f"p = {p}")
print(f"q = {q}")

if p * q == N:
    PHI = (p - 1) * (q - 1)
    e_rsa = 65537

    d = pow(e_rsa, -1, PHI)
    m = pow(enc_flag, d, N)

    print(long_to_bytes(m).decode())