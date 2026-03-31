# ZKRSA Revenger

## 1. Thông tin về thử thách

* **Challenge Name:** ZKRSA Revenger
* **Category:** Crypto

## 2. Mô tả
Files given: `ZKRSA-Revenger.py`

## 3. Phân tích đề bài
Zero-Knowledge Proof (ZKP). Máy chủ chứng minh rằng nó biết cách phân tích nhân tử của mô-đun RSA $N$ mà không trực tiếp để lộ các số nguyên tố $p, q$ hay giá trị $\phi(N)$.

**Tham số:**
* $A = 2^{1000}$
* $B = 2^{80}$
* $N = p \cdot q$ (Khóa RSA 1024-bit).

**Giao tiếp với serve:**
Có 500 lượt, mỗi lượt client có thể gửi 1 giá trị $e$ tới server và nhận lại giá trị `check`:
* $x = z^r \pmod N$
* $y = r + (N - \phi(N)) \cdot e$
* $check = \text{int}(\text{hashlib.sha256}(\text{str}(y).\text{encode}()).\text{hexdigest}(), 16) \pmod B$

($z, r$ là 2 số random tương ứng với mỗi lượt)

## 4. Điểm yếu quan sát được
Ở mỗi vòng lặp, server trả về `check` là giá trị của hàm băm:
* $\Rightarrow$ Giấu giá trị của $y$.
* Chia giá trị hash $\pmod B \Rightarrow$ giảm bit, khiến việc khai thác giá trị $y$ là không thể.

**Điều khác thường:** số $y$ đi qua hàm `str()` rồi mới chuyển về bytes: `str(y).encode()`.

### Lỗ hổng CVE-2020-10735 của Python
Từ phiên bản Python 3.11, Python áp đặt một giới hạn mặc định để chống tấn công DoS: Giới hạn độ dài chuyển đổi chuỗi số nguyên là **4300 chữ số thập phân**.

Nếu một số nguyên có từ 4301 chữ số trở lên, lệnh `str()` sẽ ném ra lỗi `ValueError`.
Kết hợp với khối `try...except` của server, ta có một **Error-Based Oracle**:

* Nếu độ dài $y < 4300$ chữ số $\rightarrow$ `str(y)` thành công $\rightarrow$ Server in ra `check`.
* Nếu độ dài $y \ge 4300$ chữ số $\rightarrow$ `str(y)` thất bại $\rightarrow$ Server in ra **ERR**.

Vậy nên ta có hướng khai thác như sau:
Đặt $S = N - \phi(N) \Rightarrow y = r - S \cdot A$.

Với việc truyền giá trị $e$ là 1 số âm rất lớn ($S \cdot e$ là 3100 chữ số), giá trị của $r$ gần như không tham gia vào việc xác định số digit của $y$.

$\Rightarrow$ Với mỗi giá trị $y_{guess}$, ta gửi cho server $e = -10^{3100} // y_{guess}$. Nếu mà server trả về `check`, tức là $y_{guess} > y$ và ngược lại nếu server trả về error thì $y_{guess} < y$.

Kết hợp với thuật toán **Binary Search** với cận trên và cân dưới của $y$ và $y_{guess} = mid$, ta có thể gửi lần lượt giá trị $e = -4^{3100} // mid$ và so sánh $mid$ với $y$ và thu hẹp dần 2 cận. Với 500 lượt so sánh thì 2 cận có thể thu hẹp thành 1 khoảng có thể brute force được.

## 5. Chiến lược tấn công

### Thuật toán Binary Search
Với 500 vòng lặp (tương đương 500 câu hỏi Có/Không), ta dùng Binary Search để ép khoảng giới hạn của $S$:

* Khởi tạo khoảng tìm kiếm: $S_{min} = \lfloor 2\sqrt{N} \rfloor$, $S_{max} = 2^{513}$.
* Mỗi vòng, lấy $S_{mid} = (S_{min} + S_{max}) // 2$.
* Gửi $e = -\lfloor 10^{4300} / S_{mid} \rfloor$.

**Nhận phản hồi:**
* Nếu có **ERR**: $|y| \ge 10^{4300} \Rightarrow S > S_{mid}$. Ta nâng cận dưới lên.
* Nếu có **check**: $|y| < 10^{4300} \Rightarrow S \le S_{mid}$. Ta hạ cận trên xuống.

Sau 500 vòng lặp, không gian mẫu của $S$ bị thu hẹp lại $2^{500}$ lần, chỉ còn lại khoảng $2^{513} / 2^{500} = 2^{13} = 8192$ trường hợp. Ta chỉ việc vét cạn (brute-force) phần còn lại offline.

### Khôi phục Khóa (Key Recovery)
Khi đã thu hẹp được khoảng chứa $S$ xuống còn vài nghìn giá trị:

* Duyệt qua từng ứng viên $S_{candidate}$.
* Tính tổng $\Sigma = p + q = S_{candidate} + 1$.
* $p$ và $q$ là 2 nghiệm của phương trình bậc 2:
$$X^2 - \Sigma X + N = 0$$
* Tính $\Delta = \Sigma^2 - 4N$.
* Nếu $\Delta$ là một số chính phương hoàn hảo, ta đã tìm đúng $p$ và $q$.
* Nghiệm tính theo công thức:
$$p = \frac{\Sigma + \sqrt{\Delta}}{2}, \quad q = \frac{\Sigma - \sqrt{\Delta}}{2}$$
* Có $p, q$, ta dễ dàng tính $\phi(N) = (p-1)(q-1)$ và khóa giải mã $d \equiv 65537^{-1} \pmod{\phi(N)}$.
* Giải mã cờ: $m \equiv c^d \pmod N$.

## 6. Code python

```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import math

HOST = '100.64.0.66' 
PORT = 31900    

r = remote(HOST, PORT)

r.recvline()
r.recvline()

N = int(r.recvline().strip())
print(f"N: {N}")

low = math.isqrt(N) * 2
high = 2**513

try:
    for i in range(500):
        r.recvuntil(b"CHALLENGE ME!!! ")

        mid = (low + high) // 2
        
        # Tạo e_val âm sao cho y = r - S*e_val xấp xỉ ngưỡng 10^4300
        e_val = -(10**4300 // mid)
        
        r.sendline(str(e_val).encode())
        
        response = r.recvline().decode().strip()
    
        if "ERR" in response:
            low = mid + 1
        else:
            high = mid
            
    r.recvuntil(b"Here's your FLAG hehehe\n")
    enc_flag = int(r.recvall().decode().strip())
    print(f"Encrypted flag: {enc_flag}")

except Exception as E:
    print(E)

finally:
    r.close()

p = 0
q = 0

# Brute-force offline các ứng viên S
for S_candidate in range(low, high + 1):
    p_plus_q = S_candidate + 1
    delta = p_plus_q**2 - 4 * N
    
    if delta < 0:
        continue
    sqrt_delta = math.isqrt(delta)
    if sqrt_delta**2 == delta:
        p = (p_plus_q + sqrt_delta) // 2
        q = (p_plus_q - sqrt_delta) // 2
        
        if p * q == N:
            print(f"Correct S found: {S_candidate}")
            break

if p and q:
    PHI = (p - 1) * (q - 1)
    e_rsa = 65537
    d = pow(e_rsa, -1, PHI)
    m = pow(enc_flag, d, N)
    
    print(long_to_bytes(m).decode())