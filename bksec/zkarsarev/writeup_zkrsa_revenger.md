# ZKRSA Revenger

* Category: Crypto
* Difficulty : Medium

## Chal Overview

```python
from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long, long_to_bytes
from random import Random
import os
import hashlib

A = 2**1000
B = 2**80

FLAG = b"BKSEC{Evil_Blahaj}"

def keygen():
    p = getPrime(512)
    q = getPrime(512)
    N = p * q
    PHI = (p - 1) * (q - 1)
    return N, PHI

def prove(z, N, PHI):
    r = getRandomRange(0, A)
    x = pow(z, r, N)
    e = int(input("CHALLENGE ME!!! "))
    if e >= B:
        raise ValueError("I refuse to prove that D:<!!!")
    y = r + (N - PHI) * e
    check = int(hashlib.sha256(str(y).encode()).hexdigest(), 16) % B
    return (x, e, y, check)

def verify(z, x, e, y, N):
    return 0 <= y < A and pow(z, y - N * e, N) == x

print("Your mathematics shenanigans (should) not work this time... My Blahaj hath fixedyour antics!!!")
print("No more knowledge. No more negativity. Truly (maybe) secured")
N, PHI = keygen()
print(N)
r = Random(int.from_bytes(os.urandom(8), 'big'))
for _ in range(500):
    try:
        z = r.randrange(2, N)
        x, e, y, check = prove(z, N, PHI)
        print(check) # This should be enough, right...?
    except Exception as E:
        print(f"ERR: {E}")
print("Here's your FLAG hehehe")
print(pow(bytes_to_long(FLAG), 65537, N))
```
Đây là phiên bản nâng cấp của challenge ZKRSA trước. Công thức tạo proof vẫn là $y = r + (N - \phi(N))e$, nhưng server không in trực tiếp $x, e, y$ nữa mà chỉ in một giá trị `check` tính từ hash của $y$. Seed để sinh $z$ cũng được lấy từ `os.urandom` thay vì cố định. Vì vậy, cách gửi $e = -2^{1000}$ rồi chia ngược từ $y$ ở bài trước không còn dùng được.

Challenge: Ta vẫn có 500 lượt gửi giá trị $e$ tới server. Với mỗi lượt, server tính:
* $x = z^r \pmod N$
* $y = r + (N - \phi(N)) \cdot e$
* $check = \operatorname{SHA256}(\operatorname{str}(y).\operatorname{encode}()) \bmod 2^{80}$

Trong đó $z, r$ được sinh mới ở mỗi lượt. Ta chỉ nhận được `check` hoặc thông báo lỗi; sau 500 lượt server mới gửi ciphertext của flag. Mục tiêu vẫn là tìm $p, q$ để giải mã RSA.

## Attack Idea

Đặt $S = N - \phi(N) = p + q - 1$, khi đó $y = r + S \cdot e$. 

Việc sửa các bug của chal cũ khiến cho việc sử dụng toán học để khai thác trở nên bế tắc . Tuy nhiên , 1 ý tưởng rất hay hiện ra khi tôi để ý việc hash $y$ để tạo ra `check`. Server phải gọi `str(y)` trước khi băm nó , và 1 giới hạn của hàm `str(y)` trong Python chỉ ra bug của bài này . Với Python 3.11+ ở cấu hình mặc định, phép chuyển số nguyên sang chuỗi chỉ cho phép tối đa 4300 chữ số thập phân. Vì vậy `str(y)` ném `ValueError` nếu $|y| \ge 10^{4300}$. Lỗi này nằm trong khối `try...except`, nên ta có một oracle từ phản hồi của server:
* Nếu $|y| < 10^{4300}$, server in ra `check`.
* Nếu $|y| \ge 10^{4300}$, server in ra `ERR`.

Ta có thể dùng oracle này để so sánh $S$ với một giá trị đoán $mid$. Đặt $T = 10^{4300}$ và gửi:
$$e = -\left\lfloor \frac{T-1}{mid} \right\rfloor$$

Khi đó $y = r - S\lfloor (T-1)/mid \rfloor$. Ta dùng $T-1$ để trường hợp $S = mid$ luôn nằm dưới ngưỡng lỗi. Vì $0 \le r < 2^{1000}$, còn $T/mid$ lớn hơn rất nhiều, $r$ không làm thay đổi kết quả so sánh:
* Nếu $S \le mid$, ta có $|y| < T$, server in `check`.
* Nếu $S > mid$, ta có $|y| \ge T$, server in `ERR`.

Từ ý tưởng đó, ta dùng 500 lượt để binary search $S$:
- Ban đầu, $low = 2\lfloor\sqrt{N}\rfloor$ vì $p + q \ge 2\sqrt{N}$; chọn $high = 2^{513}$ vì $p, q$ đều là số nguyên tố 512 bit.
- Mỗi lượt lấy $mid = \lfloor(low + high)/2\rfloor$, gửi $e = -\lfloor(T-1)/mid\rfloor$.
- Nếu nhận `ERR`, đặt $low = mid + 1$; nếu nhận `check`, đặt $high = mid$.

Sau 500 lượt, khoảng cần tìm chỉ còn cỡ $2^{513-500} = 2^{13}$ giá trị. Ta có thể brute từng giá trị $S$ còn lại để tìm $p, q$ 

## Code exploit

```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import math

context.log_level = 'error'

HOST = '127.0.0.1'
PORT = 1337

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
        e_val = -((10**4300 - 1) // mid)

        r.sendline(str(e_val).encode())
        response = r.recvline().decode().strip()

        if "ERR" in response:
            low = mid + 1
        else:
            high = mid


    r.recvuntil(b"Here's your FLAG hehehe\n")
    enc_flag = int(r.recvall().decode().strip())
    print("Enc flag: ",enc_flag)

except Exception as E:
    print(E)

finally:
    r.close()

p = 0
q = 0


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
            break

if p and q:

    PHI = (p - 1) * (q - 1)
    e_rsa = 65537
    d = pow(e_rsa, -1, PHI)
    m = pow(enc_flag, d, N)

    print(long_to_bytes(m).decode())
```

Đây là kết quả thành công trên local server:

```
N:145969836915009028574884415219575953536366858889859356205542800445012138778425447433430313614471191573042943247039847180900962456896321305446838629594099890867237667420048577051350014585983463460901655558009198513004857165769770261027305485378749318791174847807561607256956580207610294822304775420574328597859
Enc flag:  112464274008268880605434356398753809883465308334599653876167892486876139832193670508490084518595728094457599189032901987219007080818043707274744430752113529399094996908964109352705072602691654039862086507316771400071154180553222046073605971076713364775178406587509920671003448338664291790775272746012258247888
BKSEC{Evil_Blahaj}
```
