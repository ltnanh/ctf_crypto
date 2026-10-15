# ZKRSA


* Category: Crypto
* Difficulty : Easy - Medium 

## Chal Overview 

```python
from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long
from random import Random

A = 2**1000
B = 2**80

FLAG = "BKSEC{Blahaj}"

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
    print(x, e, y)
    return (x, e, y)

def verify(z, x, e, y, N):
    return 0 <= y < A and pow(z, y - N * e, N) == x

print("I can prove to you that I can factorize N without revealing any knowledge :D")
print("The protocol is so secured in fact, I will even give you the FLAG!!!")
N, PHI = keygen()
print(N)
r = Random(1337)
for _ in range(500):
    try:
        z = r.randrange(2, N)
        x, e, y = prove(z, N, PHI)
        assert verify(z, x, e, y, N)
    except Exception as E:
        print(f"ERR: {E}")
print("Here's your FLAG hehehe")
print(pow(bytes_to_long(FLAG), 65537, N))
```


Đây là 1 hệ ZKP dựa trên RSA. Server proof  nó biết cách phân tích nhân tử của mô-đun RSA $N$ mà không trực tiếp để lộ các số nguyên tố $p, q$ hay giá trị $\phi(N)$.



Challenge :Có 500 lượt, mỗi lượt client có thể gửi 1 giá trị $e$ tới server và nhận lại giá trị $x, y$:
* $x = z^r \pmod N$
* $y = r + (N - \phi(N)) \cdot e$

Với $z, r$ là 2 số random tương ứng với mỗi lượt . Ta cần phải dựa vào sample này để mà factor $N$ và decrypt flag bị mã hóa bỏi RSA 

## Attack Idea 
Ở mỗi vòng lặp, server trả về $y$:

Đặt $S = N - \phi(N) = p + q - 1$.
$$\Rightarrow y = r + S \cdot e$$

Ta thấy rằng, server chỉ cần giá trị $e < B = 2^{80}$ $\Rightarrow$ ta có thể gửi 1 số âm có giá trị tuyệt đối rất lớn.
Ví dụ: gửi $e = -A = -2^{1000}$ $\Rightarrow$ ta sẽ nhận lại $y$ là 1 giá trị âm lớn:
$$y = r - S \cdot A$$
$$\Rightarrow \frac{-y}{A} = S - \frac{r}{A}$$

Vì $r$ thường rất nhỏ so với $A$ $\Rightarrow \frac{r}{A} \approx 0 \Rightarrow \frac{-y}{A} \approx S$.
Vì vậy, ta có thể khôi phục $S$ chính xác 100% bằng cách chia làm tròn lên:
$S = \left\lceil \frac{-y}{A} \right\rceil$

Từ ý tưởng đó , ta có cách tấn công như sau : 
- Ở lượt đầu tiên, ta gửi giá trị $e = -A$, từ đó có thể lấy được giá trị của $S$:
$$S = \left\lceil \frac{-y}{A} \right\rceil$$
- Hàm verify ở serve sẽ ném ra lỗi, nhưng giá trị $y$ vẫn được gửi về và vòng lặp vẫn tiếp tục
- Ở các lượt sau, ta gửi các giá trị tùy ý cho đến khi lấy được ciphertext

- Sau khi có được $S$ từ vòng lặp đầu tiên , ta đã có $\Sigma = p + q = S + 1$. Khi này $p$ và $q$ là 2 nghiệm của phương trình bậc 2:$X^2 - \Sigma X + N = 0$ . Ta chỉ cần dùng công thức nghiệm giải pt này để tìm ra $p$ và $q$

- Có $p, q$, ta dễ dàng tính $\phi(N) = (p-1)(q-1)$ và khóa giải mã $d \equiv 65537^{-1} \pmod{\phi(N)}$ để decrypto flag $m \equiv c^d \pmod N$.

## Code exploit 

```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import math

context.log_level = 'error'

HOST = '127.0.0.1' 
PORT = 1337

A = 2**1000

r = remote(HOST, PORT)

r.recvline()
r.recvline()

N = int(r.recvline().strip())
print(f"N ={N}")

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
        print("Không nhận được FLAG")

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
```

Đây là kết quả thành công trên local server

```
N=167629805948328480856136662463024641078544529691492272664474940169464728000546260009523173466811359968916536687879188204759866327925891179582731061156232738902731111791596842791987178269624500992452823641069225953237087383044968734888184746389875147369211197267744646914195310550864372010990131043741023412271
146783221816191892832299181433716702896421731754997132955358938245262339518821028341445414172362993797673815785106931873973143584407734686950165723251703969194223859104640716116796457521713336617903799526816984305863361249467510375811532386148051196710157885384565862626449466229103636438730600643208795535543
25906298710408090870795323312593156135881716487327475646693436001925545300645964041921123146237490299054641066748402079570334742717567596771513191072756879
p = 13345924443383651307825783053348900030561990589036994089184077754058942705750224512019827345001244357228276340291843668986253908689641003932364724809374513
q = 12560374267024439562969540259244256105319725898290481557509358247866602594895739529901295801236245941826364726456558410584080834027926592839148466263382367
BKSEC{fake_flag_for_testing}
```