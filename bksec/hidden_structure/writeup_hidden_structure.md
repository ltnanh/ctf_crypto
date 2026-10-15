# Hidden Structure

* Category: Crypto
* Difficulty : Easy 

## Chal Overview 
Đây là hệ mật mã hóa RSA với quá trình generate key khác thường 

```python
from secrets import randbits
from Crypto.Util.number import *
  
flag = bytes_to_long(b"BKSEC{fake_flag}") # you lose aura if you submit this... (we are watching)

B = 1 << 256

def r256():
    x = randbits(256) | (1 << 255) | 1  
    return x

while True:
    x, y = r256(), r256()
    p = x * B + y       
    q = y * B + x       
    if isPrime(p) and isPrime(q):
        break

e = 65537
N = p * q
c = pow(flag, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{c = }")
```


Nhiệm vụ của ta là decrypt ra flag từ ciphertex được cho $c = flag^e \pmod N$

## Attack Idea 

Chắc chắn ta sẽ khai thác bất thường trong việc chọn các tham số của hệ mật:


$$p = x \cdot 2^{256} + y$$

$$q = y \cdot 2^{256} + x$$

Khi viết dưới dạng nhị phân, $p$ và $q$ sẽ có tính chất đối xứng: $x || y$ và $y || x$. Điều này dẫn đến $N$ sẽ có cấu trúc bit đặc biệt. Ta có:

$$N = p \cdot q = (xB + y)(yB + x)$$

$$N = B^2xy + B(x^2 + y^2) + xy$$

Với các số được viết dưới dạng nhị phân:

* $B^2xy = aa...aaa0000...0000$ (có 512 bit 0 ở cuối).
* $xy = aaa...aaa$ (khoảng 512 đến 513 bit).
* $B(x^2 + y^2) = bbb...bb000...000$ (có 256 bit 0 ở cuối).

Ta thấy rằng khi tổng 3 giá trị lại, 256 bit cuối của $N$ chính là 256 bit cuối của $xy$. 256 bit đầu của $N$ gần như tương ứng với 256 bit đầu của $xy$. Từ đó ta có thể lấy được giá trị của $xy$, từ đó khôi phục giá trị của $x, y$ và cuối cùng là $p, q$


Đầu tiên ta cần khôi phục $xy$ . Lấy 256 bit cuối của $N$ chính là 256 bit cuối của $xy$. 256 bit đầu của $xy$ gần bằng 256 bit đầu của $N$ vì $B(x^2 + y^2)$ có thể tạo ra carry sang phần high bits. Ta có thể brute-force một khoảng nhỏ quanh giá trị ước lượng.


Sau khi có các giá trị khả thi của $xy$ (gọi là $P$), ta có $x^2 + y^2 = \frac{N - P(B^2 + 1)}{B}$ .Từ đó tính tổng $S = x + y$ : 

$$S^2 = (x^2 + y^2) + 2P$$

Nếu $S^2$ là một số chính phương , giá trị $S$ là hợp lệ.

Cuối cùng sau khi biết $x + y = S$ và $xy = P$ , ta giải pt bậc 2 để tìm $x$ , $y$

$$t^2 - St + P = 0$$


## Code  Exploit

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes

def recover_xy(S, P):
    D = S*S - 4*P
    if D < 0:
        return None

    r = isqrt(D)
    if r*r != D:
        return None

    x = (S + r) // 2
    y = (S - r) // 2

    return x, y

N = 107444638859099155759777187090231262569833054720517547475456101236477286061642951211232522980016935214117151901316067288134076019258357378153815894696105422994651894516549086845637403949534145390050746353299397783409065996987527927026314423191436300386280922075865669873754956335784354470237039709346406222789
e = 65537
c = 56143710973900761339774002971192037727375234874650436422245945684342980716505499471085786012340621409106405319356586450688993792522513823502401085339774194961300841598824881056390845294225756335102709315028822707701848497421372062559501439381841852116763699839771135406441292657937478625029095325072727620068

B = 1 << 256
bin_N = bin(N)[2:].zfill(1024)

# lấy low 256 bits của xy
low_xy = int(bin_N[-256:], 2)


# brute bits
for shift in range(-8, 9):
    approx_high = int(bin_N[:256], 2) + shift

    for mid in [0,1]:
        xy = (approx_high << 256) | (mid << 255) | low_xy
        rem = N - xy*(B*B + 1)

        if rem <= 0:
            continue

        if rem % B != 0:
            continue

        x2_y2 = rem // B
        S2 = x2_y2 + 2*xy

        if S2 < 0:
            continue

        S = isqrt(S2)
        if S*S != S2:
            continue

        res = recover_xy(S, xy)
        if res is None:
            continue

        x, y = res
        if x*y != xy:
            continue

        p = x*B + y
        q = y*B + x

        if p*q != N:
            continue

        phi = (p-1)*(q-1)
        d = pow(e, -1, phi)

        m = pow(c, d, N)
        print("FLAG:", long_to_bytes(m))
        exit()

print("not found")

```

```bash
FLAG: b'BKSEC{p4l1n_p0ly_1d3n717y_m47h}'
```