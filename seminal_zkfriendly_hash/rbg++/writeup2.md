# RBG++

* **Karmal CTF** 
* **Thể loại:** Cryptography 
* **Kỹ thuật chính:** Algebraic Attack, LCG (Linear Congruential Generator), RSA Common Modulus,Resultant, Pseudo-Division, Zero Divisors Filtering.



## 0,Background 

### 1. Kết thức (Resultant) là gì?
**Kết thức** (Resultant) là một công cụ toán học dùng để xác định xem hai đa thức có nghiệm chung hay không, mà không cần phải giải trực tiếp để tìm các nghiệm đó.

Giả sử ta có hai đa thức một biến $f(x)$ và $g(x)$ thuộc một trường (hoặc vành) nào đó:
* $f(x) = a_n x^n + a_{n-1} x^{n-1} + \dots + a_0$
* $g(x) = b_m x^m + b_{m-1} x^{m-1} + \dots + b_0$

Kết thức của $f$ và $g$ theo biến $x$, ký hiệu là $\text{Res}_x(f, g)$, được tính bằng **định thức của ma trận Sylvester** (một ma trận vuông kích thước $(m+n) \times (m+n)$ tạo bởi các hệ số của $f$ và $g$).
$$\text{Res}_x(f, g) = 0 \iff f(x) \text{ và } g(x) \text{ có ít nhất một nghiệm chung }$$

### 2. Ứng dụng của Resultant trong giải hệ pt đại số 

* Hệ phương trình 2 biến $f(x, y) = 0$ và $g(x, y) = 0$
    - Tính $\text{Res}_x(f, g)$ => biến $x$ sẽ bị triệt tiêu hoàn toàn. Kết quả thu được là một đa thức $R(y)$ chỉ chứa biến $y$.
    - Để hệ có nghiệm thì $R(y) = 0$, ta chỉ cần giải tìm y và thay vào tìm x 

Ta cũng có thể áp dụng với nhiều nghiệm , khi dùng các phương trình để khử dần dần biến 


### 3. Đánh giá Bound bậc/số mũ (Degree Bound) của Resultant

Khi sử dụng Resultant để khử biến, cái giá phải trả là việc tăng bậc của đa thức 

Xét đa thức nhiều biến $f(x, y)$ và $g(x, y)$. Gọi:
* $n = \deg_x(f)$ (bậc cao nhất của biến $x$ trong $f$)
* $p = \deg_y(f)$ (bậc cao nhất của biến $y$ trong $f$)
* $m = \deg_x(g)$ (bậc cao nhất của biến $x$ trong $g$)
* $q = \deg_y(g)$ (bậc cao nhất của biến $y$ trong $g$)

Khi tính kết thức $R(y) = \text{Res}_x(f, g)$ để khử $x$, bậc của đa thức kết quả theo biến $y$ sẽ bị giới hạn bởi công thức:
$$\deg_y(R) \le n \cdot q + m \cdot p$$

**Ví dụ thực tế từ bài toán:**
Giả sử $f(A, H)$ có bậc 3 theo $A$ và bậc 2 theo $H$. $g(A, H)$ có bậc 3 theo $A$ và bậc 4 theo $H$.
Khi tính Resultant để khử biến $A$:
$$\deg_H(\text{Res}_A(f, g)) \le 3 \cdot 4 + 3 \cdot 2 = 18$$


## 1. Phân tích đề bài 

Đề bài cung cấp một hệ thống sinh số ngẫu nhiên từ seed m là flag 

```python
PBITS, NDAT = 371, 13

with open("flag.txt", "rb") as f:
	m = int.from_bytes(f.read())

N = getPrime(PBITS) * getPrime(PBITS)
e = getRandomRange(731, N)
print(f"{N = }")

lcg = lambda s: (s * 3 + 1337) % N

for i in range(NDAT):
	print(pow(m, e:=lcg(e), N) + pow(m, e:=lcg(e), N))
```
- các số được đinh nghĩa trên Zmod(N) với $N$ là hợp số như trong RSA 
- Để tính $C_i$ là số thứ i của generator 
    - Với initial $e_0$ là 1 số ngẫu nhiên , ta định nghĩa chuỗi $e_i$:
    $$
    e_{i+1} = 3e_i + 1337 \pmod{N} = 3e_i + 1337 - k_iN 
    $$
    - Ta định nghĩa i
    $$
    A_{2i+1} = m^{e_{2i+1}} 
    $$i
    $$
    A_{2i+2} = m^{e_{2i+2}} 
    $$
    - Ta tính ra $C_i$
$$
C_i = A_{2i+1} + A_{2i+2} 
$$


- Let $B = m^{1337}$ and $H = m^{-N}$
$$
=> A_{i+1} = m^{3e_i +1337 - k_iN}= A_i^3 B H^{k_i}
$$
- $k_i = {0,1,2}$

Ta sẽ được output của chal là số N và 13 giá trị đầu của bộ sinh số 

## 2, Exploit Idea 
Ta có thể tìm cách rút gọn nhiều ẩn $B,H,A_i$ thành còn 1 ẩn nhưng 
- Việc giải 1 phương trình bậc cao trên Zmod(N) là không thể 
- => Cần thêm 1 phương trình nữa để ta có thể GCD ra 1 đa thức bậc nhất để tìm nghiệm 

Chiến lược chuẩn của chal 
- Ta sẽ sử dụng 3 số đầu $C_0,C_1,C_2$ để tạo ra phương trình ẩn $H$ 

- Kết hợp với phương trình : $B^NH^{1337} = 1$ 
    - Vậy nên ở bước 1 ta cần phải rút ra $B$ theo $H$ nữa để thế vào pt 2 
### 2.1 Rút gọn đa thức từ $C_0,C_1,C_2$  
Ta sẽ cần phải brute force $k_i$ => Chọn càng ít phương trình càng tốt 

Ta sẽ chọn 3 số $C_i$ đầu => brute force từ $k_1$ đến $k_5$ => 243 case 

$$ C_0 = A_1 + A_1^3 \cdot B \cdot H^{k_1}$$
$$C_1 = A_3 + A_3^3 \cdot B \cdot H^{k_3}$$
$$C_2 = A_5 + A_5^3 \cdot B \cdot H^{k_5}$$

Ta sẽ tìm 1 đa thức $f(H) = 0$ và 1 đa thức $p_1(H) \cdot B + p_0(H) = 0$.
#### 2.1.1 Sử dụng kêt thức để khử  biến A 

* $f_1: A_1 + A_1^3 \cdot B \cdot H^{k_1} - C_0 = 0$
* $f_2: A_3 + A_3^3 \cdot B \cdot H^{k_3} - C_1 = 0$
* Thay $A_3 = (C_0 - A_1)^3 \cdot B \cdot H^{k_2}$

=> Tìm kết thức của $f_1 và f_2$ theo biến $A_1$ để ra 1 đa thức ẩn B và H gọi là $res1$ 
* $g_1: A_3 + A_3^3 \cdot B \cdot H^{k_3} - C_1 = 0$
* $g_2: A_5 + A_5^3 \cdot B \cdot H^{k_5} - C_2 = 0$
* Thay $A_5 = (C_1 - A_3)^3 \cdot B \cdot H^{k_4}$

=> Tìm kết thức của $g_1 và g_2$ theo biến $A_3$ để ra 1 đa thức ẩn B và H gọi là $res2$ 
#### 2.2.2 Sử dụng Grobner basis để rút gọn biến B

Với $res1$ và $res2$ , ta có thể chạy thuật toán rút gọn cơ sở Grobner để khử đi biến B 
- Với res1 và res2 có bậc là 21 theo B , hàm grobner_basis của sage math có thể có time complex khá tệ => Ta nên tự định nghĩ việc rút gọn biến B 

```python
if f1.degree() < f2.degree():
                f1, f2 = f2, f1

            f1_coef = f1[f1.degree()]
            f2_coef = f2[f2.degree()]

            g = P_H(f1_coef._pari_with_name().gcd(f2_coef._pari_with_name()))
            
        
            f1 *= P_H(f2_coef._pari_with_name() / g._pari_with_name())
            f2 *= P_H(f1_coef._pari_with_name() / g._pari_with_name())

            f1 -= f2 * B^(f1.degree() - f2.degree())

            if f1.degree() == 0 or f1.degree() == -1:
                break
```
- với f1 và f2 trong code tương ứng với res1 , res2 , khi kết thúc vòng lặp ta có thể thu được:
    - f1 là đa thức $f(H) = 0$ (gọi là $res(H)$)
    - f2 là đa thức $p_1(H) \cdot B + p_0(H) = 0$.

- Với việc tự rút gọn cơ sở như vậy , bậc ( theo biến H) của $res(H)$ hay $p_1(H)$ và $p_2(H)$ có thể lên tới hàng ngàn , nhưng hoàn toàn có thể giải được H khi tìm được 1 $res_2(H)$ để đửa vào tìm gcd 
### 2,2 Sử dụng pt $B^NH^{1337} = 1$

với đa thức f2 là $p_1(H) \cdot B + p_0(H) = 0$ vừa tìm được ta thực hiện biến đổi 
$$(p_1(H) \cdot B)^N = (-p_0(H))^N \implies p_1(H)^N \cdot B^N = -p_0(H)^N$$
Nhân $H^{1337}$ và thay $B^N \cdot H^{1337} = 1$:
$$res_2(H) = p_1(H)^N + p_0(H)^N \cdot H^{1337} = 0$$

Vì tính $N$ lũy thừa rất lớn, ta bắt buộc phải tính trong Vành thương (Quotient Ring) của $res(H)$ để ép bậc không bị phình to:
```python
Q_H = P_H.quotient(res)
res2_RSA = (Q_H(p1)^N).lift() + (Q_H(p0)^N).lift() * H_var^1337
```

sau đó , ta chỉ việc tính GCD của $res(H)$ và $res_2(H)$ để ra tính ra nghiệm $H$, từ đó thay vào để tính lại ra $B$

### 2,3 Common modulus attack 
$$
H = m^{-N} \pmod N
$$
$$
B = m^{1337} \pmod N
$$
=> Dùng common modulus attack để tính ra m là flag 

## 3, Code Exploit
Một vài lưu ý khi implement 
- Trong vòng lặp thực hiện rút gọn cơ sở Grobner với res1 và res2 (f1 và f2 trong code) , ta cần chú ý về bậc của thấp nhất của f1 và f2 , tức là phải đảm bao sao cho hệ số tự do khác 0 để tránh việc ra B = 0 là nghiệm 

- Ta phải đảm bảo cho việc gcd của $res(H)$ và $res_2(H)$ là bậc 1 ( bởi vì việc giải hệ pt bậc 2 hay hơn trên Zmod(N) gần như không thể) 
    - Thực hiện việc triệt tiêu đến khi cặp $p_1(H)$ và $res(H)$ ko còn GCD khác 1 
    - Thực hiện việc triệt tiêu đến khi cặp $p_0(H)$ và $res(H)$ ko còn GCD khác 1 


- Sage math không cho ta sử dụng GCD của đa thức đơn biến trên Zmod(N) , vậy nên ta phải dụng hàm _pari_with_name() để gọi được gcd 


```python 
from sage.all import *
import itertools
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm


N = 16167885915193478051793877611486619241886473426863252783094589654879500659067740377062272392685930800102844215704528436693321982169968535528301909521740422063158802614037675785775081053858036967400526899115004867166488372889
C = [
    23524356627767287626245212608188456486510486842884944774388457118524878337010325280806281200006513760569554973350027623280980530389685273358299240165163348831178950906369654270836363037734464763165971796940465525441254094362,
    20417144512792463288144454294819320198675053687066876812066787608526065186517106068771714888222417207180901619094929565058749740851992567962732918068890150032710566113874561398162760409944385995695085324172030092973190257577,
    10520424976309587244912110505341168843522648629096918766553735784501443210882592550479277468613423963705805659813405742198752350482717828219056306550361834962704972988508557816667577007199850461049600946454322911178025895814
]

Zn = Zmod(N)
P_H.<H> = PolynomialRing(Zn)
P_B.<B> = PolynomialRing(P_H)  
P_A.<A> = PolynomialRing(P_B)


for k_seq in tqdm(list(itertools.product([0, 1, 2], repeat=5))):
    k1, k2, k3, k4, k5 = k_seq
    try:
        #TÍNH RESULTANT ĐỂ KHỬ BIẾN A 
        f0 = A^3 * B * H^k1 + A - C[0]
        A3 = (C[0] - A)^3 * B * H^k2
        f1 = A3^3 * B * H^k3 + A3 - C[1]
        res1 = f0.resultant(f1) 

        g1 = A^3 * B * H^k3 + A - C[1]
        A5 = (C[1] - A)^3 * B * H^k4
        g2 = A5^3 * B * H^k5 + A5 - C[2]
        res2 = g1.resultant(g2) 

        if res1 == 0 or res2 == 0:
            continue

        f1, f2 = res1, res2
    
        #KHỬ BIẾN B VÀ CHẶT NGHIỆM B=0 
        while True:
            coefs = f1.list()
            while len(coefs) > 0 and coefs[0] == 0:
                coefs = coefs[1:]
            f1 = P_B(coefs)

            coefs = f2.list()
            while len(coefs) > 0 and coefs[0] == 0:
                coefs = coefs[1:]
            f2 = P_B(coefs)

            if f1.degree() < f2.degree():
                f1, f2 = f2, f1

            f1_coef = f1[f1.degree()]
            f2_coef = f2[f2.degree()]

            g = P_H(f1_coef._pari_with_name().gcd(f2_coef._pari_with_name()))
            
        
            f1 *= P_H(f2_coef._pari_with_name() / g._pari_with_name())
            f2 *= P_H(f1_coef._pari_with_name() / g._pari_with_name())

            f1 -= f2 * B^(f1.degree() - f2.degree())

            if f1.degree() == 0 or f1.degree() == -1:
                break

        if f1 == 0 or f1.degree() == -1:
            continue

        res = f1[0]#res là f(H) = 0 
        p0, p1 = f2[0] % res, f2[1] % res#p0[H]+p1[H]*B = 0 
H
        #đảm bảo p0,p1 ko có nghiệm H chung với res 
        while True:
            g = res._pari_with_name().gcd(p0._pari_with_name())
            if P_H(g).degree() == 0:
                break
            res = P_H(res._pari_with_name() / g)
            p0 %= res

        while True:
            g = res._pari_with_name().gcd(p1._pari_with_name())
            if P_H(g).degree() == 0:
                break
            res = P_H(res._pari_with_name() / g)
            p1 %= res

        #RÀNG BUỘC RSA
        Q2 = P_H.quotient(res)

        res_RSA = (Q2(p1)^N).lift() + (Q2(p0)^N).lift() * H^1337#p1^N + p0^N * H^1337 = 0 

        g_final = P_H(res._pari_with_name().gcd(res_RSA._pari_with_name()))


        if g_final.degree() > 0:
            assert g_final.degree() == 1

            H_result = -g_final.monic()[0]
            B_result = -p0(H=H_result) / p1(H=H_result)
            #common modulus attack on RSA 
            vg, v1, v2 = xgcd(1337, -N)
            m = int(B_result^v1 * H_result^v2)

            flag = long_to_bytes(m)
            print(f"\nFind flag at {k_seq}:")
            print(flag.decode('utf-8', errors='ignore'))
            exit(0)

    except Exception as e:
        print(e) 
        pass
```   

```bash
(sage) nhat-anh@nhat-anh-G5-MF5:~$ sage /home/nhat-anh/ctf/ctf_crypto/karmal_ctf/rbg++/solve.sage
[*] Đang nạp dữ liệu CTF...
 32%|█████████████▍                            | 78/243 [13:48<34:49, 12.66s/it]
Find flag at (0, 2, 2, 2, 0):
kalmar{Order_of_the_Overflow!!!_Oh_yeah_1337_too}
 32%|█████████████▍                            | 78/243 [13:57<29:31, 10.74s/it]
0
```



