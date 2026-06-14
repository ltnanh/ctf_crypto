# AOP
- **FCSC 2024**
- **Crypto** 
- Algebraic attack to SPN block cipher: Bypass SBox , GCD attack 

## 1. Challenge Overview
Challenge cho ta 1 block cipher dựa trên cấu trúc SPN 
```python
class AOP:
    def __init__(self, s = 1):
        self.p = 18446744073709551557 # p - 1 not a multiple of 3
        self.t = 5
        self.r = 9
        self.RC = [
            [ int.from_bytes(sha256(b"FCSC2024#" + str(self.t*j + i).encode()).digest()) % self.p for i in range(self.t) ]
            for j in range(self.r)
        ]
        self.M = [
            [ pow(i, j, self.p) for i in range(1, self.t + 1) ]
            for j in range(self.t)
        ]

    def R(self, r):
        # self.S <- self.S * M
        s = [ 0 ] * self.t
        for j in range(self.t):
            acc = 0
            for i in range(self.t):
                s[j] += self.M[i][j] * self.S[i]
            s[j] %= self.p
        self.S = s[:]

        # self.S <- self.S + RC[i]
        for j in range(self.t):
            self.S[j] += self.RC[r][j]

        # self.S <- self.S ** e
        e = pow(3, -r, self.p - 1)
        self.S[0] = pow(self.S[0], e, self.p)

    def __call__(self, L):
        assert len(L) == self.t, f"Error: input must be a list of {self.t} elements."
        assert all(x in range(0, self.p) for x in L), f"Error: elements must be in [0..{self.p - 1}]."
        self.S = L[:]
        for i in range(self.r):
            self.R(i)
        return self.S
```

**Cấu trúc Block Cipher:**
Thuật toán mã hóa hoạt động trên trường hữu hạn $\mathbb{F}_p$ với $p = 18446744073709551557$. Hàm mã hóa sử dụng cấu trúc SPN với 9 vòng (từ vòng 0 đến vòng 8), state size = 5 , mỗi round gồm:
* **Mix Collumn** : Nhận với ma trận 5x5 
* **Add Round Key (RC):** Cộng với các hằng số vòng .
* **Partial S-box Layer:** Chỉ phần tử đầu tiên của trạng thái (`state[0]`) , $Sbox(x) = x^e \pmod p$ với $e = 3^{-r} \pmod {p-1}$


Chal yêu cầu chúng ta tìm ra một input $X$ (size =5) với $X[0] = 0$ sao cho khi đi qua Block Cipher, output $Y$ có $Y[0] = 0$


---

## 2. Attack Strategy

với code của challenge , ta hoàn toàn có thể inverse block cipher từ output , với mỗi round:
- Inv Sbox 
- Sub round constant
- Inv mix collumn 

với việc tìm từ input X các biến đi qua Sbox sẽ có số mũ rất lớn $e = 3^{-r} \pmod {p-1}$ , vậy nên ta sẽ đi ngược lại từ output $Y$ để tránh việc đa thức bùng nổ số mũ 

```bash
Inverse exponentation
Round 0: e' = 1
Round 1: e' = 3
Round 2: e' = 9
Round 3: e' = 27
Round 4: e' = 81
Round 5: e' = 243
Round 6: e' = 729
Round 7: e' = 2187
Round 8: e' = 6561
```
=> Đi từ $Y = S_9 = [0,y_1, y_2, y_3, y_4]$ , lập phương trình $X[0] = S_0[0] = f(y_1, y_2, y_3, y_4) = 0$ 

Nhưng như vậy bậc của phương trình qua các vòng vẫn sẽ bùng nổ đến $3.9.27.81.243.729.2187.6561$ => ta cần phải tìm các để  bypass các Sbox có số mũ lớn 


### 2.1. Sbox bypassing 
Vì ở đây ta có 4 biến tự do $y_1, y_2, y_3, y_4$ nên ta có thể tạo ràng buộc của của các nghiệm này với nhau qua các inv round 8,7,6 để force thành phần $S[0]$ sau mỗi round đi vào Sbox của inv round sau sẽ ko có thành phân của biến (chỉ có constant) 

Thay vì dùng 4 biến độc lập $y_1, y_2, y_3, y_4$ , ta biểu diễn output như sao:
$$Y = [0, \quad aX, \quad bX, \quad cX, \quad dX]$$

Ta sẽ tìm a,b,c,d thỏa mãn bypass Sbox qua các round và phương trình để đa thức $f(y_1, y_2, y_3, y_4)$ cuối cùng chit cong biến $X$

### 2.2. Chiến lược "Zeroing the Coefficient" ($AX + B = B$)
Ta sẽ nói về các inv round 6,7,8 .
Giả sử state sau khi đi qua inv round 8 ( S9 về S8) sẽ có dạng
$$
S_8 = [g_0(X) , g_1(X),g_2(X),g_2(X),g_2(X)]
$$ 
với $g_0,g_1,g_2,g_3,g_4$ là đơn thức bậc nhất 1 ẩn X

- Khi đó thì $g_O(X)$ đi vào Sbox sẽ có dạng $S_8[0] = A(a,b,c,d) \cdot X + B$ với A là biểu thức tuyến tính của a,b,c,d còn B là constant , ví dụ 
```
18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X + 12345205671218884834$
```

- Ta sẽ cho A(a,b,c,d) = 0 để đảm bảo chỉ còn thành phần constant B đi vào Sbox của inv round 7 , tức là vd: 
```
18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X =0
=> 10a = 10b - 5c + d
```
- Như vậy thì đi vào Sbox của inv round 7 chỉ là constant , biến $X$ sẽ ko phải đi qua Sbox bậc 6561 của round này => phương trình giảm 6561 bậc 

Ta sẽ làm tương tự như vậy với $S_8,S_7,S_6$ đến khi dùng hết các biến tự do (tính ra a,b,c,d và chỉ còn biến $X$)

### 2.4 Lập phương trình $X[0] = S_0[0] = P(X) = 0$

Sau khi lùi qua 3 vòng (8, 7, 6), ta đã dùng hết 3 bậc tự do $a, b, c$ và cố định nốt $d = 1$. Ở 6 vòng cuối (Vòng 5 về 0), hệ thống không còn ẩn phụ để triệt tiêu, biến $X$ bắt buộc phải đi qua S-box . Bậc của các đa thức của các thành phần trong state sẽ bùng nổ số mũ do phải đi qua S-box, nhưng đã giảm đi đáng kể vì ta by pass qua 3 số mũ to nhất

Về đến Input $S_0$. Ta thu được đa thức mục tiêu $X[0] = S_0[0] = P(X) = 0$ với bậc tối đa $59,049$. 

### 2.3. GCD với Fermat constraint 
Việc giải $P(x)$ với bậc 59049 trên $GF(p)$ (gọi hàm roots trong sagemath) sẽ có time complexity rất lớn 

Ta sẽ áp dụng Định lý Fermat nhỏ 
$$
X^p - X \equiv 0 \pmod p \quad \forall X \in GF(p)
$$
Để lọc nghiệm bằng ước chung lớn nhất (GCD):
$$R(X) = \gcd(P(X), \quad X^p - X \pmod{P(X)})$$


Khi đó , chỉ cần tìm nghiệm của $R(X)$ và thay vào tìm input $S_0$ rồi nộp server 

---

## 3. Implementation Details

Với code challenge , ta có thể tính ra round constant và Inv Mix Col Matrix của từng round để hoàn thiện inv Round 
```bash
Ma trận nghịch đảo M_inv = [
   [5, 1537228672809129290, 3843071682022823244, 16909515400900422260, 14603672391686728316] ,
   [18446744073709551547, 15372286728091292982, 3074457345618258583, 3074457345618258595, 15372286728091292964] ,
   [10, 9223372036854775759, 13835058055282163680, 18446744073709551554, 13835058055282163668] ,
   [18446744073709551552, 3074457345618258603, 3074457345618258586, 15372286728091292966, 15372286728091292964] ,
   [1, 7686143364045646480, 13066443718877599021, 1537228672809129296, 14603672391686728316] ,
]

Ma trận RC :
[13233480176997314046, 9284868279641994560, 12235501346938362812, 4133703306813821108, 11628934183821097159]
[1365554073049210793, 3511007896404757791, 10119514266227461252, 12755649044034805154, 6968391277147913083]
[3436235021743231344, 14382771639998597446, 10794456969604745825, 3391001746029954469, 9575776310833530705]
[5702251878007940294, 1412611021160597154, 15293457665893109119, 17246459576629151420, 10984851308070435897]
[15432749654538409412, 851794337522974300, 17912965898469569454, 86107493925447996, 12787287593122038164]
[4482214891010895595, 7807142372481143011, 17786077328007785060, 2193376157630329748, 1835978555584597312]
[118587187516533665, 12368523247742327143, 17943100724683604257, 964261096706093360, 17879958655590459449]
[11066677148798511200, 17893234430028688514, 8251047221571039380, 10263219281137670843, 16969914817910377678]
[18149433503814401207, 12354040488908002162, 1717883272379260986, 18411889493652291634, 3094926074710221276]
```
### 3.1 , Thưc hiện bypass Sbox với round 8,7,6 
### Inv round 8
Từ ouput $Y = [0, \quad aX, \quad bX, \quad cX, \quad dX]$ , thực hiện lùi qua inv r8  và rút hệ số a 
```python
#Output of block cipher 
S9 = vector([0,a*X, b*X, c*X, d*X])
```

```python
S8 = inv_sbox_layer(S9, 8)
S8 = inv_linear_layer(S8,8)
print(S8[0])
#18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X + 12345205671218884834
# => 10a = 10b - 5c + d
a = (10 * b - 5 * c + d)*F(10)^-1
```

### Inv round 7 
Từ $S_8$ đi qua inv r7 để rút hệ số b 

```python
S7 = inv_sbox_layer(S8, 7)
S7 = inv_linear_layer(S7,7)
print(S7[0])
#10760600709663905120*b*X + 9223372036854775743*c*X + 17063238268181335199*d*X + 10318913522183144972
b = (9223372036854775743*c + 17063238268181335199*d)*F(-10760600709663905120)^-1
```


### Inv round 6 
Từ $S_7$ đi qua inv r6 để rút hệ số c

```python
S6 = inv_sbox_layer(S7, 6)
S6 = inv_linear_layer(S6,6)
print(S6[0])
#7320187277504286446*c*X + 6373745040101623205*d*X + 10099990774956362003
c = 6373745040101623205*d*F(-7320187277504286446)^-1
```

### Chọn d 
Chọn d =1 vì thực chất ta chỉ biểu diễn các ẩn $y_1,y_1,y_2,y_4$ qua tỉ lệ a,b,c,d với ẩn $X$ , từ đây ta đã có giá trị của các số trong state là đa thức biến $X$

### Inv round 5 -> 0 
Ta thực hiện nốt các Inv round từ $S_6$ về $S_0$, các thành phần đa thức trong state sẽ tăng bậc qua các Sbox 


```python
#choose d = 1 
S6 = [poly.subs(d=1) for poly in S6]


S65 = inv_sbox_layer(S6,5)
S5 = inv_linear_layer(S65,5)
print("\nDegree of S5[0]:", S5[0].degree())
#1

S54 = inv_sbox_layer(S5,4)
S4 = inv_linear_layer(S54,4)
print("Degree of S4[0]:", S4[0].degree())
#81 

S43 = inv_sbox_layer(S4,3)
S3 = inv_linear_layer(S43,3)
print("Degree of S3[0]:", S3[0].degree())
#2187 

S32 = inv_sbox_layer(S3,2)
S2 = inv_linear_layer(S32,2)
print("Degree of S2[0]:", S2[0].degree())
#19683 

S21 = inv_sbox_layer(S2,1)
S1 = inv_linear_layer(S21,1)
print("Degree of S1[0]:", S1[0].degree())
#59,049


S10 = inv_sbox_layer(S1,0)
S0 = inv_linear_layer(S10,0)
print("Degree of S0[0]:", S0[0].degree())
#59,049

```

### Giải phương trình tìm X

Cuối cùng ta chỉ cần giải phương trình $S_0[0] = P(X) = 0$ bàng việc GCD với fermat constraint , sau đo recover lại $S_0$ 

```python
#solve equation S0[0] = 0 to find X 
P_target = S0[0]
P_target = P_target.univariate_polynomial()
R.<X> = PolynomialRing(F) 
P_target = R([F(c) for c in P_target.list()])


# 3.Apply equation X^p - X = 0  to use GCD 
print("Apply equation X^p - X = 0  to use GCD")
Q = power_mod(X, p, P_target) - X
gcd_res = gcd(P_target, Q)
print("GCD:", gcd_res)

roots = gcd_res.roots(multiplicities=False)

X = int(roots[0])
print(f"Found X = {X}")
```
```bash
GCD: X + 6602977699924049275
Found X = 11843766373785502282
```
---

## 4. Exploit Code

```python
from pwn import * 
context.log_level = 'error' 

p = 18446744073709551557
F = GF(p)
t_size = 5

M_inv = [
    [5, 1537228672809129290, 3843071682022823244, 16909515400900422260, 14603672391686728316],
    [18446744073709551547, 15372286728091292982, 3074457345618258583, 3074457345618258595, 15372286728091292964],
    [10, 9223372036854775759, 13835058055282163680, 18446744073709551554, 13835058055282163668],
    [18446744073709551552, 3074457345618258603, 3074457345618258586, 15372286728091292966, 15372286728091292964],
    [1, 7686143364045646480, 13066443718877599021, 1537228672809129296, 14603672391686728316]
]

RC = [
    [13233480176997314046, 9284868279641994560, 12235501346938362812, 4133703306813821108, 11628934183821097159],
    [1365554073049210793, 3511007896404757791, 10119514266227461252, 12755649044034805154, 6968391277147913083],
    [3436235021743231344, 14382771639998597446, 10794456969604745825, 3391001746029954469, 9575776310833530705],
    [5702251878007940294, 1412611021160597154, 15293457665893109119, 17246459576629151420, 10984851308070435897],
    [15432749654538409412, 851794337522974300, 17912965898469569454, 86107493925447996, 12787287593122038164],
    [4482214891010895595, 7807142372481143011, 17786077328007785060, 2193376157630329748, 1835978555584597312],
    [118587187516533665, 12368523247742327143, 17943100724683604257, 964261096706093360, 17879958655590459449],
    [11066677148798511200, 17893234430028688514, 8251047221571039380, 10263219281137670843, 16969914817910377678],
    [18149433503814401207, 12354040488908002162, 1717883272379260986, 18411889493652291634, 3094926074710221276]
]

def inv_linear_layer(state, r):
    sub_rc = [(state[i] - RC[r][i]) for i in range(t_size)]
    next_state = []
    for j in range(t_size):
        acc = 0
        for i in range(t_size):
            acc += sub_rc[i] * M_inv[i][j]
        next_state.append(acc)
    return next_state


def inv_sbox_layer(state, r):
    next_state = state[:]
    d_round = pow(3, r, p - 1)
    next_state[0] = next_state[0]^d_round
    
    return next_state


P = PolynomialRing(Zmod(p), names="a,b,c,d,X")
a, b, c, d, X = P.gens()

#Output of block cipher 
S9 = vector([0,a*X, b*X, c*X, d*X])


S8 = inv_sbox_layer(S9, 8)
S8 = inv_linear_layer(S8,8)
print(S8[0])
#18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X + 12345205671218884834
# => 10a = 10b - 5c + d
a = (10 * b - 5 * c + d)*F(10)^-1
S8 = [poly.subs(a=a) for poly in S8]



S7 = inv_sbox_layer(S8, 7)
S7 = inv_linear_layer(S7,7)
print(S7[0])
#10760600709663905120*b*X + 9223372036854775743*c*X + 17063238268181335199*d*X + 10318913522183144972
b = (9223372036854775743*c + 17063238268181335199*d)*F(-10760600709663905120)^-1
S7 = [poly.subs(b=b) for poly in S7]




S6 = inv_sbox_layer(S7, 6)
S6 = inv_linear_layer(S6,6)
print(S6[0])
#7320187277504286446*c*X + 6373745040101623205*d*X + 10099990774956362003
c = 6373745040101623205*d*F(-7320187277504286446)^-1
S6 = [poly.subs(c=c) for poly in S6]


#choose d = 1 
S6 = [poly.subs(d=1) for poly in S6]


S65 = inv_sbox_layer(S6,5)
S5 = inv_linear_layer(S65,5)
print("\nDegree of S5[0]:", S5[0].degree())


S54 = inv_sbox_layer(S5,4)
S4 = inv_linear_layer(S54,4)
print("Degree of S4[0]:", S4[0].degree())


S43 = inv_sbox_layer(S4,3)
S3 = inv_linear_layer(S43,3)
print("Degree of S3[0]:", S3[0].degree())


S32 = inv_sbox_layer(S3,2)
S2 = inv_linear_layer(S32,2)
print("Degree of S2[0]:", S2[0].degree())


S21 = inv_sbox_layer(S2,1)
S1 = inv_linear_layer(S21,1)
print("Degree of S1[0]:", S1[0].degree())


S10 = inv_sbox_layer(S1,0)
S0 = inv_linear_layer(S10,0)
print("Degree of S0[0]:", S0[0].degree())



#solve equation S0[0] = 0 to find X 
P_target = S0[0]
P_target = P_target.univariate_polynomial()
R.<X> = PolynomialRing(F) 
P_target = R([F(c) for c in P_target.list()])


# 3.Apply equation X^p - X = 0  to use GCD 
print("Apply equation X^p - X = 0  to use GCD")
Q = power_mod(X, p, P_target) - X
gcd_res = gcd(P_target, Q)
print("GCD:", gcd_res)

roots = gcd_res.roots(multiplicities=False)

X = int(roots[0])
print(f"Found X = {X}")

#Recover input of block cipher
Final_Input = []
for poly in S0:
    val = poly.subs(X=X)
    Final_Input.append(int(val) % p)

print("Final Input: ", end = "")
print(",".join(map(str, Final_Input)))


#Send and get flag 
payload = ",".join(map(str, Final_Input))

HOST = '127.0.0.1' 
PORT = 1337       
r = remote(HOST, PORT)

r.recvuntil(b">>> ")
r.sendline(payload.encode())
flag_response = r.recvall(timeout=5)
print(flag_response.decode().strip())
```
### Result 
```bash
18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X + 12345205671218884834
10760600709663905120*b*X + 9223372036854775743*c*X + 17063238268181335199*d*X + 10318913522183144972
7320187277504286446*c*X + 6373745040101623205*d*X + 10099990774956362003

Degree of S5[0]: 1
Degree of S4[0]: 81
Degree of S3[0]: 2187
Degree of S2[0]: 19683
Degree of S1[0]: 59049
Degree of S0[0]: 59049
Apply equation X^p - X = 0  to use GCD
GCD: X + 6602977699924049275
Found X = 11843766373785502282
Final Input: 0,9917426034582540397,18047381214126843293,46303549222654641,2560376450397831035
Output Y = [0, 27009687339058180490, 4733399561315632814, 27913805199368301021, 11843766373785502282]
FCSC{449a12ead684fb0162c741fe8575fa94ff43023e4aa4627b9ce7e40cf041b314}
```