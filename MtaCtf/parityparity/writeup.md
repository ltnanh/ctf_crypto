# parity parity 

- category : Crypto 

## 1.Tổng quan về challenge 

```python
import sys
from Crypto.Util.number import getPrime, bytes_to_long
import os

flag = os.getenv('FLAG', 'flag{fake_flag}').encode()

def generate_keys():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    d = pow(e, -1, (p-1) * (q-1))
    return (n, e), d

def main():
    pub, priv = generate_keys()
    n, e = pub
    d = priv

    m = bytes_to_long(flag)
    c = pow(m, e, n)

    print(f"N = {n}")
    print(f"e = {e}")
    print(f"flag_enc = {c}")

    for i in range(1024):
        try:
            user_input = input(f"[{i+1}/1024] Enter ciphertext (integer): ")
            ct = int(user_input)
            pt = pow(ct, d, n)
            
            print(f"Parity: {pt % 2}")
            
        except ValueError:
            print("Invalid input.")
            break
        except EOFError:
            break

if __name__ == "__main__":
    main()
```

Đây là 1 hệ mã RSA , ta nhận được khóa công khai n,e và bản mã c của flag từ server 

Server là 1 oracle , cho phép ta gửi 1 bản mã ct bất kì , server sẽ giải mã $pt = ct^d \pmod N$ và trả về bit cuối cùng của pt , tức là ta xác định được pt là chẵn hay lẻ . Ta có 1024 lượt gửi 

## 2.Chiến lược tấn công 
Đây là 1 dạng lỗ hổng rất kinh điển của RSA là Parity Oracle Attack . Ta sẽ dùng binary search giải mã flag như sau 

- Đầu tiên , ta khá chắc chắn rằng $m \in (0,N)$
- Ta gửi cho server $c' = 2^e.c = (2m)^e \pmod N$ cho server , server sẽ giải mã và trả về bit cuối cùng (parity) của $2m$

    - Nếu 2m lẻ (parity = 1) => $2m >N$ (chẵn - lẻ = lẻ) => $m \in [N/2,N]$
    - Nếu 2m chẵn (parity = 0) => $2m<N$ (chẵn - 0 = chẵn) => $m \in [0,N/2]$
=> Ta giảm được không gian tìm kiếm xuông còn 1 nửa 

- Tiếp theo , ta sẽ gửi cho server $c' = 4^e.c = (4m)^e \pmod N$  server sẽ giải mã và trả về bit cuối cùng (parity) của $4m$
    - Ví dụ $m \in [N/2,N]$ => $4m \in [2N,4N]$ Ta hoàn toàn có thể tiếp tục dùng parity check để xác định 4m thuộc khoảng nào , từ đó giảm search space xuống còn 1 nửa tiếp 

- Ta cứ lần lượt nhân c với $2^e, 4^e,8^e,.....$ để gửi cho server , mỗi lần gửi ta sẽ giảm search space đi được 1 nửa , qua 1024 lần thì search space của m chỉ còn 1 giá trị duy nhất là flag

## 3.Code khai thác 
```python 
from pwn import *
from Crypto.Util.number import long_to_bytes
from fractions import Fraction

context.log_level = 'error'

r = remote('localhost', 1337)

r.recvuntil(b"N = ")
N = int(r.recvline().strip())
print("N =",N)

r.recvuntil(b"e = ")
e = int(r.recvline().strip())

r.recvuntil(b"flag_enc = ")
c = int(r.recvline().strip())
print("c =",c)

lower = Fraction(0)
upper = Fraction(N)


for i in range(1,1025):
    if i%100 ==0: 
        print(f"Request {i}/1024")
    
    
    c_prime = (c * pow(2**i, e, N)) % N  #c' = c * (2^i)^e mod N
    
    r.recvuntil(b"Enter ciphertext (integer): ")
    r.sendline(str(c_prime).encode())
    
    r.recvuntil(b"Parity: ")
    parity = int(r.recvline().strip())
    
    mid = (lower + upper) / 2
    
    if parity == 1:
        lower = mid
    else:
        upper = mid


m = int(upper) 
print(long_to_bytes(m))

r.close()
```
```bash
N = 103294454081184149883199056624931112637312727392148251424546672873963267852741842025473880881234669156186008942668587966781226776607036868619144638385756459274624335997053677963801507904239322712703141940043009808423004186249147439725877942766974621990773401858420424332647361468290442302549626147254935772223
c = 19571492792595971316780464184276826977486584915494302489085448797550220968172162395801092718067382520387865846016304742812817950893567306100323257425774240583525879023115828067859116694439951385967346857141860745861140565734987548429540657577310565594767849384234925486761363403985409243612714651179984216782
Request 100/1024
Request 200/1024
Request 300/1024
Request 400/1024
Request 500/1024
Request 600/1024
Request 700/1024
Request 800/1024
Request 900/1024
Request 1000/1024
b'flag{fake_flag}'

```