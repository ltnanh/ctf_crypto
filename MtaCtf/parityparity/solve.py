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