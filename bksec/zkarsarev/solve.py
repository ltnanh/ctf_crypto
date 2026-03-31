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
        
        e_val = -(10**4300 // mid)
        
        r.sendline(str(e_val).encode())
        
        response = r.recvline().decode().strip()
    
        if "ERR" in response:

            low = mid + 1
        else:
        
            high = mid
            
    
    r.recvuntil(b"Here's your FLAG hehehe\n")
    enc_flag = int(r.recvall().decode().strip())
    print(enc_flag)

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
            print(S_candidate)
            break

if p and q:
   
    PHI = (p - 1) * (q - 1)
    e_rsa = 65537
    d = pow(e_rsa, -1, PHI)
    m = pow(enc_flag, d, N)
    
    print(long_to_bytes(m).decode())