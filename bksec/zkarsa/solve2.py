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