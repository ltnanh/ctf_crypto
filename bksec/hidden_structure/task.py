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



