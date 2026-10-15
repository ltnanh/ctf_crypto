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
