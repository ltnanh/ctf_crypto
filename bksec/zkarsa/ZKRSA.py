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
