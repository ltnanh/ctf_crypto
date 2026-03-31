from sage.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from random import randint
import hashlib
import os

p = 57896044618658103051097247842201434560310253892815534401457040244646854264811

# y^2 = x^3 + 57896044618658103051097247842201434560310253892815534336455328262589759096811*x + 6378745995050415640528904257536000
a = 57896044618658103051097247842201434560310253892815534336455328262589759096811
b = 6378745995050415640528904257536000
E = EllipticCurve(GF(p), [a, b])

# ECDH
G = E.random_point()
print(f"{G=}")
dA = randint(2, G.order())
dB = randint(2, G.order())

PA = dA * G
PB = dB * G

print(f"{PA=}")
print(f"{PB=}")

s = int((dB * PA).x())
key = hashlib.sha256(int(s).to_bytes((s.bit_length() + 7) // 8, 'big')).digest()

# AES encryption
with open('flag.txt', 'rb') as infile:
  flag = infile.read()

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

padder = padding.PKCS7(128).padder()
padded_data = padder.update(flag) + padder.finalize()

encrypted = encryptor.update(padded_data) + encryptor.finalize()

print('Encrypted data:', encrypted.hex())
print('IV:', iv.hex())
