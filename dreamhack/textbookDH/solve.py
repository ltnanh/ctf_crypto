from pwn import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

context.log_level = 'error'

def decrypt(ct_hex, shared_key):
    aes_key = hashlib.md5(str(shared_key).encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(bytes.fromhex(ct_hex)), 16).decode()


r = remote("host3.dreamhack.games", 19884)


r.recvuntil(b"Prime: ")
p = int(r.recvline().strip(), 16)
print(f"Prime (p): {hex(p)}")


r.recvuntil(b"Alice sends her key to Bob. Key: ")
A = int(r.recvline().strip(), 16)
print(f"Alice's Public Key (A): {hex(A)}")

r.recvuntil(b">> ")
r.sendline(b"4")


r.recvuntil(b"Bob sends his key to Alice. Key: ")
B = int(r.recvline().strip(), 16)
print(f"Bob's Public Key (B): {hex(B)}")

r.recvuntil(b">> ")
r.sendline(b"4")


r.recvuntil(b"Alice: ")
ct_alice = r.recvline().strip().decode()
r.recvuntil(b"Bob: ")
ct_bob = r.recvline().strip().decode()

print(f"Alice CT: {ct_alice}")
print(f"Bob CT: {ct_bob}")


sk_alice = pow(A, 2, p) 
sk_bob = pow(B, 2, p)   

flag_part1 = decrypt(ct_alice, sk_alice)
flag_part2 = decrypt(ct_bob, sk_bob)

print(f"Flag: {flag_part1 + flag_part2}")

r.close()