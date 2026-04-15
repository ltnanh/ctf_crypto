from sage.all import * 
from pwn import * 
import os 

F.<x> = GF(2^128, name='x', modulus=x^128 + x^7 + x^2 + x + 1)


def bytes_to_F(block):
    res = F(0)
    bits = bin(int.from_bytes(block, 'big'))[2:].zfill(128)
    for i in range(128):
        if bits[i] == '1':
            res += x^i
    return res

def F_to_bytes(f_elem):
    coeffs = f_elem.polynomial().list()
    coeffs = coeffs + [0] * (128 - len(coeffs))
    bit_string = "".join(str(int(c)) for c in coeffs)
    return int(bit_string, 2).to_bytes(16, 'big')


def excute_H(tag1,tag2,plt1,plt2):
    sqrH = (tag1+tag2)/(plt1+plt2)
    H = sqrH.sqrt()
    return H 


def find_H(r,sum_num):
    plt1 = os.urandom(16)
    plt2 = os.urandom(16)
    differ = bytes_to_F(plt1) + bytes_to_F(plt2)
    lookup = {}
    for i in range(256):
        r.sendlineafter(b"[1] summon, [2] dual summon >", str(1).encode())
        r.sendlineafter(b"summon number (1 or 2) >", str(sum_num).encode())
        r.sendlineafter(b"sacrifice (hex) >" ,plt1.hex().encode())
        r.recvuntil(b"tag(hex) = ")
        tag1 = bytes.fromhex(r.recvline().decode())
        r.recvuntil(b"ciphertext(hex) = ")
        c1 = bytes.fromhex(r.recvline().decode())
        if c1 not in lookup:
            lookup[c1] = tag1

    for i in range(256):
        r.sendlineafter(b"[1] summon, [2] dual summon >", str(1).encode())
        r.sendlineafter(b"summon number (1 or 2) >", str(sum_num).encode())
        r.sendlineafter(b"sacrifice (hex) >" ,plt2.hex().encode())
        r.recvuntil(b"tag(hex) = ")
        tag2 = bytes.fromhex(r.recvline().decode())
        r.recvuntil(b"ciphertext(hex) = ")
        c2 = bytes.fromhex(r.recvline().decode())
        c1_trial = F_to_bytes(bytes_to_F(c2) + differ)

        if c1_trial in lookup:
            tag1 = lookup[c1_trial]
            H = excute_H(bytes_to_F(tag1), bytes_to_F(tag2), bytes_to_F(plt1), bytes_to_F(plt2))
            return H,bytes_to_F(tag1), bytes_to_F(plt1)
    return None 
            

def solve_dual_sommon(r):
    #find H1 for key1
    res1 = find_H(r,1)
    if res1 is None:
        print("nonce len may be than 1 byte")
        return False
    H1, tag11, plt11 = res1
    print(f"\nH1 = {H1}")
    
    #find H2 for key2
    res2 = find_H(r,2)
    if res2 is None:
        print("nonce len may be than 1 byte")
        return False
    H2, tag21, plt21 = res2
    print(f"\nH2 = {H2}")
    


    #compte key plaintext of problem with H1 and H2 
    const_tag1 = tag11 - plt11*(H1^2)
    const_tag2 = tag21 - plt21*(H2^2)

    plt = (const_tag2 - const_tag1)/(H1^2 - H2^2)
    plt = F_to_bytes(plt)


    trial = 0 
    for i in range(300^2):
        trial += 1 
        r.sendlineafter(b"[1] summon, [2] dual summon >", str(2).encode())
        r.sendlineafter(b"name of sacrifice (hex) >" ,plt.hex().encode() )
        response = r.recvline()
        if b"Wow! you could exec dual_summon!" in response:
            print("\nSuccess after {} trials".format(trial))
            print(r.recvline())
            return True
        else:
            continue

    print('Failed to solve dual summon in 300^2 tries')
    return False






HOST = '127.0.0.1'
PORT = 1337
context.log_level = 'info'

while True:
    r = remote(HOST, PORT)
    if solve_dual_sommon(r):
        break
    r.close()






