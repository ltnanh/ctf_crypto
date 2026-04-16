# Dual summoner revenger 

## 1, Challenge overview 
- code server 
```python
from Crypto.Cipher import AES
import secrets
import os
import signal
import random 

signal.alarm(300)

flag = os.getenv('flag', "SECCON{nonc3_i5_Imp0rtant_1n_9Cm}")

keys = [secrets.token_bytes(16) for _ in range(2)]
len_nonce = random.randint(1, 11)

def summon(number, plaintext):
    assert len(plaintext) == 16
    nonce = os.urandom(len_nonce)
    aes = AES.new(key=keys[number-1], mode=AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(plaintext)
    return ct, tag

# When you can exec dual_summon, you will win
def dual_summon(plaintext):
    assert len(plaintext) == 16
    nonce1 = os.urandom(len_nonce)
    nonce2 = os.urandom(len_nonce)
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce1)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce2)
    ct1, tag1 = aes1.encrypt_and_digest(plaintext)
    ct2, tag2 = aes2.encrypt_and_digest(plaintext)
    # When using dual_summon you have to match tags
    assert tag1 == tag2

print("Welcome to summoning circle. Can you dual summon?")
while True:
    mode = int(input("[1] summon, [2] dual summon >"))
    if mode == 1:
        number = int(input("summon number (1 or 2) >"))
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        ct, tag = summon(number, name)
        print(f"monster name = [---filtered---]")
        print(f"tag(hex) = {tag.hex()}")
        print(f"ciphertext(hex) = {ct.hex()}")

    if mode == 2:
        name = bytes.fromhex(input("name of sacrifice (hex) >"))
        try:
            dual_summon(name)
            print("Wow! you could exec dual_summon! you are master of summoner!")
            print(flag)
            break
        except AssertionError:
            print("Summon failed! The tags did not match.")
```



- There a 2 object in server is summon and dual_summon
- Each object has 2 AES key k1 and k2 
### Contact with server 
- Mode 1: Summoner : request server to encrypt a chosen plaintext with k1 or k2 and response correspond ciphertxt and tag 
- Mode 2: Dual summoner : give server a plaintext , If the tag when encrypt the plaintext by 2 key is the same => achieve the flag 
- Unlimited contact with 2 object 

## 2 , Attack strategy 

### 2.1 , Weakness 
**Short nonce ?**
- Server choose a random number to be len of nonce 
```python
len_nonce = random.randint(1, 11)
```
=>   The server will almost have 1 time use 1 byte nonce after few session

=>   It is easy to find IV collision if server use 1 byte nonce 

### 2,2 , Exploit script 
### Forbidden attack to a nonce collision 
- Give many plaintext for summon to achive correspond cihpertext adn tag 
- With plaintex $P_i$ , $P_j$ and corresponding ciphertext $C_i$ , $C_j$ .If :
  
- $$P_i - C_i = P_j - C_j $$

  - => Nonce collision 
  
  - Then we can use forbidden attack to find corresponding hash key H 
- To optimize search time
    - Send $P_i$ about 256 time , then save ciphertext ,tag in a lookup table 
    - Then send $P_j$ and check for collision 
- So that we can find $H$ and $Mask = Enc(IV)$ of the nonce
  
### Dual summon 
- For $K_1$ , implemet like above and we can find $H_1$  and $Mask_1$ corresponding to the nonce in collision 
- For $K_2$ , implemet like above and we can find $H_2$  and $Mask_2$ corresponding to the nonce in collision 
- To solve dual_summon ,assume that two nonce that the function choose is corresponding to $Mask_1$ and $Mask_2$ 
  - =>  we need to find a plaintext $P$ (16 bytes) s.t:
  
$$tag1 = tag2 $$

$$<=> C_1 \cdot H_1^2 + lenblock \cdot H_1 + Mask_1 =  C_2 \cdot H_2^2 + lenblock \cdot H_2 + Mask_2$$

$$<=> (P + Ks_1)\cdot H_1^2 + lenblock \cdot H_1 + Mask_1 = (P + Ks_2)\cdot H_2^2 + lenblock \cdot H_2 + Mask_2$$

$$<=> P \cdot H_1^2 + const1 = P \cdot H_2^2 + const2 $$

$$P = \frac{const2 - const1}{H_1^2 - H_2^2}$$

- So we can compute $P$ like that 
- **But can two nonce that the function choose is corresponding to $Mask_1$ and $Mask_2$** ?
  - Cause using 1 byte nonce, send $P$ to server about $256^2$ times and we will almost certeinly achieve the flag 
## 3, Exploit code

```python
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

```

