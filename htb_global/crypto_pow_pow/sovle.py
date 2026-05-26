from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import hashlib
import re

io = remote('localhost', 1337)

init_data = io.recvuntil(b"n =").decode()
a = int(re.search(r"a = (\d+)", init_data).group(1))
b = int(re.search(r"b = (\d+)", init_data).group(1))
n_line = io.recvline().decode().strip()
n = int(n_line)

print("a = ",a)
print("b = ",b)
print("n = ",n)

genesis_block = hashlib.sha256(b"Korvia command channel genesis").digest()
current_hash = (a * bytes_to_long(genesis_block) + b) % n



a_inv = inverse(a, n)

for i in range(100):
    io.recvuntil(b"Validate proxy transaction batch:\n")
    tx1 = io.recvline()
    tx2 = io.recvline()
    tx3 = io.recvline()
    block_data = tx1 + tx2 + tx3
    
    io.recvuntil(b"Enter block nonce in hex: ")
    
    prefix = long_to_bytes(current_hash) + block_data
    prefix_long = bytes_to_long(prefix)
    C = (a * (prefix_long << 256) + b) % n
    target_nonce = (-C * a_inv) % n
    
    nonce_hex = hex(target_nonce)[2:].rjust(64, '0')
    io.sendline(nonce_hex.encode())
    
    #recv flag after sent the last block hash 
    if i == 99:
        io.recvuntil(b'Flag payload: ')
        flag_hash_hex = io.recvline().decode() 
        flag_hash_int = int(flag_hash_hex, 16)
            
        flag_int = ((flag_hash_int - b) * a_inv) % n
        flag = long_to_bytes(flag_int)
        
        print(flag)
        break 
        
    #recv response for the block from 1 -> 99     
    result = io.recvline().decode().strip()
    if "[VALIDATED]" not in result:
        print(f"Failed at block {i+1}: {result}")
        break
        

    current_hash = 0