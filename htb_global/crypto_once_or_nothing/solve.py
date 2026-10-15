#!/usr/bin/env python3
from pwn import *
import re
import binascii

context.log_level = 'error'

def get_token(io, hex_msg):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'hex: ', hex_msg.encode())
    
    all_data = b''
    while b'Token issued:' not in all_data:
        all_data += io.recvline()
    
    token_line = all_data.decode()
    while ']' not in token_line:
        token_line += io.recvline().decode()
    
    hex_numbers = re.findall(r'Uint\(0x([0-9A-Fa-f]{64})\)', token_line)
    tokens = [int(h, 16) for h in hex_numbers]
            
    return tokens


def main():
    host = 'localhost'
    port = 1337 
    io = remote(host, port)
    
    #token of msg1 
    msg1 = b'd' + b'\xff' * 10
    hex_msg1 = binascii.hexlify(msg1).decode()
    token1 = get_token(io, hex_msg1)
    print(f"Done token for msg1")
    print(f"Token1: {token1[:10]}...") 
    
    #token of msg2
    msg2 = b'9_netadmin'
    hex_msg2 = binascii.hexlify(msg2).decode()
    token2 = get_token(io, hex_msg2)
    print(f"Done token for msg2")
    print(f"Token2: {token2[:10]}...")
    
    #combine token1 and token2 to find token of target msg 
    target = b'd9_netadmin'
    final_token = token1[:176] + token2[176:]
    print(f"Done token for target msg")
    print(f"Target token: {final_token[:10]}...")
    
    #send token of target msg and get flag 
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'validate: ', target)
    
    token_hex_str = ','.join(f"{t:064x}" for t in final_token)
    io.sendlineafter(b'hex): ', token_hex_str.encode())
    
    try:
        print(io.recvline(timeout=3).decode())
    except Exception as e:
        print(f"Error: {e}")
    io.close()

if __name__ == '__main__':
    main()