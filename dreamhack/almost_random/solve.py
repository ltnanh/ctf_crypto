
import base64
import os
import random
import struct
import sys
import textwrap
from pwn import *

def b64u_enc_u32(x):
    raw = struct.pack(">I", x & 0xFFFFFFFF)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_dec_u32(s):
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode())
    if len(raw) != 4:
        raise ValueError("bad length")
    return struct.unpack(">I", raw)[0]


def tempering(y):
    y = y ^(y>>11)
    y = y^((y<<7) & 0x9d2c5680)
    y = y^((y<<15) & 0xefc60000)
    y = y ^(y>>18)

    return y


def untempering(y):
    y = y ^(y>>18)

    y = y^((y<<15) & 0xefc60000)

    temp = y
    for _ in range(4):
        temp = y ^ ((temp << 7) & 0x9d2c5680)
    y = temp

    temp = y
    for _ in range(2):
        temp = y ^ (temp >> 11)
    y = temp

    return y 


def twist(states):
    new_states = [0] * 624 

    N = 624
    M = 397 
    A = 0x9908b0df
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7fffffff
    for i in range(N):
        x = (states[i] & UPPER_MASK) | (states[(i+1)%N] & LOWER_MASK)
        xA = x >> 1
        if x % 2 != 0:
            xA = xA ^ A
        new_states[i] = states[(i+M)%N] ^ xA

    return new_states


def main():
    r = remote("host3.dreamhack.games", 21643)

    states = []

    for _ in range(624):
        r.sendline(str(1).encode())
        r.recvuntil(b"]: ")
        token = r.recvline().strip().decode()
        val = b64u_dec_u32(token)
        state = untempering(val)
        print(state)
        states.append(state)
    
    new_states = twist(states)
    next_val = tempering(new_states[0])
    next_token = b64u_enc_u32(next_val)
    print("Next token:", next_token)
    
    r.sendline(str(2).encode())
    r.sendline(next_token.encode())
    print(r.recvall().decode())


main()





