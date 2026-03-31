# Almost random

## 1,Challenge overview 
- challenge give me 700 times to request to server
- A request can be 
    - get a token 
    - guess next token 
- We will achieve the flag if we guess true next token (only need to guess true 1 time)

- the token is gen by a rng using **random** lib in python 

## 2,Attack strategy
### 2.1 , The random.seed generator 
- The PRNG of challenge
```python
    rng = random.Random()
    rng.seed(int.from_bytes(os.urandom(16), "big"))
```
- To gen a token 
```python
    val = rng.getrandbits(32)
    tok = b64u_enc_u32(val)
```

- The PRNG using Mersenne Twister algorithm ,which use a 624 state to gen 32 bit random number 
- with a seed , the PRNG inital a 624-state 
- when call the first 32 bit random number , twist the 624 state to achieve new state

    - ```python
        N = 624
        M = 397
        MATRIX_A = 0x9908b0df
        UPPER_MASK = 0x80000000
        LOWER_MASK = 0x7fffffff

        for i in range(N):
            x = (state[i] & UPPER_MASK) | (state[(i + 1) % N] & LOWER_MASK)
            xA = x >> 1
            if x & 1:
                xA ^= MATRIX_A
            new_state[i] = state[(i + M) % N] ^ xA
        ```

- the random number from 0 to 623 will be indexed from this new_state list and then tempering.
    - with y = state[i] indexed , we tempering y to get the output 
    - ```python
        def tempering(y):
        y = y ^(y>>11)
        y = y^((y<<7) & 0x9d2c5680)
        y = y^((y<<15) & 0xefc60000)
        y = y ^(y>>18)

        return y
        ```
- after 624 indexed in state , twist the current state to get new state for next 623 random number 


## 2.2 ,Attack the PRNG

- We will get the first 624 random number of the PRNG
- for each random number , untempering to achieve the corresponding number in state
- when we have full 624-state , we will twist the state to get the new state for next 624 number 
- $=>$ we can index the first number of new state , them tempering it to have the next random number => next token 

## 3,Exploit code
```python

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

```
