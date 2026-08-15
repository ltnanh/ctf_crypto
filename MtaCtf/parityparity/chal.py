import sys
from Crypto.Util.number import getPrime, bytes_to_long
import os

flag = os.getenv('FLAG', 'flag{fake_flag}').encode()

def generate_keys():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    d = pow(e, -1, (p-1) * (q-1))
    return (n, e), d

def main():
    pub, priv = generate_keys()
    n, e = pub
    d = priv

    m = bytes_to_long(flag)
    c = pow(m, e, n)

    print(f"N = {n}")
    print(f"e = {e}")
    print(f"flag_enc = {c}")

    for i in range(1024):
        try:
            user_input = input(f"[{i+1}/1024] Enter ciphertext (integer): ")
            ct = int(user_input)
            pt = pow(ct, d, n)
            
            print(f"Parity: {pt % 2}")
            
        except ValueError:
            print("Invalid input.")
            break
        except EOFError:
            break

if __name__ == "__main__":
    main()