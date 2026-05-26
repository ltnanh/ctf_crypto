from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.number import getPrime
import time
import os

FLAG = b'HTB{This_is_local_flag}'

class KorviaLedger:
    def __init__(self):
        self.POW_hardness = 50 # 50 bits seems reasonable
        self.n = getPrime(256)
        while True:
            self.a = getPrime(256)
            self.b = getPrime(256)
            if self.a < self.n and self.b < self.n:
                break
        genesis_block = sha256(b"Korvia command channel genesis").digest()
        self.ledger = [self.ledger_hash(genesis_block)]
        
    def ledger_hash(self, data):
        hash = (self.a * bytes_to_long(data) + self.b) % self.n
        return hash
    
    def validate_block(self, blockdata, nonce):
        hash = self.ledger_hash(long_to_bytes(self.ledger[-1]) + blockdata + nonce)
        hash_bits = bin(hash)[2:]
        hash_bits = "0"*(256 - len(hash_bits)) + hash_bits
        if hash_bits[:self.POW_hardness] == self.POW_hardness*"0":
            self.ledger.append(hash)
            return True
        else:
            return False
         
def generate_proxy_transactions(tx_count):
    block_data = b""
    for i in range(tx_count):
        block_data += b"Proxy 0x" + os.urandom(8).hex().encode() + b" delivered payload to asset 0x" + os.urandom(8).hex().encode() + b"\n"
    return block_data

def main():
    print("Task Force Nightfall — intercepting DeadDrop Cartel proxy-payment ledger. Mine 100 blocks before the window closes.")
    korvia_ledger = KorviaLedger()
    a = korvia_ledger.a
    b = korvia_ledger.b
    n = korvia_ledger.n
    print(f"Ledger hash parameters are {a = }, {b = } and {n = }")

    timeout = 30
    start = time.time()
    while time.time() < start + timeout:
        next_block_data = generate_proxy_transactions(3)
        print("Validate proxy transaction batch:")
        print(next_block_data.decode())
        nonce = bytes.fromhex(input("Enter block nonce in hex: "))
        assert len(nonce) == 32
        if not korvia_ledger.validate_block(next_block_data, nonce):
            print("[REJECTED] Invalid nonce. Vane's operators have been alerted.")
            break
        elif len(korvia_ledger.ledger) > 100:
            print("[SUCCESS] Ledger breached. Flag payload: " + hex(korvia_ledger.ledger_hash(FLAG))[2:])
            break
        else:
            print("[VALIDATED] Block accepted. Proceed to next intercept.")

    if time.time() > start + timeout:
        print("[TIMEOUT] Window closed. Korvia shifted their routing.")

if __name__ == '__main__':
    main()