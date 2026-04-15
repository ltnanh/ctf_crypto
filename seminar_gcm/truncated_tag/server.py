import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
ORIGINAL_PLT = b"Giao dich 1001: Chuyen 10 USD"
KEY_PLT = b"Give me flag"
FLAG = "FLAG{GCM_Trunc4t3d_M4c_1s_D4ng3r0us}"


def gf_mult(x, y):
        R = 0xE1000000000000000000000000000000
        Z, V = 0, x
        for i in range(128):
            if (y >> (127 - i)) & 1: Z ^= V
            V = (V >> 1) ^ R if V & 1 else V >> 1
        return Z


def get_client_data():
    nonce = os.urandom(12)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(ORIGINAL_PLT)
    
    return {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex() 
    }



def oracle_verify(nonce, ct, tag):
    nonce = bytes.fromhex(nonce)
    ct = bytes.fromhex(ct)
    user_tag = bytes.fromhex(tag)
    
    H_bytes = AES.new(KEY, AES.MODE_ECB).encrypt(b'\x00'*16)
    H = int.from_bytes(H_bytes, 'big')
    
    cipher_mask = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    _, mask_bytes = cipher_mask.encrypt_and_digest(b"")
    mask = int.from_bytes(mask_bytes, 'big')
    
    blocks = [int.from_bytes(ct[i:i+16], 'big') for i in range(0, len(ct), 16)]
    blocks.append(len(ct) * 8) 
    
    actual_tag = 0
    for b in blocks:
        actual_tag = gf_mult(actual_tag ^ b, H)

    actual_tag = (actual_tag ^ mask).to_bytes(16, 'big')
    
    return user_tag[:1] == actual_tag[:1]



def admin_verify(nonce, ct, tag):
    nonce = bytes.fromhex(nonce)
    ct = bytes.fromhex(ct)
    user_tag = bytes.fromhex(tag)
    
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    
    try:
        plt = cipher.decrypt_and_verify(ct, user_tag)
        if KEY_PLT in plt:
            return f"SUCCESS: {FLAG}"
        return "Authenticated, but unknown command."
    except ValueError:
        return "FAILED: Invalid MAC."



if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(line_buffering=True) 
    
    intercepted = False
    
    while True:
        print("\n1. Client  |  2. Oracle  |  3. Admin  |  4. Exit")
        try:
            choice = input("Select: ").strip()
            
            if choice == '1':
                if not intercepted:
                    data = get_client_data()
                    print(f"Nonce: {data['nonce']}\nCT: {data['ciphertext']}\nTag: {data['tag']}")
                    intercepted = True
                else:
                    print("You already intercepted the data!")
                    
            elif choice == '2':
                nonce = input("Nonce (hex): ")
                ct = input("CT (hex): ")
                tag = input("Tag (hex)(1 byte): ")
                
                try:
                    if oracle_verify(nonce, ct, tag):
                        print("Valid Tag!")
                    else:
                        print("Invalid Tag!")
                except Exception as ex:
                    print(f"SERVER CRASHED: {ex}")
                    
            elif choice == '3':
                nonce = input("Nonce (hex): ")
                ct = input("CT (hex): ")
                tag = input("Tag (hex)(16 byte): ")
                
                print(f"{admin_verify(nonce, ct, tag)}")
                
            elif choice == '4':
                break
        except Exception as e:
            print(f"Bad input: {e}")