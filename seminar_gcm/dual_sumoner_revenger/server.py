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
            # Nếu tag không khớp, chỉ in ra thông báo và cho vòng lặp chạy tiếp
            print("Summon failed! The tags did not match.")