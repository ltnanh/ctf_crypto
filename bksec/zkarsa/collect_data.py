from pwn import *

HOST = '100.64.0.66'
PORT = 31700

list_x = []
list_e = []
list_y = []

r = remote(HOST, PORT)

r.recvline()
r.recvline()

N = int(r.recvline().strip())
print(f"[+] Đã nhận N: {N}")
enc_flag = 0 

try:
    for i in range(500):

        r.recvuntil(b"CHALLENGE ME!!! ")

        # chọn e khác nhau mỗi lần
        e_challenge = (2**80 - 1) - i

        r.sendline(str(e_challenge).encode())

        response = r.recvline().decode().strip().split()

        if len(response) == 3:
            x_val = int(response[0])
            e_val = int(response[1])
            y_val = int(response[2])

            list_x.append(x_val)
            list_e.append(e_val)
            list_y.append(y_val)

            if (i + 1) % 50 == 0:
                print(f"[*] Đã thu thập: {i + 1}/500")

        else:
            print(f"[!] Lỗi format lần {i}")

    print("[*] Đang nhận ciphertext flag...")

    r.recvuntil(b"Here's your FLAG hehehe")
    flag_data = r.recvall().decode().strip() 
    if flag_data:
        enc_flag = int(flag_data)
        print(f"[+] Đã nhận FLAG mã hóa: {enc_flag}") 
    else:
        print("[!] Không nhận được dữ liệu FLAG!")

except EOFError:
    print("[!] Server đóng kết nối sớm")

r.close()

print(f"[*] Thu thập x: {list_x}...")
print(f"[*] Thu thập e: {list_e}...")
print(f"[*] Thu thập y: {list_y}...")
print(f"[*] Thu thập FLAG mã hóa: {enc_flag}...")
