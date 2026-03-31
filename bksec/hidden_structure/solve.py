from math import isqrt
from Crypto.Util.number import long_to_bytes


def recover_xy(S, P):
    D = S*S - 4*P
    if D < 0:
        return None
    r = isqrt(D)
    if r*r != D:
        return None
    x = (S + r) // 2
    y = (S - r) // 2
    return x, y


N = 107444638859099155759777187090231262569833054720517547475456101236477286061642951211232522980016935214117151901316067288134076019258357378153815894696105422994651894516549086845637403949534145390050746353299397783409065996987527927026314423191436300386280922075865669873754956335784354470237039709346406222789
e = 65537
c = 56143710973900761339774002971192037727375234874650436422245945684342980716505499471085786012340621409106405319356586450688993792522513823502401085339774194961300841598824881056390845294225756335102709315028822707701848497421372062559501439381841852116763699839771135406441292657937478625029095325072727620068

B = 1 << 256

bin_N = bin(N)[2:].zfill(1024)

# lấy low 256 bits của xy
low_xy = int(bin_N[-256:], 2)

print("low_xy =", low_xy)

# brute high bits
for shift in range(-8, 9):
    approx_high = int(bin_N[:256], 2) + shift
    for mid in [0,1]:
        xy = (approx_high << 256) | (mid << 255) | low_xy
        rem = N - xy*(B*B + 1)
        if rem <= 0:
            continue
        if rem % B != 0:
            continue
        x2_y2 = rem // B
        S2 = x2_y2 + 2*xy
        if S2 < 0:
            continue
        S = isqrt(S2)
        if S*S != S2:
            continue
        print("[+] candidate xy found")
        res = recover_xy(S, xy)
        if res is None:
            continue
        x,y = res
        if x*y != xy:
            continue
        print("[+] recovered x,y")

        print(shift, mid)

        p = x*B + y
        q = y*B + x

        if p*q != N:
            continue

        print("[+] FACTORIZATION SUCCESS")
        phi = (p-1)*(q-1)
        d = pow(e, -1, phi)
        m = pow(c, d, N)
        print("FLAG:", long_to_bytes(m))
        exit()

print("[-] not found")