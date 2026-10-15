from sage.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib

p = 57896044618658103051097247842201434560310253892815534401457040244646854264811
a = 57896044618658103051097247842201434560310253892815534336455328262589759096811
b = 6378745995050415640528904257536000
E = EllipticCurve(GF(p), [a, b])

G = E(46876917648549268272641716936114495226812126512396931121066067980475334056759 ,29018161638760518123770904309639572979634020954930188106398864033161780615057) 
PA = E(41794565872898552028378254333448511042514164360566217446125286680794907163222 , 28501067479064047326107608780246105661757692260405498327414296914217192089882)
PB = E(832923623940209904267388169663314834051489004894067103155141367420578675552 , 7382962163953851721569729505742450736497607615866914193411926051803583826592 )
iv_hex = "478876e42be078dceb3aee3a6a8f260f"
encrypted_hex = "e31e0e638110d1e5c39764af90ac6194c1f9eaabd396703371dc2e6bb2932a18d824d86175ab071943cba7c093ccc6c6"


def smart_attack(P, G, p):

    E = G.curve()
    
    # Nâng đường cong lên trường số p-adic Q_p với độ chính xác O(p^2)
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + O(p**2) for t in E.a_invariants()])

    # Nâng điểm G lên Q_p
    G_Zp = Eqp.lift_x(ZZ(G.x()), all=True)
    for pt in G_Zp:
        if GF(p)(pt.y()) == G.y():
            G_qp = pt
            break

    # Nâng điểm P lên Q_p
    P_Zp = Eqp.lift_x(ZZ(P.x()), all=True)
    for pt in P_Zp:
        if GF(p)(pt.y()) == P.y():
            P_qp = pt
            break

    # Nhân các điểm với p
    p_G = p * G_qp
    p_P = p * P_qp

    # Lấy tọa độ
    x_G, y_G = p_G.xy()
    x_P, y_P = p_P.xy()

    # Tính p-adic elliptic logarithm: phi(Q) = -(x/y)
    phi_G = -(x_G / y_G)
    phi_P = -(x_P / y_P)

    # Khóa bí mật chính là tỷ lệ của hai logarit này modulo p
    d = ZZ(phi_P / phi_G) % p
    return d

dA_cracked = smart_attack(PA, G, p)
print(f"dA: {dA_cracked}")
assert dA_cracked * G == PA


# 3. compute secret key s 
shared_point = dA_cracked * PB
s = int(shared_point.x())
print(f"s: {s}")

# 4. decrypt AES 
key = hashlib.sha256(int(s).to_bytes((s.bit_length() + 7) // 8, 'big')).digest()
iv = bytes.fromhex(iv_hex)
encrypted_data = bytes.fromhex(encrypted_hex)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
flag = unpadder.update(padded_data) + unpadder.finalize()

print(f"FLAG: {flag.decode('utf-8')}")