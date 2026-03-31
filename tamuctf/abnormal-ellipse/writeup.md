# Abnormal ellipse

## 1,Challenge Overview 

- System use Elliptic Curve Diffie Hellman key exchange to generate key for AES encryption 
- ECDH components 
  
    - $p=57896044618658103051097247842201434560310253892815534401457040244646854264811$
    - $a = 57896044618658103051097247842201434560310253892815534336455328262589759096811$
    - $b = 6378745995050415640528904257536000$
    - Curve: $y^2=x^3+ax+b \pmod{p}$
    - Key exchange:
        ```sage
        dA = randint(2, G.order())
        dB = randint(2, G.order())
        PA = dA * G
        PB = dB * G
        s = int((dB * PA).x())
        key = hashlib.sha256(int(s).to_bytes((s.bit_length() + 7) // 8, 'big')).digest()

- AES Encryption
    - pad flag
    - encrypt padded flag with generated key by AES in CBC mode 

- Ouput 
    - point $G,Pa,Pb$
    - $encrypted flag + IV$

## 2, Attack strategy 
### 2,1 Basic idea 
- Seem that we can only found weekness if we analysis the given elliptic curve 
- Try to solve ECDH Problem to find secret s 
- recover key and decrypt ciphertext 

### 2,2 Analysis the curve 
- when I try finding order of elliptic curve 
    ```sage
    E = EllipticCurve(GF(p), [a, b])
    N = E.order()
    ```
- I found a interesting result 
    ```bash
    order of the curve: N = 57896044618658103051097247842201434560310253892815534401457040244646854264811
    order equal to modulus
    ```
- $order=p =>$ this is **Anomalous Curve**
  
  $=>$ We can use **Smart Attack** to solve the ECDHP with complexity $O(\log^3 n)$

### 2,3 Smart attack 
- Lifting to $\mathbb{Q}_p$ :
    -  The algorithm lifts the elliptic curve and the points P,G from the discrete space GF(p) to a much larger infinite field: the p-adic number field 	
    - For efficiency, it is sufficient to work with precision $O(p^2)$
- Mapping into the Formal Group:
    - Map point $P$ and $G$ to $\mathbb{Q}_p$
    - Since the order of the point is p, over $GF(p)$ we have $p×G=O$. However, in the new space $\mathbb{Q}_p$ , $p×G$ lies in a neighborhood of the point at infinity.
- p-adic Elliptic Logarithm:
    - Near the point at infinity, there exists a function $ψ$ : it transforms point multiplication into scalar multiplication
    $$
    ψ(Q)\approx-\frac{x}{y}
    $$
    - Since $ψ(P) = d.ψ(G)=>d = ψ(P)/ψ(G)$


### 2,4 Decrypt flag 
- We can use smart attack to solve ECDH and find $dA =>$ recover point $s =>$ recover key 
- Then use AES decrypt to achieve flag 

## 3, Exploit code 

```sage
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
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + O(p**2) for t in E.a_invariants()])

    G_Zp = Eqp.lift_x(ZZ(G.x()), all=True)
    for pt in G_Zp:
        if GF(p)(pt.y()) == G.y():
            G_qp = pt
            break

    P_Zp = Eqp.lift_x(ZZ(P.x()), all=True)
    for pt in P_Zp:
        if GF(p)(pt.y()) == P.y():
            P_qp = pt
            break

    p_G = p * G_qp
    p_P = p * P_qp

    x_G, y_G = p_G.xy()
    x_P, y_P = p_P.xy()

    phi_G = -(x_G / y_G)
    phi_P = -(x_P / y_P)

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
```