from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sympy import sqrt_mod
from sympy.ntheory.modular import crt
from math import isqrt

s = 485391067385099231898174017598 
n = 71016310005824589926747341243598522145452505235842335510488353587223142066921470760443852767377534776713566052988373656012584808377496091765373981120165220471527586994259252074709653090148780742972203779666231432769553199154214563039426087870098774883375566546770723222752131892953195949848583409407713489831      
e = 65537      
D = 9478993126102369804166465392238441359765254122557022102787395039760473484373917895152043164556897759129379257347258713397227019255397523784552330568551257950882564054224108445256766524125007082113207841784651721510041313068567959041923601780557243220011462176445589034556139643023098611601440872439110251624
c = 1479919887254219636530919475050983663848182436330538045427636138917562865693442211774911655964940989306960131568709021476461747472930022641984797332621318327273825157712858569934666380955735263664889604798016194035704361047493027641699022507373990773216443687431071760958198437503246519811635672063448591496

def hkdf_mask(secret: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"rsa-d-mask",
        backend=default_backend()
    )
    return hkdf.derive(secret)

# factorize n 
def factor_with_d_algebraic(n, e, d):
    
    k_est = (e * d) // n
    
    for k in range(k_est, k_est + 3):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
            
        phi_n = (e * d - 1) // k
        S = n - phi_n + 1
        delta = S * S - 4 * n
        if delta < 0:
            continue
        sq_delta = isqrt(delta)
        if sq_delta * sq_delta == delta: 
            q1 = (S + sq_delta) // 2
            q2 = (S - sq_delta) // 2      
            if q1 * q2 == n:
                return q1, q2           
    return None


d = None
q1 = None
q2 = None

# d.bit_length() // 8 thường là 128 (đối với khóa 1024-bit) hoặc 127
for length in [128, 127, 126, 129]:
    mask = bytes_to_long(hkdf_mask(long_to_bytes(s), length))
    test_d = D ^ mask
    
    result = factor_with_d_algebraic(n, e, test_d)
    if result:
        q1, q2 = result
        d = test_d
        print(f"q1 = {q1}")
        print(f"q2 = {q2}")
        break

if not d:
    print("Cant find d")
    exit()



r1 = sqrt_mod(c, q1, all_roots=True)
r2 = sqrt_mod(c, q2, all_roots=True)

count = 0
for m1 in r1:
    for m2 in r2:
        #(CRT)
        m_root, _ = crt([q1, q2], [m1, m2])

        try:
            flag_text = long_to_bytes(m_root).decode('utf-8')
            count += 1
            print(f"\n[Sol{count}] => {repr(flag_text)}")
        except UnicodeDecodeError:
            pass

if count == 0:
    print("Cant find any valid flag")