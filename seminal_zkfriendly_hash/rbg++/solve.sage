from sage.all import *
import itertools
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm


N = 16167885915193478051793877611486619241886473426863252783094589654879500659067740377062272392685930800102844215704528436693321982169968535528301909521740422063158802614037675785775081053858036967400526899115004867166488372889
C = [
    23524356627767287626245212608188456486510486842884944774388457118524878337010325280806281200006513760569554973350027623280980530389685273358299240165163348831178950906369654270836363037734464763165971796940465525441254094362,
    20417144512792463288144454294819320198675053687066876812066787608526065186517106068771714888222417207180901619094929565058749740851992567962732918068890150032710566113874561398162760409944385995695085324172030092973190257577,
    10520424976309587244912110505341168843522648629096918766553735784501443210882592550479277468613423963705805659813405742198752350482717828219056306550361834962704972988508557816667577007199850461049600946454322911178025895814
]

Zn = Zmod(N)
P_H.<H> = PolynomialRing(Zn)
P_B.<B> = PolynomialRing(P_H)  
P_A.<A> = PolynomialRing(P_B)


for k_seq in tqdm(list(itertools.product([0, 1, 2], repeat=5))):
    k1, k2, k3, k4, k5 = k_seq
    try:
        #TÍNH RESULTANT ĐỂ KHỬ BIẾN A 
        f0 = A^3 * B * H^k1 + A - C[0]
        A3 = (C[0] - A)^3 * B * H^k2
        f1 = A3^3 * B * H^k3 + A3 - C[1]
        res1 = f0.resultant(f1) 

        g1 = A^3 * B * H^k3 + A - C[1]
        A5 = (C[1] - A)^3 * B * H^k4
        g2 = A5^3 * B * H^k5 + A5 - C[2]
        res2 = g1.resultant(g2) 


        if res1 == 0 or res2 == 0:
            continue

        f1, f2 = res1, res2

        coefs = f1.list()
        while len(coefs) > 0 and coefs[0] == 0:
            coefs = coefs[1:]
        f1 = P_B(coefs)

        coefs = f2.list()
        while len(coefs) > 0 and coefs[0] == 0:
            coefs = coefs[1:]
        f2 = P_B(coefs)

        print(f1.resultant(f2))
    
        #KHỬ BIẾN B VÀ CHẶT NGHIỆM B=0 
        while True:
            coefs = f1.list()
            while len(coefs) > 0 and coefs[0] == 0:
                coefs = coefs[1:]
            f1 = P_B(coefs)

            coefs = f2.list()
            while len(coefs) > 0 and coefs[0] == 0:
                coefs = coefs[1:]
            f2 = P_B(coefs)

            if f1.degree() < f2.degree():
                f1, f2 = f2, f1

            f1_coef = f1[f1.degree()]
            f2_coef = f2[f2.degree()]

            g = P_H(f1_coef._pari_with_name().gcd(f2_coef._pari_with_name()))
            
        
            f1 *= P_H(f2_coef._pari_with_name() / g._pari_with_name())
            f2 *= P_H(f1_coef._pari_with_name() / g._pari_with_name())

            f1 -= f2 * B^(f1.degree() - f2.degree())

            if f1.degree() == 0 or f1.degree() == -1:
                break

        if f1 == 0 or f1.degree() == -1:
            continue

        res = f1[0]#res là f(H) = 0 
        p0, p1 = f2[0] % res, f2[1] % res#p0[H]+p1[H]*B = 0 

        #đảm bảo p0,p1 ko có nghiệm H chung với res 
        while True:
            g = res._pari_with_name().gcd(p0._pari_with_name())
            if P_H(g).degree() == 0:
                break
            res = P_H(res._pari_with_name() / g)
            p0 %= res

        while True:
            g = res._pari_with_name().gcd(p1._pari_with_name())
            if P_H(g).degree() == 0:
                break
            res = P_H(res._pari_with_name() / g)
            p1 %= res

        #RÀNG BUỘC RSA
        Q2 = P_H.quotient(res)

        res_RSA = (Q2(p1)^N).lift() + (Q2(p0)^N).lift() * H^1337#p1^N + p0^N * H^1337 = 0 

        g_final = P_H(res._pari_with_name().gcd(res_RSA._pari_with_name()))


        if g_final.degree() > 0:
            assert g_final.degree() == 1

            H_result = -g_final.monic()[0]
            B_result = -p0(H=H_result) / p1(H=H_result)
            #common modulus attack on RSA 
            vg, v1, v2 = xgcd(1337, -N)
            m = int(B_result^v1 * H_result^v2)

            flag = long_to_bytes(m)
            print(f"\nFind flag at {k_seq}:")
            print(flag.decode('utf-8', errors='ignore'))
            exit(0)

    except Exception as e:
        print(e) 
        pass