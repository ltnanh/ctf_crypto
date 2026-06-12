from pwn import * 
context.log_level = 'error' 

p = 18446744073709551557
F = GF(p)
t_size = 5

M_inv = [
    [5, 1537228672809129290, 3843071682022823244, 16909515400900422260, 14603672391686728316],
    [18446744073709551547, 15372286728091292982, 3074457345618258583, 3074457345618258595, 15372286728091292964],
    [10, 9223372036854775759, 13835058055282163680, 18446744073709551554, 13835058055282163668],
    [18446744073709551552, 3074457345618258603, 3074457345618258586, 15372286728091292966, 15372286728091292964],
    [1, 7686143364045646480, 13066443718877599021, 1537228672809129296, 14603672391686728316]
]

RC = [
    [13233480176997314046, 9284868279641994560, 12235501346938362812, 4133703306813821108, 11628934183821097159],
    [1365554073049210793, 3511007896404757791, 10119514266227461252, 12755649044034805154, 6968391277147913083],
    [3436235021743231344, 14382771639998597446, 10794456969604745825, 3391001746029954469, 9575776310833530705],
    [5702251878007940294, 1412611021160597154, 15293457665893109119, 17246459576629151420, 10984851308070435897],
    [15432749654538409412, 851794337522974300, 17912965898469569454, 86107493925447996, 12787287593122038164],
    [4482214891010895595, 7807142372481143011, 17786077328007785060, 2193376157630329748, 1835978555584597312],
    [118587187516533665, 12368523247742327143, 17943100724683604257, 964261096706093360, 17879958655590459449],
    [11066677148798511200, 17893234430028688514, 8251047221571039380, 10263219281137670843, 16969914817910377678],
    [18149433503814401207, 12354040488908002162, 1717883272379260986, 18411889493652291634, 3094926074710221276]
]

def inv_linear_layer(state, r):
    sub_rc = [(state[i] - RC[r][i]) for i in range(t_size)]
    next_state = []
    for j in range(t_size):
        acc = 0
        for i in range(t_size):
            acc += sub_rc[i] * M_inv[i][j]
        next_state.append(acc)
    return next_state


def inv_sbox_layer(state, r):
    next_state = state[:]
    d_round = pow(3, r, p - 1)
    next_state[0] = next_state[0]^d_round
    
    return next_state


P = PolynomialRing(Zmod(p), names="a,b,c,d,X")
a, b, c, d, X = P.gens()

#Output of block cipher 
S9 = vector([0,a*X, b*X, c*X, d*X])


S8 = inv_sbox_layer(S9, 8)
S8 = inv_linear_layer(S8,8)
print(S8[0])
#18446744073709551547*a*X + 10*b*X + 18446744073709551552*c*X + d*X + 12345205671218884834
# => 10a = 10b - 5c + d
a = (10 * b - 5 * c + d)*F(10)^-1
S8 = [poly.subs(a=a) for poly in S8]



S7 = inv_sbox_layer(S8, 7)
S7 = inv_linear_layer(S7,7)
print(S7[0])
#10760600709663905120*b*X + 9223372036854775743*c*X + 17063238268181335199*d*X + 10318913522183144972
b = (9223372036854775743*c + 17063238268181335199*d)*F(-10760600709663905120)^-1
S7 = [poly.subs(b=b) for poly in S7]




S6 = inv_sbox_layer(S7, 6)
S6 = inv_linear_layer(S6,6)
print(S6[0])
#7320187277504286446*c*X + 6373745040101623205*d*X + 10099990774956362003
c = 6373745040101623205*d*F(-7320187277504286446)^-1
S6 = [poly.subs(c=c) for poly in S6]


#choose d = 1 
S6 = [poly.subs(d=1) for poly in S6]

print("\nDeg of eqn")

S65 = inv_sbox_layer(S6,5)
S5 = inv_linear_layer(S65,5)
print(S5[0].degree())


S54 = inv_sbox_layer(S5,4)
S4 = inv_linear_layer(S54,4)
print(S4[0].degree())


S43 = inv_sbox_layer(S4,3)
S3 = inv_linear_layer(S43,3)
print(S3[0].degree())


S32 = inv_sbox_layer(S3,2)
S2 = inv_linear_layer(S32,2)
print(S2[0].degree())


S21 = inv_sbox_layer(S2,1)
S1 = inv_linear_layer(S21,1)
print(S1[0].degree())


S10 = inv_sbox_layer(S1,0)
S0 = inv_linear_layer(S10,0)
print(S0[0].degree())



#solve equation S0[0] = 0 to find X 
P_target = S0[0]
P_target = P_target.univariate_polynomial()
R.<X> = PolynomialRing(F) 
P_target = R([F(c) for c in P_target.list()])


# 3.Apply equation X^p - X = 0  to use GCD 
print("Apply equation X^p - X = 0  to use GCD")
Q = power_mod(X, p, P_target) - X
gcd_res = gcd(P_target, Q)
print("GCD:", gcd_res)

roots = gcd_res.roots(multiplicities=False)

X = int(roots[0])
print(f"Found X = {X}")

#Recover input of block cipher
Final_Input = []
for poly in S0:
    val = poly.subs(X=X)
    Final_Input.append(int(val) % p)

print("Final Input: ", end = "")
print(",".join(map(str, Final_Input)))


#Send and get flag 
payload = ",".join(map(str, Final_Input))

HOST = '127.0.0.1' 
PORT = 1337       
r = remote(HOST, PORT)

r.recvuntil(b">>> ")
r.sendline(payload.encode())
flag_response = r.recvall(timeout=5)
print(flag_response.decode().strip())





