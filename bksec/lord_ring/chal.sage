import os
import random
import ast

proof.arithmetic(False)

flag = os.environ.get("FLAG","BKSEC{testing}")
p = 8380417
F = GF(p)
R.<x> = F[]

fs = []
degree = [8,16,32,64]
errs = random.sample(range(p), 3)

for d in degree:
    f = R.irreducible_element(d)
    if f not in fs:
        fs.append(f)

f = prod(fs)

def parse_poly(user_in):
    coeffs = ast.literal_eval(user_in)
    if not isinstance(coeffs, (list, tuple)):
        raise ValueError
    if not all(isinstance(c, int) for c in coeffs):
        raise ValueError
    return R([c % p for c in coeffs])


def poly_crt(res, fs):
    M = prod(fs)
    a = R(0)
    for i, fi in enumerate(fs):
        Mi = M // fi
        Ni = Mi.inverse_mod(fi)   
        a += res[i] * Mi * Ni
    return a % M
    
def poly_sample(lb, ub):
    es = [R([random.randint(lb,ub) for _ in range(d)]) for d in degree]
    
    return poly_crt(es, fs)

def error_sample(errs):
    es = [R([random.choice(errs) for _ in range(d)]) for d in degree]
    
    return poly_crt(es, fs)


print("Welcome to RLWE challenge!")
print("I will let u sample at most 10 samples this time  :DDDDD")
print("num sample:")

num_sample = int(input("> "))
if num_sample > 10:
    print("You are too greedy !!!")
    exit()

a_s = [poly_sample(0, p - 1) for _ in range(num_sample)]
s = poly_sample(0, p - 1)
e_s = [error_sample(errs) for _ in range(num_sample)]

samples = [(list(a % f), list((a * s + e) % f)) for a, e in zip(a_s, e_s)]

print("Here is your polynomial f:")
print(list(f))
print("Here are your samples:")
print(samples)

print("Submit your guess for my secret :<<<<")

try:
    guess = R(parse_poly(input("> ")))
    print('Guess:', guess)
    if guess == s:
        print("Congrats! Here is your flag: " + flag)
except:
    print("Don't be that desperate :v")
    exit()
