import ast
import sys
import time
import math
import itertools
from sage.all import *
from pwn import *


p = 8380417
F = GF(p)
R.<x> = F[]

f1 = R([1, 8380413, 8380407, 10, 15, 8380411, 8380410, 1, 1])
f2 = R([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
f3 = R([27583, 93555, 8360273, 8181428, 175914, 8065760, 132437, 8054074, 496535, 151090, 431212, 7842844, 98317, 33297, 541045, 8216476, 8243564, 8069617, 75534, 54402, 95912, 8363834, 8369908, 8364615, 1854, 1071, 1385, 8380318, 8380364, 8380357, 2, 1, 1])
f4 = R([214574, 350114, 1008286, 5172729, 2470965, 2424807, 2282275, 7424679, 5175797, 8211276, 4435449, 3962903, 1274322, 7759229, 5300855, 7274107, 3125906, 960978, 7783238, 1359090, 6587541, 2480838, 3762331, 815904, 4306408, 1137478, 6571889, 3204802, 4291656, 7160207, 3729379, 1242302, 4554596, 1820751, 3562854, 6780231, 8282117, 320853, 1030522, 1836179, 5632992, 8213997, 7886359, 987778, 1406960, 1598464, 1360816, 4723993, 3067189, 1899346, 6164104, 3531442, 4536664, 8052058, 8199316, 8162951, 11326, 6031, 6793, 8380190, 8380300, 8380293, 2, 1, 1])


#UTILITY FUNCTION

# convert mul a(x) to mul matrix A 
def poly_to_matrix(a_poly, mod_poly, degree):
    cols = []
    for j in range(degree):
        term = (a_poly * (x**j)) % mod_poly
        c = term.list()
        c += [0] * (degree - len(c))
        cols.append(c)
    return matrix(F, cols).transpose()

# using crt to excute  a (mod f1f2f3f4) from a(mod f1), a(mod f2), a(mod f3), a(mod f4)
def poly_crt(res, fs):
    M = prod(fs)
    a = R(0)
    for i, fi in enumerate(fs):
        Mi = M // fi
        Ni = Mi.inverse_mod(fi)   
        a += res[i] * Mi * Ni
    return a % M





# MULTI MODULAR KNAPSACK SOLVER (FOR PHASE 2,3,4)

# Extract and validate the solution vector from the reduced basis
def extract_and_validate(reduced_basis, num_var, num_eq, A, S, p):
    for row in reduced_basis:
        if all(row[num_var + 1 + j] == 0 for j in range(num_eq)):
            if row[num_var] == -1/2:
                e_cand = [int(val + 1/2) for val in row[:num_var]]
            elif row[num_var] == 1/2:
                e_cand = [int(1/2 - val) for val in row[:num_var]]
            else:
                continue
            
            if all(bit in [0, 1] for bit in e_cand):
                valid = True
                if all(e_cand[i] + e_cand[i + num_var//2] <= 1 for i in range(num_var//2)):
                    for j in range(num_eq):
                        if (sum(e_cand[i] * A[j][i] for i in range(num_var)) % p) != (S[j] % p):
                            valid = False
                            break
                if valid:
                    return e_cand
    return None



# Solve the multi modular knapsack problem (S = Ax (modp))
def solve_multi_modular_subset_sum(A, S, p):
    num_eq = len(A)
    num_var = len(A[0])

    W = 2**100
    M = Matrix(QQ, num_var + num_eq + 1, num_var + num_eq + 1)
    
    for i in range(num_var):
        M[i, i] = 1                       
        for j in range(num_eq):
            M[i, num_var + 1 + j] = W * A[j][i]
            
    for j in range(num_eq):
        M[num_var + j, num_var + 1 + j] = W * p

    for i in range(num_var):
        M[num_var + num_eq, i] = 1/2                    
    M[num_var + num_eq, num_var] = 1/2
    
    for j in range(num_eq):
        M[num_var + num_eq, num_var + 1 + j] = W * S[j]
    
    print(f"Lattice size {M.nrows()}x{M.ncols()}")
    print("Running LLL")
    reduced_M = M.LLL()
    
    sol = extract_and_validate(reduced_M, num_var, num_eq, A, S, p)
    if sol:
        return sol
        
    else: 
        print("LLL fail, try using BKZ(block_size=20)")
        reduced_M = M.BKZ(block_size=20)
        return extract_and_validate(reduced_M, num_var, num_eq, A, S, p)
        
    return None




def solve_branch_lattice(phase ,fi, degree, samples, errs, num_eq):
    print(f"\nSolving phase {phase} with f{phase} of deg {degree}")
    
    a0_f = R(samples[0][0]) % fi
    b0_f = R(samples[0][1]) % fi
    a1_f = R(samples[1][0]) % fi
    b1_f = R(samples[1][1]) % fi

    c1, c2, c3 = errs[0], errs[1], errs[2]
    delta2 = (c2 - c1) % p
    delta3 = (c3 - c1) % p

    A0 = poly_to_matrix(a0_f, fi, degree)
    A1 = poly_to_matrix(a1_f, fi, degree)

    b0_vec = vector(F, b0_f.list() + [0] * (degree - len(b0_f.list())))
    b1_vec = vector(F, b1_f.list() + [0] * (degree - len(b1_f.list())))

    A1_sub = A1[:num_eq, :]
    b1_sub = b1_vec[:num_eq]

    A_big = block_matrix([[A0], [A1_sub]]) 
    b_big = vector(F, list(b0_vec) + list(b1_sub)) 

    L = A_big.left_kernel().basis_matrix() 

    c1_vec = vector(F, [c1] * (degree + num_eq))

    #targer vecto s of multi knapsack problem 
    s_target = L * b_big - L * c1_vec

    W_X = L * delta2 
    W_Y = L * delta3 

    # matrix of multi knapsack problem A_knap = W_X | W_Y
    A_knap = block_matrix([[W_X, W_Y]]) 

    A_list = [[int(A_knap[j, i]) for i in range(2 * (degree + num_eq))] for j in range(num_eq)]
    s_list = [int(val) for val in s_target]


    solution = solve_multi_modular_subset_sum(A_list, s_list, p)
    if solution:
        print(f"Found solution")
        X_0 = solution[:degree]
        Y_0 = solution[degree + num_eq : 2 * degree + num_eq]
        
        e0 = []
        for i in range(degree):
            val = (c1 + X_0[i] * delta2 + Y_0[i] * delta3) % p
            e0.append(val)
            
        s_vec = A0.inverse() * (b0_vec - vector(F, e0))
        s = list(s_vec) + [0] * (degree - len(list(s_vec)))
        print(f"Solved phase {phase}")
        print(f"s mod f{phase} =",s)
        return s
    else:
        print(f"Lattice fail")
        return None





# SOLVE PHASE1 
def solve_phase1(fi, degree, samples):
    print(f"\nSolving phase 1 with f1 of deg {degree}")

    samples_5 = samples[:5]
    
    A_matrices = []
    B_vectors = []
    for a_list, b_list in samples_5:
        A_matrices.append(poly_to_matrix(R(a_list) % fi, fi, degree))
        b_coeffs = (R(b_list) % fi).list()
        B_vectors.append(vector(F, b_coeffs + [0] * (degree - len(b_coeffs))))

    A0_inv = A_matrices[0].inverse()
    v0 = A0_inv * B_vectors[0]
    M0 = A0_inv
    
    T_matrices = [A_matrices[i] * M0 for i in range(1, 5)]
    V_vectors = [B_vectors[i] - A_matrices[i] * v0 for i in range(1, 5)]

    PR.<c1, c2, c3> = PolynomialRing(F, 3)
    monomials = [PR(1), c1, c2, c3, c1^2, c1*c2, c1*c3, c2^2, c2*c3, c3^2,c1^3, c1^2*c2, c1^2*c3, c1*c2^2, c1*c2*c3, c1*c3^2,c2^3, c2^2*c3, c2*c3^2, c3^3]
    C_var = [c1, c2, c3]

    patterns = [p for p in itertools.product([0, 1, 2], repeat=degree) 
                    if set(p) == {0, 1, 2} and p.index(0) < p.index(1) and p.index(1) < p.index(2)]

    errs = []
    s1 = []
    
    for pat in patterns:
        e0_sym = vector(PR, [C_var[idx] for idx in pat])
        equations = []
        for i in range(4):
            ei_sym = V_vectors[i-1] + T_matrices[i-1] * e0_sym
            for k in range(degree):
                E = ei_sym[k]
                equations.append((E - c1) * (E - c2) * (E - c3))
                
        M_lin = matrix(F, 32, 20)
        for row_idx, eq in enumerate(equations):
            for col_idx, mon in enumerate(monomials):
                M_lin[row_idx, col_idx] = eq.monomial_coefficient(mon)
                

        ker = M_lin.right_kernel()
        if ker.dimension() > 0:
            for vec in ker.basis():
                if vec[0] != 0:
                    vec = vec / vec[0]
                    ans_c1, ans_c2, ans_c3 = vec[1], vec[2], vec[3]
                    
                    # check valid solution of c1, c2, c3
                    if vec[4] == ans_c1**2 and vec[7] == ans_c2**2:
                        errs = [int(ans_c1), int(ans_c2), int(ans_c3)]
                        e0_val = vector(F, [ans_c1 if idx==0 else (ans_c2 if idx==1 else ans_c3) for idx in pat])
                        
                        s1_val = M0 * (B_vectors[0] - e0_val)
                        s1 = list(s1_val) +  [0] * (degree - len(list(s1_val))) 
                        break
        if errs: 
            break

    if not errs:
        print("Can't find errs and s mod f1")
        sys.exit(1)
    
    print("Solved phase 1")
    print(f"errs = {errs}")
    print(f"s mod f1 = {s1}")
    
    return errs, s1
        
    




# MAIN 
def main():
    context.log_level = 'error' 
    io = remote('127.0.0.1', 1337)


    # Fetch 10 samples
    print("Fetching 10 samples from the server")
    io.recvuntil(b"num sample:\n> ")
    io.sendline(b"10")
    
    io.recvuntil(b"Here are your samples:\n")
    samples_str = io.recvline().decode().strip()
    samples = ast.literal_eval(samples_str)
    print("Fetched 10 samples from the server")


    # Find s mod fi
    errs,s1 = solve_phase1(f1, 8, samples)
    s2 = solve_branch_lattice(2, f2, 16, samples, errs, num_eq=16)
    s3 = solve_branch_lattice(3, f3, 32, samples, errs, num_eq=32)
    s4 = solve_branch_lattice(4, f4, 64, samples, errs, num_eq=30)

    if not (s2 and s3 and s4):
        sys.exit(1)


    # 4. crt all s mod fi to find secret 
    fs = [f1, f2, f3, f4]
    res = [R(s1), R(s2), R(s3), R(s4)]
    secret = poly_crt(res, fs)
    print("\nFound secret s =",secret.list())

    
    # Send secret and achieve flag 
    io.recvuntil(b"> ")
    payload = str(list(secret)).encode()
    io.sendline(payload)
    response = io.recvall(timeout=3).decode().strip()
    print("\n" ,response)
   

if __name__ == "__main__":
    main()