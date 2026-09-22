from sage.all import ZZ, matrix

def centered(x, p):
    x = int(x) % p
    return x if x <= p // 2 else x - p


    
def small_root_sys(coeff, target, p, scale, height):
    m = coeff.nrows()
    d = coeff.ncols()
    rank = m + d + 1
    
    B = matrix(ZZ, rank, rank)
    
    # Block p * I_m
    for i in range(m):
        B[i, i] = p
        
    # Block D^T and s * I_d
    for j in range(d):
        for i in range(m):
            B[m + j, i] = centered(coeff[i, j], p)
        B[m + j, m + j] = scale
        
    # Block -target^T and H
    for i in range(m):
        B[-1, i] = -centered(target[i], p)
    B[-1, -1] = height
    
    reduced_B = B.LLL()
    
    candidates = []
    for row in reduced_B:
        if abs(row[-1]) == height:
            sign = row[-1] // height
            xs = [int(sign * x // scale) for x in row[m:m + d]]
            candidates.append(xs)
            
    return candidates
