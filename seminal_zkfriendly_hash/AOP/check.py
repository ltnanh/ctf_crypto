#Tinh inv cua ma tran M , RC 

p = 18446744073709551557 # p - 1 not a multiple of 3
t = 5
r = 9

M = [
            [ pow(i, j, p) for i in range(1, t + 1) ]
            for j in range(t)
        ]

for row in M:
    print(row)

print("\nso mu e nguoc")
for i in range(r):
    e = pow(3, i, p - 1)
    print(f"Round {i}: e = {e}")
    



from hashlib import sha256

p = 18446744073709551557
t = 5

# Khởi tạo ma trận M gốc từ đề bài
M = [[pow(i, j, p) for i in range(1, t + 1)] for j in range(t)]

# Hàm tính nghịch đảo mô-đun (ax ≡ 1 mod m)
def modInverse(a, m):
    g, x, y = ext_gcd(a, m)
    return x % m

def ext_gcd(a, b):
    if a == 0: return b, 0, 1
    gcd, x1, y1 = ext_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Hàm tính ma trận nghịch đảo mod p bằng Gauss-Jordan
def invert_matrix_mod(matrix, p):
    n = len(matrix)
    # Tạo ma trận đơn vị kế bên để biến đổi song song
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    A = [row[:] for row in matrix] # Copy ma trận gốc
    
    for i in range(n):
        # Tìm phần tử nghịch đảo của A[i][i]
        inv = modInverse(A[i][i], p)
        
        # Quy phần tử hàng i cột i về 1
        for j in range(n):
            A[i][j] = (A[i][j] * inv) % p
            I[i][j] = (I[i][j] * inv) % p
            
        # Triệt tiêu các phần tử ở các hàng khác cùng cột i
        for k in range(n):
            if k != i:
                factor = A[k][i]
                for j in range(n):
                    A[k][j] = (A[k][j] - factor * A[i][j]) % p
                    I[k][j] = (I[k][j] - factor * I[i][j]) % p
    return I

# Tính ma trận nghịch đảo M_inv
M_inv = invert_matrix_mod(M, p)

print("\nMa trận nghịch đảo M_inv = [")
for row in M_inv:
    print("  ", row, ",")
print("]")





RC = [
            [ int.from_bytes(sha256(b"FCSC2024#" + str(t*j + i).encode()).digest()) % p for i in range(t) ]
            for j in range(r)
        ]

print("\nMa trận RC :")
for row in RC:
    print(row)


