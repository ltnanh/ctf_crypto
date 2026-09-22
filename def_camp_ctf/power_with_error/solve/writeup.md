# Power with Error 


## 1. challenge overview 

The supplied parameters are:

```text
p = 289681150111530694174556323703782825681
n = 10
t = 5
c = 3
```

The generator pads the flag to 100 bytes. For each of five groups, it chooses
a new random matrix

$$
A\in\operatorname{Mat}_{10}(\mathbb F_p).
$$

Within that group, it generates three independent 100-byte keys. Each key has
the form

```python
key = b"\x00" + os.urandom(99)
```

For each key, it chooses an exponent, computes a power of the group's matrix,
and adds the key bytes to the flattened matrix entries:

```python
flag = xor(key, flag)
U = pow(A, secrets.randbelow(p)).list()
U = [a + b for (a, b) in zip(U, key)]
```

Sage flattens the matrix in row order. Since each `a` is an element of
$\mathbb F_p$, the addition in the final line is field addition modulo
$p$.

Reshape each output and each key into a $10\times10$ matrix. For one group,
write the three public matrices as

$$
U_a=P_a+K_a\pmod{p},\qquad P_a=A^{r_a},\qquad a\in\{0,1,2\}.
$$

The unknown key entries satisfy

$$
0\le K_a[i,j]\le255,\qquad K_a[0,0]=0.
$$

There are two different operations to keep separate:

| Operation | Purpose |
|---|---|
| Matrix-entry addition modulo $p$ | Hides each matrix power behind its key |
| Bytewise XOR | Encrypts the flag using those same key bytes |

The five groups have different underlying matrices, so we attack each group
independently. Once all 15 keys are recovered, decrypt using

$$
\text{flag}_{\mathrm{padded}}
=\text{enc}\oplus\bigoplus_{T=0}^{4}\bigoplus_{a=0}^{2}
\operatorname{flatten}(K_{T,a}).
$$

The source also prints each key. If that stdout transcript were supplied,
the keys could be read directly. The supplied instance contains the noisy
matrices and ciphertext, so the attack below uses those files.

## 2. The algebraic weakness: powers of one matrix commute

For any nonnegative integers $r_a,r_b$,

$$
A^{r_a}A^{r_b}=A^{r_a+r_b}=A^{r_b}A^{r_a}.
$$

This identity does not require $A$ to be invertible or diagonalizable.
Consequently,

$$
P_aP_b-P_bP_a=0.
$$

Define the commutator notation

$$
[B,D]=BD-DB.
$$

Each group supplies three relations:

$$
[P_0,P_1]=[P_0,P_2]=[P_1,P_2]=0.
$$

Substituting $P_a=U_a-K_a$ gives equations in the small unknown key
entries 

=> **Small Integer Solution** .We will try to apply lattice reduction , LLL in solving for the keys without using too much equations 

## 3. Center the unknown bytes

Lattices use Euclidean length, so it helps to represent each unknown byte
near in $[-128,127]$ instead of in $[0,255]$.

Define the known matrix

$$
C[i,j]=\begin{cases}0,&(i,j)=(0,0),\\128,&\text{otherwise},\end{cases}
$$

and let

$$
X_a=U_a-C,\qquad E_a=K_a-C.
$$

Then

$$
X_a=P_a+E_a,\qquad -128\le E_a[i,j]\le127,
\qquad E_a[0,0]=0.
$$

All matrix identities below hold modulo $p$. When discussing the size of
an error, we use its small signed integer representative.

Expanding commutativity gives

$$
\begin{aligned}
0&=[X_a-E_a,X_b-E_b]\\
 &=[X_a,X_b]-[E_a,X_b]-[X_a,E_b]+[E_a,E_b].
\end{aligned}
$$

Therefore,

$$
\boxed{
[E_a,X_b]+[X_a,E_b]-[X_a,X_b]=[E_a,E_b]\pmod{p}.
}
$$

This separates the equation into three useful parts:

- $[X_a,X_b]$ is completely known.
- $[E_a,X_b]+[X_a,E_b]$ is linear in the unknown errors.
- $[E_a,E_b]$ is quadratic, but its integer entries are small.

For an entry of the quadratic term,

$$
[E_a,E_b]_{i,j}
=\sum_{k=0}^{9}
\left(E_a[i,k]E_b[k,j]-E_b[i,k]E_a[k,j]\right).
$$

Each product has absolute value at most $128^2$, giving the conservative
bound

$$
\boxed{|[E_a,E_b]_{i,j}|\le20\cdot128^2=327680.}
$$

This is tiny compared with the 128 bits modulus.

=> Consider the quadratic term as a small residual in a bounded modular linear problem. This is **Learning with error** 

## 4. Recover a small part first to control the lattice dimension

A direct construction using every key entry would contain 297 unknown
bytes and up to 300 scalar commutator equations. The straightforward square
embedding would have dimension

$$
297+300+1=598.
$$

We did not run that lattice. Instead, select only a small block of equations.

### 4.1 Which errors affect one commutator entry?

The entry $[E_a,X_b]_{i,j}$ depends only on row $i$ and column $j$
of $E_a$. Likewise, $[X_a,E_b]_{i,j}$ depends only on row $i$ and
column $j$ of $E_b$.

Choose the top-left $b\times b$ block of each of the three commutators:

$$
0\le i,j<b.
$$

These equations involve only error entries in the union of the first $b$
rows and the first $b$ columns. They do not involve the bottom-right
$(10-b)\times(10-b)$ error block.

One can also see this by writing each true power in blocks:

$$
P_a=\begin{pmatrix}Q_a&R_a\\S_a&T_a\end{pmatrix}.
$$

The top-left block of its commutator with $P_b$ is

$$
Q_aQ_b+R_aS_b-Q_bQ_a-R_bS_a.
$$

The unknown bottom-right blocks $T_a,T_b$ do not appear.

### 4.2 Counting variables and equations

Per matrix, the selected rows and columns contain

$$
10b+10b-b^2=20b-b^2
$$

entries. Remove the known error at $(0,0)$, then multiply by three:

$$
d=3(20b-b^2-1).
$$

There are three matrix pairs and $b^2$ entries per pair, so we use

$$
m=3b^2
$$

scalar equations. The square embedding has rank

$$
N=d+m+1=60b-2.
$$

| Block size $b$ | Byte variables $d$ | Equations $m$ | Embedding rank |
|---:|---:|---:|---:|
| 1 | 54 | 3 | 58 |
| 2 | 105 | 12 | 118 |
| 3 | 150 | 27 | **178** |
| 4 | 189 | 48 | 238 |

We choose $b=3$. It gives more modular constraints than the smaller
blocks while keeping the lattice below rank 200. The smaller options were
considered during design; the successful runs used $b=3$.

At this point, our target is exactly 50 unknown centered bytes per matrix:
the first three rows and columns, excluding $(0,0)$.

## 5. Build the first modular linear system

Collect the 150 selected errors into a vector

$$
e\in\mathbb Z^{150}.
$$

Collect the 27 selected commutator equations into

$$
\boxed{De-\beta=r\pmod{p},}
$$

where:

- $D\in\mathbb F_p^{27\times150}$ contains known linear coefficients;
- $\beta\in\mathbb F_p^{27}$ contains entries of $[X_a,X_b]$;
- $r\in\mathbb Z^{27}$ contains entries of $[E_a,E_b]$.

### 5.1 Exact coefficient formulas

Index an equation by $(a,b,i,j)$, with $a<b$ and $i,j<3$.
Index an unknown by $(h,k,\ell)$, meaning the entry $E_h[k,\ell]$.

For $h=a$, its coefficient is

$$
D_{(a,b,i,j),(a,k,\ell)}
=\mathbf{1}_{k=i}X_b[\ell,j]
-\mathbf{1}_{\ell=j}X_b[i,k].
$$

For $h=b$, its coefficient is

$$
D_{(a,b,i,j),(b,k,\ell)}
=\mathbf{1}_{\ell=j}X_a[i,k]
-\mathbf{1}_{k=i}X_a[\ell,j].
$$

For the third matrix, the coefficient is zero. The known target entry is

$$
\beta_{(a,b,i,j)}=[X_a,X_b]_{i,j}.
$$

These formulas follow directly by expanding the two linear commutators.
They also handle entries where both indicator conditions hold: both terms
must be included.

## 6. Embed the small-error problem into a lattice

Choose integer lifts of $D$ and $\beta$, using representatives close
to zero. Let

$$
s=256,\qquad H=32768.
$$

Construct the integer **row basis**

$$
\boxed{
B=\begin{pmatrix}
pI_m&0&0\\
D^T&sI_d&0\\
-\beta^T&0&H
\end{pmatrix},
\qquad m=27,\quad d=150.
}
$$

The matrix is square, full rank, and has dimension 178.

### 6.1 Why the correct solution gives a short vector

For the true error vector, there is some integer vector $q$ such that

$$
De-\beta=r+pq.
$$

Take the integer combination of basis rows with coefficients
$(-q^T,e^T,1)$. It produces

$$
(-q^T,e^T,1)B
=\boxed{(r^T,se^T,H)}.
$$

The modulus terms disappear. What remains consists entirely of small
residuals, scaled bytes, and the fixed embedding coordinate.

This is a Kannan-style embedding of the target into a shortest-vector


### 6.2 Why these scales are reasonable

A centered random byte has a typical magnitude around 74. Multiplying it
by 256 gives a coordinate scale around 19,000. A rough independence
estimate puts a quadratic commutator entry on the order of 24,000.

Thus, $s=256$ makes the two kinds of coordinates comparable. The final
coordinate $H=32768$ is of a similar order.



### 6.3 Extract and validate a candidate

Scan the reduced basis rows. If the last coordinate is $+H$ or $-H$,
normalize the sign so it becomes $+H$. Divide the 150 byte coordinates
by $s$ to obtain a candidate $e$.

Do not assume the solution is always the first reduced row. The solver
examines every row with a suitable final coordinate.

Accept a candidate only after checking:

1. Every recovered centered byte lies in $[-128,127]$.
2. The fixed errors at $(0,0)$ remain zero.
3. Substituting the candidate into the original selected commutators makes
   all 27 entries exactly zero modulo $p$.

The third check is stronger than checking that the linear residual is
small: it restores and verifies the actual quadratic relation.

Unknown bottom-right errors can temporarily be set to zero during this
check because the selected commutator entries do not depend on them.

Finally, undo the centering:

$$
K_a[i,j]=E_a[i,j]+128
$$

for recovered entries other than $(0,0)$, whose key byte is zero.

### 6.4 Why the known zero byte helps

Commutativity alone cannot distinguish $P_a$ from $P_a+\lambda_a I$,
because scalar identity matrices commute with every matrix. Such a shift
would change the inferred diagonal key entries.

The fixed value $K_a[0,0]=0$ anchors each matrix and removes this scalar
shift ambiguity. We use it directly by excluding those three error
variables from the lattice.

## 7. Recover the remaining bytes using exact linear equations

After the first lattice, we know the complete first three rows and columns
of all three true power matrices. Each still has an unknown
$7\times7$ bottom-right key block.

These remaining 147 bytes can be recovered one column at a time.

### 7.1 Correct the known entries

Let $V_a$ equal $X_a$ after subtracting all errors recovered so far.
Its first three rows are now exactly the corresponding rows of $P_a$.

Fix an unprocessed column $j\in\{3,\ldots,9\}$. Define its remaining
centered errors by

$$
y_{a,k}=E_a[k,j],\qquad a\in\{0,1,2\},\quad k\in\{3,\ldots,9\}.
$$

There are 21 unknowns. For $k\ge3$,

$$
P_a[k,j]=V_a[k,j]-y_{a,k}.
$$

Use rows $i=0,1,2$ of the three pairwise commutativity relations:

$$
\sum_{k=0}^{9}
\left(P_a[i,k]P_b[k,j]-P_b[i,k]P_a[k,j]\right)=0.
$$

Every row coefficient is already known. Substitution gives

$$
\boxed{
\sum_{k=3}^{9}
\left(V_a[i,k]y_{b,k}-V_b[i,k]y_{a,k}\right)
=[V_a,V_b]_{i,j}\pmod{p}.
}
$$

Unlike the first stage, this is an **exact linear equation**. There is no
remaining product of two unknowns in these selected entries.

### 7.2 The rank-31 embedding

Collect the nine equations into

$$
\boxed{
Fy=\gamma\pmod{p}
}
\qquad F\in\mathbb F_p^{9\times21}.
$$

Use the row basis

$$
B_{\mathrm{col}}=
\begin{pmatrix}
pI_9&0&0\\
F^T&I_{21}&0\\
-\gamma^T&0&128
\end{pmatrix}.
$$

Its rank is

$$
9+21+1=31,
$$

and the true solution produces the short vector

$$
(0,\ldots,0,\;y^T,\;128).
$$

Reduce with LLL, extract candidates from rows with last coordinate
$\pm128$, and require both byte bounds and the exact equality
$Fy=\gamma\pmod{p}$.

Update the corrected matrices and convert the recovered centered errors
back into key bytes. Repeat for columns 3 through 9.

Ordinary Gaussian elimination alone would leave free variables in a system
with 21 unknowns and nine equations. The lattice uses the additional fact
that all 21 unknowns are bounded bytes, rather than arbitrary field elements.

## 8. Implementation

First, we isolate the core lattice reduction logic into a standalone module `solve_small_root_sys.sage`. This function takes the system's coefficients and target vector, builds the Kannan embedding, runs LLL, and extracts all candidate solutions:

```python
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

```

The main solver is implemented in `solve_new.sage`. We start by importing the necessary libraries, the module above, and hardcoding our input data to simplify the script:

```python
import ast
from itertools import combinations
from sage.all import GF, matrix, vector

load('solve/solve_small_root_sys.sage')

p = 289681150111530694174556323703782825681
n = 10
t = 5
enc = b'...'
TESTCASES = [...]
PAIRS = list(combinations(range(3), 2))
```

To solve a group, we first initialize the field, parse the public matrices, and apply the -128 centering shift to create the known matrices $X$:

```python
def solve_group(case, p, n):

    print(f"\n[*] Solving Group {case}")
    field = GF(p)
    
    U = [matrix(field, n, n, row) for row in TESTCASES[case]]
    
    # Center the key to 0 (subtract 128)
    C = matrix(field, n, n, [0] + [128]*(n*n-1))
    X = [U[a] - C for a in range(3)]
```

For the first phase, we target the $3 \times 3$ top-left block. We calculate the exact mathematical coefficients for the 150 unknown variables across the 27 equations based on the commutators:

```python
    # Solve the 3x3 block (Lattice rank 178)
    pos_3x3 = [(a, i, j) for a in range(3) for i in range(n) for j in range(n) 
               if (i < 3 or j < 3) and (i, j) != (0, 0)]
    eqs_3x3 = [(a, b, i, j) for a, b in PAIRS for i in range(3) for j in range(3)]
    
    D = matrix(field, len(eqs_3x3), len(pos_3x3))
    beta = []
    
    for r, (a, b, i, j) in enumerate(eqs_3x3):
        beta.append((X[a]*X[b] - X[b]*X[a])[i, j])
        for s, (h, k, l) in enumerate(pos_3x3):
            if h == a:
                D[r, s] = (X[b][l, j] if k == i else 0) - (X[b][i, k] if l == j else 0)
            elif h == b:
                D[r, s] = (X[a][i, k] if l == j else 0) - (X[a][l, j] if k == i else 0)
```

We pass this system to our lattice solver with a scale of 256 and an embedding height of 32768. Then, we validate the candidate solutions by substituting them back into the quadratic equations:

```python
    candidates_3x3 = small_root_sys(D, beta, p, scale=256, height=32768)
    

    valid_e = None
    for cand in candidates_3x3:
        if all(-128 <= x <= 127 for x in cand):
            E_temp = [matrix(field, n, n) for _ in range(3)]
            for (a, i, j), val in zip(pos_3x3, cand):
                E_temp[a][i, j] = val
            V_temp = [X[a] - E_temp[a] for a in range(3)]
            
            if all((V_temp[a]*V_temp[b] - V_temp[b]*V_temp[a])[i, j] == 0 for a, b, i, j in eqs_3x3):
                valid_e = cand
                break
                
    if not valid_e:
        raise Exception(f"No valid key found for 3x3 block ")
        
    print("  [+] Found 50 bytes of each key")
```

Once the $3 \times 3$ block is verified, we apply these known errors to $X$ to form the partially corrected matrices $V$:

```python
    V = [matrix(field, X[a]) for a in range(3)]
    keys = [[[None]*n for _ in range(n)] for _ in range(3)]
    for a in range(3):
        keys[a][0][0] = 0
        
    for (a, i, j), val in zip(pos_3x3, valid_e):
        keys[a][i][j] = val + 128
        V[a][i, j] -= val
```

Next, we solve the remaining columns one by one. For each column, we build a perfectly exact linear system from the completely known first 3 rows of $V$:

```python
    # Solve the remaining columns sequentially (Lattice rank 31)
    for j in range(3, n):
        pos_col = [(a, k) for a in range(3) for k in range(3, n)]
        eqs_col = [(a, b, i) for a, b in PAIRS for i in range(3)]
        
        F = matrix(field, len(eqs_col), len(pos_col))
        gamma = []
        
        for r, (a, b, i) in enumerate(eqs_col):
            gamma.append((V[a]*V[b] - V[b]*V[a])[i, j])
            for s, (h, k) in enumerate(pos_col):
                if h == b:
                    F[r, s] = V[a][i, k]
                elif h == a:
                    F[r, s] = -V[b][i, k]
```

We solve this smaller exact system using a scale of 1 and a height of 128, validate it linearly, and update the keys iteratively:

```python
        cands_col = small_root_sys(F, gamma, p, scale=1, height=128)
        target_vec = vector(field, gamma)
        
        valid_y = None
        for cand in cands_col:
            if all(-128 <= x <= 127 for x in cand):
                if F * vector(field, cand) == target_vec:
                    valid_y = cand
                    break
                    
        if not valid_y:
            raise Exception(f"No valid key found for column {j}")
            
        for (a, k), val in zip(pos_col, valid_y):
            keys[a][k][j] = val + 128
            V[a][k, j] -= val
            
    print(f"  [+] Recovered 3 keys")


    return keys
```

Finally, we loop through all 5 groups, extract the fully recovered keys, and XOR them against the ciphertext to read the flag:

```python
def main():
    all_keys = []
    
    for case in range(t):
        keys = solve_group(case, p, n)
        flat = [[int(x) for row in key for x in row] for key in keys]
        all_keys.extend(flat)
        

    plain = bytearray(enc)
    
    for key in all_keys:
        for i, byte in enumerate(key):
            plain[i] = plain[i] ^^ byte
            
    flag = bytes(plain).rstrip(b'\x00').decode('utf-8')
    print(f"FLAG: {flag}")

if __name__ == '__main__':
    main()
```

Run the code and we will get the flag 

```bash
[*] Solving Group 0
  [+] Found 50 bytes of each key
  [+] Recovered 3 keys

[*] Solving Group 1
  [+] Found 50 bytes of each key
  [+] Recovered 3 keys

[*] Solving Group 2
  [+] Found 50 bytes of each key
  [+] Recovered 3 keys

[*] Solving Group 3
  [+] Found 50 bytes of each key
  [+] Recovered 3 keys

[*] Solving Group 4
  [+] Found 50 bytes of each key
  [+] Recovered 3 keys
FLAG: CTF{7ff8b019311e3394808f55ebaa1e9c7cef048a6c8681074d0cda751a85dbe9df}
```