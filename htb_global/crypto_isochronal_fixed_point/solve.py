
from sage.all import *
from pwn import *
from ast import literal_eval
from hashlib import sha256
import random
import sys


# -----------------------------------------------------------------------------
# Challenge parameters
# -----------------------------------------------------------------------------

p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()

P_y = K["y"]
y = P_y.gen()                 # variable used when solving the reverse equations

HOST = "localhost"
PORT = 1337

sys.setrecursionlimit(10_000)  # the payload is longer than a 64-byte hash





def deterministic_sqrt(value):
    return min(value.sqrt(all=True))


def select0(E0, first_bit):
    roots = sorted(E0.torsion_polynomial(2).roots(multiplicities=False))
    if first_bit:
        return roots[-1], roots[1]
    return roots[1], roots[-1]


def select(left, right, bit):
    return max(left, right) if bit else min(left, right)


def next_curve(A, alpha, bit):
    xi = alpha**2
    eta = deterministic_sqrt(3 * xi + A)

    new_A = -(4 * A + 15 * xi)
    new_alpha = select(alpha + 2 * eta, alpha - 2 * eta, bit)
    return new_A, new_alpha


def data_to_bits(data):
    """The server hashes raw bytes, not a Python string."""
    if isinstance(data, str):
        data = data.encode()
    return [int(bit) for byte in data for bit in "{:08b}".format(byte)]






def make_payload(digest):
    """
    Return one byte string that works in both menu options.

    Registration uses payload.decode('latin-1') and literal_eval().  It sees
    only the quoted digest because the print call is after a comment.

    Deployment passes the raw bytes to eval().  Python honors the UTF-7
    coding cookie; +AAo- becomes a newline, exposing print(FLAG).
    """
    return (
        b"# coding: utf_7\n(\'" + digest.encode() +
        b"\' # +AAo-,print(FLAG)\n)"
    )






def backtrack(A_curr, alpha_curr, bit_index, bits):
    """
    Undo next_curve() from `bit_index` down to bit 0.

    If alpha_old is the prior marked 2-torsion root, it satisfies:

        4*alpha_old^2 - 2*alpha_curr*alpha_old
            + alpha_curr^2 + A_curr = 0.
    """
    if bit_index == 0:
        B0 = -alpha_curr**3 - A_curr * alpha_curr
        E0 = EllipticCurve(K, [A_curr, B0])

        alpha_test, _ = select0(E0, bits[0])
        return E0 if alpha_test == alpha_curr else None

    if bit_index % 100 == 0:
        log.info(f"reverse step {bit_index}/{len(bits) - 1}")

    bit = bits[bit_index]

    # Solve the quadratic above for the old marked root.
    equation = (
        4 * y**2
        - 2 * alpha_curr * y
        + alpha_curr**2
        + A_curr
    )

    for alpha_old in equation.roots(multiplicities=False):
        A_old = (-A_curr - 15 * alpha_old**2) / 4

        # Keep only roots compatible with the server's deterministic sqrt()
        # and min/max ordering convention.
        try:
            test_A, test_alpha = next_curve(A_old, alpha_old, bit)
        except ValueError:
            continue

        if (test_A, test_alpha) != (A_curr, alpha_curr):
            continue

        result = backtrack(A_old, alpha_old, bit_index - 1, bits)
        if result is not None:
            return result

    return None






def random_target_curve():
    """Make a random supersingular target with rational 2-torsion."""
    A = K(1)
    E = EllipticCurve(K, [A, K(0)])     # j = 1728, supersingular for p = 3 mod 4
    alpha, _ = select0(E, 0)

    # This is only used to pick a fresh target in the same supersingular
    # component.  It is the same target-generation idea as the old solver.
    for _ in range(30):
        A, alpha = next_curve(A, alpha, random.choice([0, 1]))

    xi = alpha**2
    target_A = -(4 * A + 15 * xi)
    target_B = -alpha * (8 * A + 22 * xi)
    return EllipticCurve(K, [target_A, target_B])






def solve():
    attempt = 0

    while True:
        attempt += 1
        log.info(f"trying target curve #{attempt}")

        E_final = random_target_curve()
        target_A = E_final.a4()
        target_B = E_final.a6()

        # The final j-invariant tells us the string that literal_eval() must
        # return.  The payload contains that string and also prints FLAG when
        # it is evaluated during deployment.
        digest = sha256(str(E_final.j_invariant()).encode()).hexdigest()
        payload = make_payload(digest)

        assert literal_eval(payload.decode("latin-1")) == digest
        bits = data_to_bits(payload)

        # Undo the final, unlabelled 2-isogeny.  Its kernel coordinate solves
        # 8*alpha^3 + 2*target_A*alpha - target_B = 0.
        tail_equation = 8 * y**3 + 2 * target_A * y - target_B

        for alpha_last in tail_equation.roots(multiplicities=False):
            A_last = (-target_A - 15 * alpha_last**2) / 4

            E0 = backtrack(A_last, alpha_last, len(bits) - 1, bits)
            if E0 is not None:
                log.success(f"found E0 after {attempt} target curves")
                return E0, payload






def get_parts(value):
    """Write a0 + a1*x as the two integers expected by the server."""
    coeffs = value.polynomial().list()
    a0 = int(coeffs[0]) if len(coeffs) > 0 else 0
    a1 = int(coeffs[1]) if len(coeffs) > 1 else 0
    return a0, a1


def main():
    E0, payload = solve()

    a4_0, a4_1 = get_parts(E0.a4())
    a6_0, a6_1 = get_parts(E0.a6())

    io = remote(HOST, PORT)
    io.sendlineafter(b"a4.0 > ", str(a4_0).encode())
    io.sendlineafter(b"a4.1 > ", str(a4_1).encode())
    io.sendlineafter(b"a6.0 > ", str(a6_0).encode())
    io.sendlineafter(b"a6.1 > ", str(a6_1).encode())

    # Register the digest literal, then send the exact same bytes again.
    # The UTF-7 source trick makes the second evaluation print FLAG.
    io.sendlineafter(b"choice > ", b"1")
    io.sendlineafter(b"data (hex) > ", payload.hex().encode())

    io.sendlineafter(b"choice > ", b"2")
    io.sendlineafter(b"data (hex) > ", payload.hex().encode())
    io.interactive()


if __name__ == "__main__":
    main()
