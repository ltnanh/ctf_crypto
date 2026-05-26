#!/usr/bin/env python3

from sage.all import GF, EllipticCurve_from_j, EllipticCurve
import json
import os
from hashlib import sha256
from ast import literal_eval

FLAG = open("flag.txt").read()

p = 2**49 * 3**36 - 1
K = GF(p**2, "x", modulus=[1, 0, 1])
x = K.gen()


def deterministic_sqrt(x):
    return min(x.sqrt(all=True))


### Helper Functions ###
# Algorithm 3 & 4
# Yoshida, R., Takashima, K., (2009). Simple Algorithms for Computing a Sequence of 2-Isogenies
# https://doi.org/10.1007/978-3-642-00730-9_4
def select0(E0, b0):
    torsion_points = sorted(E0.torsion_polynomial(2).roots(multiplicities=False))
    if b0:
        return torsion_points[-1], torsion_points[1]
    else:
        return torsion_points[1], torsion_points[-1]


def select(lambda0, lambda1, b):
    if b:
        return max(lambda0, lambda1)
    else:
        return min(lambda0, lambda1)


def next_curve(A, alpha, b):
    xi = alpha**2
    zeta = 3 * xi + A
    eta = deterministic_sqrt(zeta)
    new_A = -(4 * A + 15 * xi)

    lambda0 = alpha + 2 * eta
    lambda1 = alpha - 2 * eta
    new_alpha = select(lambda0, lambda1, b)
    return new_A, new_alpha


def CGL_hash(E0, data):
    data = data_to_bits(data)
    n = len(data)

    A = E0.a4()
    alpha, _ = select0(E0, data[0])
    for i in range(n - 1):
        A, alpha = next_curve(A, alpha, data[i + 1])

    xi = alpha**2
    new_A = -(4 * A + 15 * xi)
    new_B = -alpha * (8 * A + 22 * xi)

    E = EllipticCurve(E0.base_field(), [new_A, new_B])
    j = str(E.j_invariant()).encode()
    return sha256(j).hexdigest()


def data_to_bits(data):
    bits = [int(b) for c in data for b in "{:08b}".format(c)]
    assert bits and all(b in (0, 1) for b in bits)
    return bits


### Challenge ###
def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      OPERATION FORGED NORMALITY  —  D9 ATTEST NODE      ║")
    print("║                  [ TASK FORCE NIGHTFALL ]                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("Initialising attestation engine. Define your starting point.")

    a4_0 = int(input("a4.0 > "))
    a4_1 = int(input("a4.1 > "))
    a6_0 = int(input("a6.0 > "))
    a6_1 = int(input("a6.1 > "))

    a4 = a4_0 + a4_1 * x
    a6 = a6_0 + a6_1 * x
    E0 = EllipticCurve(K, [a4, a6])

    if not E0.is_supersingular():
        print("[REJECTED] Protocol violation: curve must be supersingular.")
        return

    registry = set()
    print("--- D9 ATTESTATION ENGINE ---")
    print("1 > register quine credential")
    print("2 > deploy quine payload")
    while True:
        choice = int(input("choice > "))
        payload = bytes.fromhex(input("data (hex) > "))
        hsh = CGL_hash(E0, payload)
        if choice == 1 and hsh == literal_eval(payload.decode("latin-1")):
            registry.add(hsh)
        elif choice == 2 and hsh in registry:
            eval(payload)
        else:
            print("[REJECTED] Attestation mismatch. Quines only.")


if __name__ == "__main__":
    main()
