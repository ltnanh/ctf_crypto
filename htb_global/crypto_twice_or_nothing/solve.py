#!/usr/bin/env python3

from pwn import *
from hashlib import sha256
from itertools import combinations
import random
import re

HOST = "localhost"
PORT = 1337

N = 256
TARGET = b"d9_netadmin"
NUM_TOKENS = 6




def hash_bits(msg: bytes):
    h = sha256(msg).digest()
    value = int.from_bytes(h, "big")
    return [(value >> (255 - i)) & 1 for i in range(256)]




def find_messages():
    """
    Find 6 messages such that, for every bit position,
    at least one message has the same bit as TARGET.
    """

    target_bits = hash_bits(TARGET)

    # Generate many random candidate messages.
    candidates = []

    for i in range(1000):
        msg = f"candidate_{i}_{random.getrandbits(128):032x}".encode()

        # Just in case: avoid TARGET appearing literally.
        if TARGET in msg:
            continue

        candidates.append((msg, hash_bits(msg)))

    # Try random groups of 6.
    for _ in range(10000):
        selected = random.sample(candidates, NUM_TOKENS)

        covered = [False] * N

        for _, bits in selected:
            for i in range(N):
                if bits[i] == target_bits[i]:
                    covered[i] = True

        if all(covered):
            return selected

    # If random search somehow fails, use greedy selection.
    selected = []
    covered = [False] * N

    remaining = candidates[:]

    for _ in range(NUM_TOKENS):
        best = None
        best_gain = -1

        for candidate in remaining:
            msg, bits = candidate

            gain = sum(
                not covered[i] and bits[i] == target_bits[i]
                for i in range(N)
            )

            if gain > best_gain:
                best_gain = gain
                best = candidate

        if best is None:
            break

        selected.append(best)
        remaining.remove(best)

        _, bits = best

        for i in range(N):
            if bits[i] == target_bits[i]:
                covered[i] = True

    if all(covered):
        return selected

    raise RuntimeError("Could not find 6 suitable messages")





def parse_token(line):
    line = line.decode(errors="replace")

    m = re.search(r"Token issued:\s*\[(.*)\]", line)
    if not m:
        raise ValueError(f"Could not parse token:\n{line}")

    parts = [x.strip() for x in m.group(1).split(",")]

    if len(parts) != 256:
        raise ValueError(f"Expected 256 token elements, got {len(parts)}")

    values = []

    for x in parts:
        # Rust prints U256 as:
        # Uint(0xABCDEF...)
        m = re.fullmatch(r"Uint\(0x([0-9A-Fa-f]+)\)", x)

        if not m:
            raise ValueError(f"Unexpected token element: {x}")

        values.append(int(m.group(1), 16))

    return values






def main():

    context.log_level = "info"

    target_bits = hash_bits(TARGET)

    log.info("Searching for 6 messages...")

    selected = find_messages()

    log.success("Found suitable messages!")

    for i, (msg, bits) in enumerate(selected):
        log.info(f"Message {i}: {msg.hex()}")

    # --------------------------------------------------
    # Connect to challenge
    # --------------------------------------------------

    io = remote(HOST, PORT)

    tokens = []

    for i, (msg, _) in enumerate(selected):

        log.info(f"Requesting token {i + 1}/6")

        io.sendlineafter(b"> ", b"1")

        io.sendlineafter(
            b"Enter credential payload in hex: ",
            msg.hex().encode()
        )

        line = io.recvline()

        log.info(line.decode().strip())

        token = parse_token(line)

        assert len(token) == 256

        tokens.append(token)

    # --------------------------------------------------
    # Construct token for TARGET
    # --------------------------------------------------

    log.info("Constructing token for d9_netadmin...")

    final_token = []

    for i in range(N):

        target_bit = target_bits[i]

        chosen = None

        for token_index in range(NUM_TOKENS):

            msg, bits = selected[token_index]

            if bits[i] == target_bit:
                chosen = tokens[token_index][i]
                break

        if chosen is None:
            raise RuntimeError(
                f"No suitable secret for bit position {i}"
            )

        final_token.append(chosen)

    assert len(final_token) == 256

    # crypto_bigint::U256::from_be_hex() expects hexadecimal.
    # Format every value as exactly 64 hex digits.
    token_string = ",".join(
        f"{x:064x}"
        for x in final_token
    )

    # --------------------------------------------------
    # Submit forged token
    # --------------------------------------------------

    log.info("Submitting forged admin token...")

    io.sendlineafter(b"> ", b"2")

    io.sendlineafter(
        b"Enter admin message to validate: ",
        TARGET
    )

    io.sendlineafter(
        b"Enter token segments (comma-separated hex): ",
        token_string.encode()
    )

    io.interactive()




if __name__ == "__main__":
    main()