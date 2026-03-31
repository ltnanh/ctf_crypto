import base64
import os
import random
import struct
import sys
import textwrap

def b64u_enc_u32(x):
    raw = struct.pack(">I", x & 0xFFFFFFFF)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_dec_u32(s):
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode())
    if len(raw) != 4:
        raise ValueError("bad length")
    return struct.unpack(">I", raw)[0]

MENU = textwrap.dedent(
    """
    [1] Get a token
    [2] Guess the next token
    [3] Exit
    """
).strip("\n")


def main():
    inp = sys.stdin.buffer
    out = sys.stdout.buffer

    rng = random.Random()
    rng.seed(int.from_bytes(os.urandom(16), "big"))

    issued = 0
    flag = "DH{This_is_fake_flag}"

    out.write(b"You get up to 700 tokens. If you can guess the NEXT one, you win.\n\n")
    out.flush()

    while True:
        out.write((MENU + "\n> ").encode())
        out.flush()

        line = inp.readline()
        if not line:
            return

        cmd = line.strip().decode(errors="ignore")

        if cmd == "1":
            if issued >= 700:
                out.write(b"Limit reached.\n")
                out.flush()
                continue

            val = rng.getrandbits(32)
            tok = b64u_enc_u32(val)
            issued += 1
            out.write(f"Token[{issued:03d}]: {tok}\n".encode())
            out.flush()
        elif cmd == "2":
            if issued < 1:
                out.write(b"Get at least one token first.\n")
                out.flush()
                continue

            out.write(b"Next token: ")
            out.flush()

            guess_line = inp.readline()
            if not guess_line:
                return

            guess_s = guess_line.strip().decode(errors="ignore")

            real = rng.getrandbits(32)
            try:
                guess = b64u_dec_u32(guess_s)
            except Exception:
                out.write(b"Nope.\n")
                out.flush()
                return
            if guess == real:
                out.write(b"Correct.\n")
                out.write((flag + "\n").encode())
            else:
                out.write(b"Nope.\n")
            out.flush()
            return
        elif cmd == "3":
            out.write(b"bye\n")
            out.flush()
            return
        else:
            out.write(b"Unknown.\n")
            out.flush()

if __name__ == "__main__":
    main()
