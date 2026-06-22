# x25519.py
# RFC 7748 - X25519 implementation

import secrets

P = 2**255 - 19
A24 = 121665


def decode_scalar(k):
    k = bytearray(k)

    k[0] &= 248
    k[31] &= 127
    k[31] |= 64

    return int.from_bytes(k, "little")


def decode_u_coordinate(u):
    return int.from_bytes(u, "little")


def encode_u_coordinate(u):
    return (u % P).to_bytes(32, "little")


def inv(x):
    return pow(x, P - 2, P)


def x25519(k, u):
    k = decode_scalar(k)
    u = decode_u_coordinate(u)

    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0

    for t in reversed(range(255)):

        kt = (k >> t) & 1
        swap ^= kt

        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2

        swap = kt

        A = (x2 + z2) % P
        AA = (A * A) % P

        B = (x2 - z2) % P
        BB = (B * B) % P

        E = (AA - BB) % P

        C = (x3 + z3) % P
        D = (x3 - z3) % P

        DA = (D * A) % P
        CB = (C * B) % P

        x3 = ((DA + CB) ** 2) % P
        z3 = (x1 * ((DA - CB) ** 2)) % P

        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E)) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    result = (x2 * inv(z2)) % P

    return encode_u_coordinate(result)


def generate_private_key():
    return secrets.token_bytes(32)


def generate_public_key(private_key):
    base_point = (9).to_bytes(32, "little")
    return x25519(private_key, base_point)


if __name__ == "__main__":

    alice_private = generate_private_key()
    alice_public = generate_public_key(alice_private)

    bob_private = generate_private_key()
    bob_public = generate_public_key(bob_private)

    alice_shared = x25519(alice_private, bob_public)
    bob_shared = x25519(bob_private, alice_public)

    print("Alice Public :", alice_public.hex())
    print("Bob Public   :", bob_public.hex())
    print("Shared Match :", alice_shared == bob_shared)
    print("Shared Secret:", alice_shared.hex())
