import math

def pad_message(message: bytes) -> bytes:
    """Pads message to a multiple of 512 bits (64 bytes) according to spec."""
    orig_len_bits = len(message) * 8
    # Append a '1' bit (0x80 byte)
    message += b'\x80'
    
    # Pad with zeros until we are 8 bytes short of a multiple of 64
    while (len(message) + 8) % 64 != 0:
        message += b'\x00'
        
    # Append original length as a 64-bit big-endian integer
    message += orig_len_bits.to_bytes(8, byteorder='big')
    return message

def sha256_from_scratch(message: bytes) -> bytes:
    """Pure Python implementation of SHA-256 (RFC 4634)"""
    
    # 1. Initial 32-bit Hash Values (First 32 bits of fractional parts of primes 2..19)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # 2. SHA-256 Constants (First 32 bits of fractional parts of primes 2..311)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Helper operations for 32-bit integer math (simulating hardware registers)
    rotr = lambda x, n: ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    shr  = lambda x, n: (x >> n) & 0xFFFFFFFF

    # Pad message to meet standard length
    padded = pad_message(message)
    
    # Process message in consecutive 64-byte chunks
    for chunk_idx in range(0, len(padded), 64):
        chunk = padded[chunk_idx:chunk_idx+64]
        
        # Expand 16 32-bit words into a 64-word schedule array (W)
        W = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)] + [0]*48
        for i in range(16, 64):
            s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ shr(W[i-15], 3)
            s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ shr(W[i-2], 10)
            W[i] = (W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF

        # Initialize working variables with current hash values
        a, b, c, d, e, f, g, h = H

        # Core Compression Loop (64 Rounds)
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Merge working variables back into state register
        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    # Convert state array integers back to bytes
    return b"".join(val.to_bytes(4, 'big') for val in H)

