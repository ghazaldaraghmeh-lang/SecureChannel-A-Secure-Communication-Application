## 1. Introduction

This project implements a secure communication protocol between a client and a server using Python.
The protocol is built from scratch based on official cryptographic standards (RFCs and FIPS) and provides confidentiality, integrity, authentication, and replay protection.

The system is designed to simulate modern secure communication protocols such as TLS 1.3 by combining ephemeral key exchange, key derivation, and authenticated encryption.

---

## 2. Message Format

Each encrypted message in the system follows the structure:

** Header (AAD) || Ciphertext || Poly1305 Tag **

### Header (Associated Data - AAD)
The header is transmitted in plaintext but authenticated. It includes:
- Protocol version
- Message type (handshake or data)
- Sender ID
- Sequence number

### Ciphertext
The encrypted payload generated using the ChaCha20 stream cipher.

### Authentication Tag
Generated using Poly1305 as part of the ChaCha20-Poly1305 AEAD construction.

The header is not encrypted but is fully integrity-protected.

---

## 3. Key Schedule

The key establishment process follows these steps:

### 1. Ephemeral Key Exchange
Both client and server generate ephemeral X25519 key pairs and exchange public keys.

A shared secret is computed as:

shared_secret = X25519(private_key, peer_public_key)

---

### 2. Authentication
A pre-shared key (PSK) is used to authenticate the handshake:

HMAC(PSK, handshake_transcript)

The handshake transcript includes:
- Client public key
- Server public key
- Identity information
- Protocol version

If authentication fails, the connection is terminated.

---

### 3. Key Derivation (HKDF)

The shared secret is processed using HKDF-SHA256 to derive session keys:

- Client → Server encryption key (K_enc)
- Server → Client encryption key (K_dec)
- Initial nonce seed

The PSK is used as the HKDF salt to bind the derived keys to the authenticated handshake.

---

## 4. Nonce Construction

Each message uses a unique nonce to ensure security of ChaCha20-Poly1305.

The nonce is derived by combining:
- A 12-byte base nonce (from HKDF)
- A strictly increasing 64-bit sequence number

This guarantees that every encryption operation uses a unique nonce and prevents nonce reuse attacks.

---

## 5. Replay Protection

Replay attacks are prevented using sequence numbers:

- Each message includes a sequence number in the header
- The receiver tracks the expected sequence number
- Messages with duplicate or old sequence numbers are rejected

This ensures that replayed messages cannot be accepted even if ciphertext and authentication tag are valid.

---

## 6. Tampering Protection

Tampering is prevented using ChaCha20-Poly1305 AEAD:

- Any modification in ciphertext causes decryption failure
- Any modification in AAD (header) causes authentication failure

This ensures both confidentiality and integrity of messages.

---

## 7. Security Summary

The protocol provides:

- Confidentiality → ChaCha20 encryption
- Integrity → Poly1305 MAC
- Authentication → HMAC-based handshake
- Secure key exchange → X25519
- Key derivation → HKDF-SHA256
- Replay protection → sequence numbers

---

## 8. Conclusion

This project demonstrates a complete secure communication system built entirely from cryptographic primitives implemented from scratch.

All cryptographic components follow official standards (RFC 7748, RFC 5869, RFC 8439, and FIPS 180-4) without using external cryptographic libraries.

The system successfully ensures secure key exchange, authenticated encryption, and protection against real-world attacks such as replay and tampering.
