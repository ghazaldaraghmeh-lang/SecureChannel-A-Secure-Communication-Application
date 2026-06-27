# Secure Chat Protocol Implementation

---

## Team Members

- Ghazal Salah – 1230542  
- Baker Shalabi – 1231050  

---

## Project Description

This project implements a secure communication protocol in Python using cryptographic primitives implemented from scratch according to official RFC specifications.

The protocol provides:

- X25519 Ephemeral Diffie-Hellman key exchange (RFC 7748)  
- HMAC-SHA256 authentication  
- HKDF-SHA256 key derivation (RFC 5869)  
- ChaCha20 stream cipher (RFC 8439)  
- Poly1305 message authentication (RFC 8439)  
- AEAD ChaCha20-Poly1305 authenticated encryption (RFC 8439)  

The system establishes a secure session between a client and a server, derives independent session keys, and protects messages against tampering and replay attacks.

---

## Project Structure
Project/

├── crypto/

│   ├── aead.py

│   ├── chacha20.py

│   ├── hkdf.py

│   ├── hmac.py

│   ├── poly1305.py

│   ├── sha256.py

│   └── x25519.py

│

├── protocol/

│   ├── handshake.py

│   └── session.py

│

├── network/

│   ├── client.py

│   └── server.py

│

├── Tests/

│   ├── aead_Test.py

│   ├── chacha20_Test.py

│   ├── poly1305_Test.py

│   ├── sha256_Test.py

│   ├── hmac_Test.py

│   ├── hkdf_Test.py

│   └── x25519_Test.py

│

├── requirements.txt

├── REPORT.md

└── README.md

---

## Running Instructions

### Start the Server

python -m network.server

Start the Client

Open another terminal:

python -m network.client

Communication

After connection is established, start typing messages to communicate securely.

Exit

To terminate the session, type:

exit

---

#Test Vectors

All implementations are verified against official test vectors defined in the corresponding standards:

FIPS 180-4 – SHA-256
RFC 2104 – HMAC
RFC 5869 – HKDF
RFC 8439 – ChaCha20, Poly1305, and AEAD
RFC 7748 – X25519

---

#Running the Test Suite

ChaCha20

python -m Tests.chacha20_Test

Poly1305

python -m Tests.poly1305_Test

AEAD ChaCha20-Poly1305

python -m Tests.aead_Test

SHA-256

python -m Tests.sha256_Test

HMAC-SHA256

python -m Tests.hmac_Test

HKDF

python -m Tests.hkdf_Test

X25519

python -m Tests.x25519_Test

All tests must pass successfully before submission.

---

#Official References

SHA-256 (FIPS 180-4): https://csrc.nist.gov/pubs/fips/180-4/final

HMAC (RFC 2104): https://datatracker.ietf.org/doc/html/rfc2104

HKDF (RFC 5869): https://datatracker.ietf.org/doc/html/rfc5869

ChaCha20 / Poly1305 / AEAD (RFC 8439): https://datatracker.ietf.org/doc/html/rfc8439

X25519 (RFC 7748): https://datatracker.ietf.org/doc/html/rfc7748

---


#Secret Material Policy

Long-term private keys and pre-shared keys must not be committed to the repository.

For development purposes, the current implementation uses a local pre-shared key:

PSK = b"my_super_secret_psk"

This value must be generated locally and replaced before deployment.

Ephemeral X25519 key pairs are generated dynamically for every new session and are never stored permanently.
