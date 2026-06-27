from crypto.chacha20 import chacha20_encrypt

key = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

nonce = bytes.fromhex(
    "000000000000004a00000000"
)

plaintext = (
    b"Ladies and Gentlemen of the class of '99: "
    b"If I could offer you only one tip for the future, sunscreen would be it."
)

expected_cipher = (
    "6e2e359a2568f98041ba0728dd0d6981"
    "e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b357"
    "1639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e"
    "52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42"
    "874d"
)

cipher = chacha20_encrypt(key, nonce, plaintext, counter=1)

print("Ciphertext:")
print(cipher.hex())

print("\nMatches RFC 8439:", cipher.hex() == expected_cipher)