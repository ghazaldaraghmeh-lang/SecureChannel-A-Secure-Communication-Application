from crypto.aead import aead_encrypt, aead_decrypt

key = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)

# RFC 8439 nonce = fixed-common (4 bytes) + IV (8 bytes)
nonce = bytes.fromhex(
    "070000004041424344454647"
)

aad = bytes.fromhex(
    "50515253c0c1c2c3c4c5c6c7"
)

plaintext = (
    b"Ladies and Gentlemen of the class of '99: "
    b"If I could offer you only one tip for the future, sunscreen would be it."
)

expected_ciphertext = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
)

expected_tag = bytes.fromhex(
    "1ae10b594f09e26a7e902ecbd0600691"
)

ciphertext, tag = aead_encrypt(
    key,
    nonce,
    plaintext,
    aad
)

print("Ciphertext:")
print(ciphertext.hex())

print("\nExpected Ciphertext:")
print(expected_ciphertext.hex())

print("\nCiphertext Match:",
      ciphertext == expected_ciphertext)

print("\nTag:")
print(tag.hex())

print("\nExpected Tag:")
print(expected_tag.hex())

print("\nTag Match:",
      tag == expected_tag)

recovered = aead_decrypt(
    key,
    nonce,
    ciphertext,
    tag,
    aad
)

print("\nRecovered Plaintext:")
print(recovered)

print("\nDecrypt OK:",
      recovered == plaintext)