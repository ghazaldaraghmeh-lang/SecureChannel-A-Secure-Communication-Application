from crypto.poly1305 import poly1305_mac

# RFC 8439 Test Vector
key = bytes.fromhex(
    "85d6be7857556d337f4452fe42d506a8"
    "0103808afb0db2fd4abff6af4149f51b"
)

message = b"Cryptographic Forum Research Group"

expected_tag = bytes.fromhex(
    "a8061dc1305136c6c22b8baf0c0127a9"
)

tag = poly1305_mac(key, message)

print("Generated Tag:")
print(tag.hex())

print("\nExpected Tag:")
print(expected_tag.hex())

print("\nMatches RFC 8439:", tag == expected_tag)