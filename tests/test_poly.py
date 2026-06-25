from poly1305 import poly1305_mac


# =========================
# RFC 8439 Test Vector
# =========================

key = bytes.fromhex(
    "85d6be7857556d337f4452fe42d506a8"
    "0103808afb0db2fd4abff6af4149f51b"
)

message = b"Cryptographic Forum Research Group"

expected_tag = "a8061dc1305136c6c22b8baf0c0127a9"

# =========================
# Run test
# =========================

tag = poly1305_mac(key, message).hex()

print("Generated Tag :", tag)
print("Expected Tag  :", expected_tag)

if tag == expected_tag:
    print("\nPoly1305 is CORRECT")
else:
    print("\nPoly1305 is WRONG")