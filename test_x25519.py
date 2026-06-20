from x25519 import x25519

print("Running X25519 tests...\n")

# =========================
# Test Vector 1
# =========================

alice_private = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a"
)

bob_public = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f"
)

expected = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25"
    "e07e21c947d19e3376f09b3c1e161742"
)

result = x25519(alice_private, bob_public)

print("Test 1")
print("Expected:", expected.hex())
print("Got     :", result.hex())
print("Pass:", result == expected)
print()

