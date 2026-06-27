# test_hkdf.py

from crypto.hkdf import hkdf_derive


def test_case(name, ikm, salt, info, length, expected_prefix_hex=None):
    print("=" * 60)
    print("Test:", name)

    result = hkdf_derive(ikm, salt, info, length)

    print("Output:", result.hex())

    # إذا عندك expected value (اختياري)
    if expected_prefix_hex:
        assert result.hex().startswith(expected_prefix_hex), "Mismatch with expected vector prefix!"

    assert len(result) == length, "Wrong output length!"

    print("PASS")


def main():

    # 1) Basic deterministic test
    test_case(
        name="Basic test",
        ikm=b"input key material",
        salt=b"salt",
        info=b"info",
        length=96
    )

    # 2) Empty salt case (RFC behavior)
    test_case(
        name="Empty salt",
        ikm=b"input key material",
        salt=b"",
        info=b"info",
        length=64
    )

    # 3) Long output test
    test_case(
        name="Long output",
        ikm=b"shared_secret_example",
        salt=b"psk",
        info=b"SecureChannel-v1",
        length=160
    )

    # 4) Edge case: zero-length info
    test_case(
        name="Empty info",
        ikm=b"abc",
        salt=b"salt",
        info=b"",
        length=64
    )

    print("\nALL HKDF TESTS PASSED")


if __name__ == "__main__":
    main()
