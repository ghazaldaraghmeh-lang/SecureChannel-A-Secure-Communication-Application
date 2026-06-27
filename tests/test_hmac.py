from crypto.hmac import hmac_sha256
import hmac
import hashlib


def test(key, msg):
    your = hmac_sha256(key, msg).hex()
    ref = hmac.new(key, msg, hashlib.sha256).hexdigest()

    print("=" * 60)
    print("Key :", key)
    print("Msg :", msg)
    print("Your:", your)
    print("Ref :", ref)

    assert your == ref, "HMAC mismatch!"
    print("PASS")


def main():
    test(b"secret", b"hello world")
    test(bytes([0x0b] * 20), b"Hi There")
    test(b"a", b"b" * 1000)
    test(b"\x00\x01\x02", b"\xff" * 50)

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
