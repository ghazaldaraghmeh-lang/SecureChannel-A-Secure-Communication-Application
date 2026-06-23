from handshake import perform_handshake

def test_handshake():
    r1 = perform_handshake()
    r2 = perform_handshake()

    # 1. التأكد من وجود القيم
    assert r1["shared_secret"] is not None
    assert r1["session_key"] is not None
    assert r1["nonce"] is not None

    # 2. التأكد من الأطوال
    assert len(r1["session_key"]) == 32
    assert len(r1["nonce"]) == 32

    # 3. كل handshake مستقل يعطي قيم صحيحة
    assert len(r2["session_key"]) == 32
    assert len(r2["nonce"]) == 32


    print("✔ Handshake test passed")

if __name__ == "__main__":
    test_handshake()