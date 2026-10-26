from challenge.verify import verify


def test_verify_exact_and_seed_sensitive():
    assert verify("deadbeef", "deadbeef") is True
    assert verify("deadbeef", "feedface") is False
    assert verify(None, "deadbeef") is False
    assert verify("deadbeef", None) is False
    assert verify("", "") is False
