import pytest

from tests.challenge.conftest import _get, _post, _wait_probe_record


@pytest.mark.integration
def test_challenge_served_and_answer_joined(server):
    server.register_challenge("chlXYZ", "cafe")
    page = _get(server, "/challenge/chlXYZ")
    assert "cafe" in page and "/answer/chlXYZ" in page
    _post(server, "/answer/chlXYZ", b"abc123")
    assert server.get_answer("chlXYZ") == "abc123"


@pytest.mark.integration
def test_probe_collect_still_join(server):
    nonce = "prbTEST"
    _get(server, "/probe/" + nonce)
    _post(server, "/collect/" + nonce, b'{"webdriver": false}')
    rec = _wait_probe_record(server, nonce)
    assert rec.js == {"webdriver": False}
