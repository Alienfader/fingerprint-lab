import pytest

from challenge.clients import coherent_forger, engine_forger, honest_browser
from challenge.issue import make_challenge
from challenge.oracle import run_oracle
from challenge.verify import verify


@pytest.mark.integration
def test_oracle_and_honest_browser_agree(server):
    c = make_challenge()
    expected = run_oracle(server, c)
    assert expected
    got = honest_browser(server, c.seed)
    assert verify(expected, got) is True


@pytest.mark.integration
def test_coherent_forger_cannot_answer(server):
    c = make_challenge()
    assert coherent_forger(server, c.seed) in (None, "")


@pytest.mark.integration
def test_engine_forger_computes_a_valid_answer(server):
    c = make_challenge()
    expected = run_oracle(server, c)
    assert verify(expected, engine_forger(server, c.seed)) is True
