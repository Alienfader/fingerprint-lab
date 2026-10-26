import pytest

from challenge.ladder import run_ladder


@pytest.mark.integration
def test_ladder_catches_only_the_coherent_forger(server):
    rows = {r["name"]: r for r in run_ladder(server)}
    assert rows["honest-browser"]["passed"] is True
    assert rows["coherent-forger"]["passed"] is False
    assert rows["engine-forger"]["passed"] is True
