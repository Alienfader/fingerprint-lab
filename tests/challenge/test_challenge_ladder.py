import pytest

from challenge.ladder import LADDER, run_ladder


@pytest.mark.integration
def test_ladder_catches_only_the_coherent_forger(server):
    rows = run_ladder(server)
    by = {r["name"]: r for r in rows}
    assert by["honest-browser"]["passed"] is True
    assert by["coherent-forger"]["passed"] is False
    assert by["engine-forger"]["passed"] is True
    assert len(rows) == len(LADDER)
    for row, rung in zip(rows, LADDER):
        assert row["name"] == rung["name"]
        assert row["passed"] == rung["expect_pass"]
