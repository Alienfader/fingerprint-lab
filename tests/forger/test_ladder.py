import pytest

from forger.ladder import LADDER, run_ladder


@pytest.mark.integration
def test_ladder_climbs_from_automated_to_real(server):
    rows = run_ladder(server)
    assert rows[0]["label"] == "automated"
    assert rows[-1]["label"] == "real"
    for row, rung in zip(rows[:-1], LADDER[:-1]):
        assert row["label"] == "automated"
        assert rung["defeats"] in {c["code"] for c in row["surviving_contradictions"]}
