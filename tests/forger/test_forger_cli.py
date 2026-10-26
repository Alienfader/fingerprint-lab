import json

import pytest

from forger.cli import main


@pytest.mark.integration
def test_cli_writes_artifact(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    doc = json.loads((tmp_path / "ladder.json").read_text())
    assert doc["rungs"][-1]["label"] == "real"
    readme = (tmp_path / "README.md").read_text()
    for h in ("## The attack", "## Evasion ladder", "## What this measures",
              "## Scope and ethics", "## Reproduce"):
        assert h in readme
    for banned in ("Claude", "Anthropic", "AI-generated"):
        assert banned not in readme
