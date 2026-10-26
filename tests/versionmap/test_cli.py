import json

import pytest

from versionmap.cli import main

HEADINGS = ["## Normalization recipe", "## Stability finding",
            "## Resolution granularity", "## Scope and caveats", "## Reproduce"]


@pytest.mark.integration
def test_cli_end_to_end(tmp_path):
    assert main(["--out", str(tmp_path), "--n", "4"]) == 0
    for name in ("version_map.json", "corpus.json", "README.md"):
        assert (tmp_path / name).is_file()
    doc = json.loads((tmp_path / "version_map.json").read_text())
    keys = doc["keys"]
    assert len(keys) >= 3
    assert any(len({m["version"] for m in ms}) > 1 for ms in keys.values())
    md = doc["metadata"]
    assert md["launch_flags"] and md["os"] and md["arch"]
    expected = "python -m versionmap --out %s --n 4" % tmp_path
    assert md["command"] == expected
    corpus = json.loads((tmp_path / "corpus.json").read_text())
    assert corpus["command"] == expected
    readme = (tmp_path / "README.md").read_text()
    for h in HEADINGS:
        assert h in readme
    for banned in ("Claude", "Anthropic"):
        assert banned not in readme
