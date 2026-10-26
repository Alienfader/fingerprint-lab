from pathlib import Path

import pytest

from versionmap.chromium_builds import discover_chromium_builds


@pytest.mark.integration
def test_discovers_installed_chromium_builds():
    builds = discover_chromium_builds()
    majors = {b.version.split(".")[0] for b in builds}
    assert {"130", "140", "146", "150", "151", "156"} <= majors
    for b in builds:
        assert Path(b.executable_path).exists()
        assert b.os == "mac" and b.arch == "arm64"
        assert b.source in ("cft", "playwright")
