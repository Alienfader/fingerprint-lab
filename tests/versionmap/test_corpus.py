import pytest

from tests.versionmap.conftest import by_major
from versionmap.corpus import capture_build, reduce_keys


def test_reduce_keys():
    assert reduce_keys([]) == ("", False, False)
    assert reduce_keys(["a", "a", "a"]) == ("a", True, True)
    assert reduce_keys(["a", "b", "a"]) == ("a", True, False)


@pytest.mark.integration
def test_capture_resolves_and_tolerates_dead_build(server, chromium_builds):
    e146 = capture_build(server, by_major(chromium_builds, "146"), n=5)
    e151 = capture_build(server, by_major(chromium_builds, "151"), n=5)
    e156 = capture_build(server, by_major(chromium_builds, "156"), n=5)
    assert e146.runnable and e146.stable
    assert e146.normalized_key != e151.normalized_key
    assert e151.normalized_key == e156.normalized_key          # 151/156 are a range
    e120 = capture_build(server, by_major(chromium_builds, "120"), n=2)
    assert e120.runnable is False and e120.normalized_key == ""  # OS-incompatible, no crash
