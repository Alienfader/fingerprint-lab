import pytest

from tests.versionmap.conftest import by_major
from versionmap import corpus
from versionmap.chromium_builds import ChromiumBuild
from versionmap.corpus import capture_build, reduce_keys


def test_reduce_keys():
    assert reduce_keys([]) == ("", False, False)
    assert reduce_keys(["a", "a", "a"]) == ("a", True, True)
    assert reduce_keys(["a", "b", "a"]) == ("a", True, False)


def test_dead_build_entry_offline(monkeypatch):
    monkeypatch.setattr(corpus, "_capture_once", lambda server, exe: None)
    b = ChromiumBuild("120.0.0.0", "mac", "arm64", "/nonexistent", "cft")
    e = capture_build(None, b, n=3)
    assert e.runnable is False and e.normalized_key == "" and e.stable is False
    d = e.to_dict()
    assert (d["runnable"], d["normalized_key"], d["stable"], d["n"]) == (False, "", False, 3)
    assert d["raw_ja4_samples"] == []


def test_unexecable_binary_returns_none(tmp_path):
    class S:
        records = {}
        port = 1
    bad = tmp_path / "bad"
    bad.write_text("not an executable")
    assert corpus._capture_once(S(), str(bad)) is None


@pytest.mark.integration
def test_capture_resolves_and_tolerates_dead_build(server, chromium_builds):
    e146 = capture_build(server, by_major(chromium_builds, "146"), n=5)
    e151 = capture_build(server, by_major(chromium_builds, "151"), n=5)
    e156 = capture_build(server, by_major(chromium_builds, "156"), n=5)
    assert e146.runnable and e146.stable and e146.normalized_key != ""
    assert e151.runnable and e151.stable and e151.normalized_key != ""
    assert e156.runnable
    assert e146.normalized_key != e151.normalized_key
    assert e151.normalized_key == e156.normalized_key          # 151/156 are a range
    e120 = capture_build(server, by_major(chromium_builds, "120"), n=2)
    assert e120.runnable is False and e120.normalized_key == ""  # OS-incompatible, no crash
