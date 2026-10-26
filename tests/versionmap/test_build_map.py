import json

from versionmap.build_map import build_version_map, dump_map
from versionmap.corpus import CorpusEntry


def entry(version, key, runnable=True, stable=True):
    return CorpusEntry(
        family="chrome", version=version, os="mac", arch="arm64",
        source="cft", normalized_key=key, raw_ja4_samples=[], n=3,
        runnable=runnable, stable=stable,
    )


def test_single_version_key_resolves_exactly():
    vmap = build_version_map([entry("151", "k1"), entry("156", "k2")])
    assert vmap.granularity()["single_version_keys"] == 2
    assert vmap.resolve("k1") == [("chrome", "151", "mac", "arm64")]


def test_shared_key_becomes_range_not_overwrite():
    vmap = build_version_map([entry("150", "kX"), entry("151", "kX")])
    versions = {m.version for m in vmap.entries_by_key["kX"]}
    assert versions == {"150", "151"}
    assert vmap.granularity()["range_keys"] == 1


def test_dump_map_carries_os_arch_and_recipe(tmp_path):
    dump_map(build_version_map([entry("151", "k1")]), tmp_path,
             metadata={"recipe": "normalized-ext-key-v1", "os": "mac", "arch": "arm64"})
    doc = json.loads((tmp_path / "version_map.json").read_text())
    assert doc["metadata"]["os"] == "mac" and doc["metadata"]["recipe"]
    assert doc["keys"]["k1"][0]["arch"] == "arm64"


def test_non_runnable_and_unstable_entries_excluded():
    vmap = build_version_map([
        entry("150", "", runnable=False, stable=False),
        entry("151", "", runnable=True, stable=False),
        entry("152", "kU", runnable=True, stable=False),
        entry("153", "k1"),
    ])
    assert set(vmap.entries_by_key) == {"k1"}
    assert "" not in vmap.entries_by_key
    assert vmap.resolve("kU") == []


def test_duplicates_deduped_and_output_sorted(tmp_path):
    vmap = build_version_map([entry("151", "b"), entry("151", "b"),
                              entry("150", "b"), entry("149", "a")])
    assert len(vmap.entries_by_key["b"]) == 2
    assert vmap.granularity()["range_keys"] == 1
    dump_map(vmap, tmp_path, metadata={})
    doc = json.loads((tmp_path / "version_map.json").read_text())
    assert list(doc["keys"]) == ["a", "b"]
    assert [m["version"] for m in doc["keys"]["b"]] == ["150", "151"]
