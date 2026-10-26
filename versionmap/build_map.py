"""Fold corpus entries into a normalized-key -> versions map."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from versionmap.corpus import CorpusEntry


@dataclass(frozen=True)
class MapEntry:
    family: str
    version: str
    os: str
    arch: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


def _version_key(version: str) -> tuple:
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                 for p in re.split(r"[.\-]", version))


def _sort_key(m: MapEntry) -> tuple:
    return (m.family, _version_key(m.version), m.os, m.arch, m.source)


@dataclass
class VersionMap:
    entries_by_key: dict[str, list[MapEntry]] = field(default_factory=dict)

    def resolve(self, key: str) -> list[tuple]:
        return [(m.family, m.version, m.os, m.arch)
                for m in self.entries_by_key.get(key, [])]

    def granularity(self) -> dict:
        single, ranges, spans = [], [], {}
        for key, ms in self.entries_by_key.items():
            versions = sorted({m.version for m in ms}, key=_version_key)
            if len(versions) == 1:
                single.append(key)
            else:
                ranges.append(key)
                spans[key] = versions
        return {
            "single_version_keys": len(single),
            "range_keys": len(ranges),
            "total_keys": len(self.entries_by_key),
            "range_spans": {k: spans[k] for k in sorted(spans)},
        }


def build_version_map(entries: list[CorpusEntry]) -> VersionMap:
    """Map key -> MapEntries, keeping only runnable and stable entries."""
    grouped: dict[str, set[MapEntry]] = {}
    for e in entries:
        if not (e.runnable and e.stable) or not e.normalized_key:
            continue
        grouped.setdefault(e.normalized_key, set()).add(
            MapEntry(e.family, e.version, e.os, e.arch, e.source))
    return VersionMap({k: sorted(grouped[k], key=_sort_key)
                       for k in sorted(grouped)})


def dump_map(vmap: VersionMap, out_dir, metadata: dict) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "metadata": metadata,
        "keys": {k: [m.to_dict() for m in ms]
                 for k, ms in sorted(vmap.entries_by_key.items())},
    }
    (out / "version_map.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n")
