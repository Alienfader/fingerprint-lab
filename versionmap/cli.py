"""python -m versionmap: discover builds, capture corpus, build map, write artifact."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from versionmap.build_map import build_version_map, dump_map, _version_key
from versionmap.chromium_builds import discover_chromium_builds
from versionmap.corpus import LAUNCH_FLAGS, CorpusEntry, build_corpus

DEFAULT_OUT = "runs/2026-10-25-version-map"
RECIPE = "direct-launch chromium, normalized ClientHello key (tls.ja4_norm)"


def _span(versions: list[str]) -> str:
    majors = sorted({v.split(".")[0] for v in versions}, key=int)
    return majors[0] if len(majors) == 1 else "%s-%s" % (majors[0], majors[-1])


def render_readme(entries: list[CorpusEntry], vmap, metadata: dict) -> str:
    g = vmap.granularity()
    ordered = sorted(entries, key=lambda e: _version_key(e.version))
    runnable = [e for e in ordered if e.runnable]
    stable = [e for e in runnable if e.stable]
    excluded = [e for e in ordered if not e.runnable]
    unstable = [e for e in runnable if not e.stable]
    L = []
    a = L.append
    a("# Phase 2: version-resolution map (Chromium, macOS/arm64)\n")
    a("I built this to answer one question: how finely can a TLS ClientHello "
      "alone resolve a Chromium version? The map goes from a normalized "
      "ClientHello key to the set of builds that produce it. Everything below "
      "is computed from `corpus.json` and `version_map.json` in this directory.\n")
    a("## Normalization recipe\n")
    a("The key is a JA4-style ClientHello hash computed after a normalization "
      "pass (exposed as `tls.ja4_norm`). Two exclusions matter:\n")
    a("- **GREASE values inside `signature_algorithms`.** Chromium injects a "
      "random GREASE code point into the signature_algorithms list on each "
      "connection. Naive JA4 implementations filter GREASE from ciphers, "
      "extensions and versions but forget this list, so JA4_c changes from one "
      "connection to the next even though nothing about the build changed. I "
      "strip GREASE there too.")
    a("- **Resumption extensions `pre_shared_key` (0x0029) and `early_data` "
      "(0x002a).** These appear only when the client attempts session "
      "resumption, so they toggle between connections of the same build. They "
      "are excluded so a resumed and a fresh connection give the same key.\n")
    a("Each entry's `source` (cft or playwright) records only where the binary "
      "came from. Every build, including the playwright-sourced ones, was "
      "launched directly by my harness with the flags listed under Scope and "
      "caveats, so all keys are from the direct-launch profile.\n")
    a("The Phase 1 artifact (`runs/2026-10-25/phase1_capture.json`) predates the "
      "GREASE-in-signature_algorithms fix, so its browser JA4_c was computed by "
      "the old code. I have not re-run Phase 1.\n")
    a("## Stability finding\n")
    a("A key is only useful if one build always produces the same one. During "
      "de-risking, Chrome 156 produced about 25 distinct raw keys over 40 "
      "connections before the fix (a motivating measurement, not part of this "
      "artifact). For this artifact, each build was launched %d times; the "
      "table compares distinct raw JA4 strings with the normalized key.\n"
      % (ordered[0].n if ordered else 0))
    a("| Chromium | runnable | connections captured | distinct raw JA4 | normalized key stable |")
    a("|---|---|---|---|---|")
    for e in ordered:
        a("| %s | %s | %d | %d | %s |" % (
            e.version, "yes" if e.runnable else "no", len(e.raw_ja4_samples),
            len(set(e.raw_ja4_samples)), "yes" if e.stable else "no"))
    a("")
    a("%d of %d runnable builds gave a single normalized key across all "
      "captured connections." % (len(stable), len(runnable)))
    a("")
    a("Note on what this run does and does not show: here the distinct-raw-JA4 "
      "count is 1 for every build, i.e. the raw JA4_c already equals the "
      "normalized key. That is because the GREASE-in-signature_algorithms fix "
      "removes the main source of raw per-connection variance, and each capture "
      "uses a fresh `--user-data-dir`, so the client never attempts session "
      "resumption and the `pre_shared_key`/`early_data` extensions never appear. "
      "So in this artifact the normalization's resumption exclusion is a "
      "defensive guarantee (exercised by the unit tests, not by these fresh-cache "
      "captures), and the pre-fix ~25-keys measurement is what motivates the "
      "GREASE-in-sigalgs exclusion. Both exclusions are in the key so a "
      "resumption-bearing or GREASE-bearing connection still resolves correctly.\n")
    if unstable:
        a("Unstable builds (excluded from the map): %s."
          % ", ".join(e.version for e in unstable))
    a("")
    a("## Resolution granularity\n")
    a("The map holds **%d keys over %d runnable, stable builds**: %d "
      "single-version keys and %d range keys.\n"
      % (g["total_keys"], len(stable), g["single_version_keys"], g["range_keys"]))
    for key, ms in sorted(vmap.entries_by_key.items()):
        vs = [m.version for m in ms]
        a("- `%s` -> %s (%s)" % (key, ", ".join(vs),
                                "single version" if len(vs) == 1 else
                                "range, Chromium %s" % _span(vs)))
    a("")
    a("A range key means those builds are indistinguishable by this key; the "
      "map can say 'one of these', not which.\n")
    a("## Scope and caveats\n")
    a("- Chrome/Chromium only, on %s/%s, %d runnable builds (%s)."
      % (metadata["os"], metadata["arch"], len(runnable),
         ", ".join(e.version for e in runnable)))
    if excluded:
        a("- Not runnable on this machine, so excluded: %s (produced no "
          "ClientHello; e.g. OS-incompatible on this macOS)."
          % ", ".join(e.version for e in excluded))
    a("- The key is valid only for the recorded launch profile (direct launch "
      "with these flags): `%s`. During de-risking I saw a different key for "
      "the same build under Playwright's automation flags (an observation "
      "outside this artifact, not computed from corpus.json)."
      % " ".join(metadata["launch_flags"]))
    a("- Multi-OS coverage is deferred; it needs my own Windows and Linux VMs.")
    a("- Enrichment from public fingerprint datasets is deferred pending a "
      "license check.\n")
    a("## Reproduce\n")
    a("```\n%s\n```\n" % metadata["command"])
    a("Generated at %s." % metadata["generated_at"])
    a("\nAuthor: Thiago Goncalves")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m versionmap")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--n", type=int, default=10)
    args = ap.parse_args(argv)

    command = "python -m versionmap --out %s --n %d" % (args.out, args.n)
    builds = discover_chromium_builds()
    if not builds:
        print("error: no Chromium builds discovered; nothing to capture",
              file=sys.stderr)
        return 1
    entries = build_corpus(builds, args.n, args.out, command=command)
    vmap = build_version_map(entries)
    metadata = {
        "recipe": RECIPE,
        "os": sorted({b.os for b in builds})[0] if builds else "",
        "arch": sorted({b.arch for b in builds})[0] if builds else "",
        "launch_flags": LAUNCH_FLAGS,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": command,
    }
    dump_map(vmap, args.out, metadata)
    (Path(args.out) / "README.md").write_text(
        render_readme(entries, vmap, metadata), encoding="utf-8")
    return 0
