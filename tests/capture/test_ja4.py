import hashlib
import re
from pathlib import Path

from capture.ja4 import GREASE, compute_ja3, compute_ja4, parse_client_hello

FIXTURE_BYTES = (Path(__file__).parent / "fixtures" / "chrome124_clienthello.bin").read_bytes()


def test_compute_ja4_matches_oracle():
    ch = parse_client_hello(FIXTURE_BYTES)
    assert compute_ja4(ch) == "t13d1516h2_8daaf6152771_02713d6af862"


def test_grease_excluded_from_counts():
    ch = parse_client_hello(FIXTURE_BYTES)
    # The raw hello does carry GREASE, so the filter below is not vacuous.
    assert any(c in GREASE for c in ch.ciphers)
    assert any(e in GREASE for e in ch.exts)
    # 16 raw ciphers/extensions minus GREASE must give the JA4_a counts.
    nongrease_ciphers = [c for c in ch.ciphers if c not in GREASE]
    nongrease_exts = [e for e in ch.exts if e not in GREASE]
    a = compute_ja4(ch).split("_")[0]
    assert a[4:6] == f"{len(nongrease_ciphers):02d}"
    assert a[6:8] == f"{len(nongrease_exts):02d}"


def test_ja4_a_fields():
    ch = parse_client_hello(FIXTURE_BYTES)
    a = compute_ja4(ch).split("_")[0]
    assert a == "t13d1516h2"  # TLS1.3, SNI present, 15 ciphers, 16 exts, h2


def test_compute_ja3_shape_and_hash():
    ch = parse_client_hello(FIXTURE_BYTES)
    ja3, md5 = compute_ja3(ch)
    assert re.fullmatch(r"[0-9a-f]{32}", md5)
    assert ja3.count(",") == 4  # 5 fields
    assert hashlib.md5(ja3.encode()).hexdigest() == md5
    version, ciphers, exts, curves, pf = ja3.split(",")
    assert version == "771"  # legacy_version 0x0303
    assert len(ciphers.split("-")) == 15
    assert len(exts.split("-")) == 16
    assert curves and pf
    # No GREASE value (all are decimal forms of 0x?a?a) in any field.
    grease_dec = {str(g) for g in GREASE}
    for field in (ciphers, exts, curves):
        assert not grease_dec & set(field.split("-"))


def test_parsed_curves_and_point_formats():
    ch = parse_client_hello(FIXTURE_BYTES)
    assert ch.point_formats == [0]
    assert 29 in ch.curves  # x25519
