import hashlib
import re
from pathlib import Path

from capture.ja4 import GREASE, ClientHello, compute_ja3, compute_ja4, parse_client_hello

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


def test_compute_ja3_synthetic_exact_values():
    # Hand-built hello: pins field order, version placement, GREASE exclusion
    # on ciphers/extensions/curves, and curves vs point_formats not swapped.
    ch = ClientHello(
        legacy_ver=0x0303,
        ciphers=[0x0A0A, 0x1301, 0xC02B],
        exts=[0x1A1A, 0x0000, 0x000A, 0x000B, 0x2A2A],
        curves=[0x3A3A, 29, 23],
        point_formats=[0, 1],
    )
    ja3, md5 = compute_ja3(ch)
    assert ja3 == "771,4865-49195,0-10-11,29-23,0-1"
    assert md5 == "98ec1f3f1d3348ab2e2d66e11eaacdf3"


def test_compute_ja3_fixture_regression_pin():
    # Regression guard on the saved bytes (not an oracle match: curl_cffi
    # shuffles extension order per connection, so peet.ws legitimately differs).
    ch = parse_client_hello(FIXTURE_BYTES)
    ja3, md5 = compute_ja3(ch)
    assert ja3 == (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "51-27-5-65281-23-45-0-11-18-16-65037-17513-10-35-13-43,25497-29-23-24,0"
    )
    assert md5 == "233c2ed2533144fdaafed27e54f93077"
