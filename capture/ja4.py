"""TLS ClientHello parser plus JA3 / JA4 fingerprint computation.

GREASE values are excluded from every count and hash, per the FoxIO JA4
spec and the original JA3 convention.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

GREASE: frozenset[int] = frozenset(
    {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
)
VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}

_EXT_SNI = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_ALPN = 0x0010
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B


@dataclass
class ClientHello:
    legacy_ver: int
    ciphers: list[int] = field(default_factory=list)
    exts: list[int] = field(default_factory=list)
    sni: bool = False
    alpns: list[str] = field(default_factory=list)
    sigalgs: list[int] = field(default_factory=list)
    sup_vers: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)


def _u16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def _ng(xs: list[int]) -> list[int]:
    return [x for x in xs if x not in GREASE]


def _hex(v: int) -> str:
    return f"{v:04x}"


def parse_client_hello(rec: bytes) -> ClientHello:
    """Parse a raw TLS record (starting at the 0x16 record header) holding a ClientHello."""
    if rec[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    hs = rec[5:]
    if hs[0] != 0x01:
        raise ValueError("not a ClientHello")
    # handshake: type(1) len(3) version(2) random(32) sidlen(1) sid ...
    p = 4
    legacy_ver = _u16(hs, p)
    p += 2
    p += 32  # random
    p += 1 + hs[p]  # session id
    cslen = _u16(hs, p)
    p += 2
    ciphers = [_u16(hs, p + i) for i in range(0, cslen, 2)]
    p += cslen
    p += 1 + hs[p]  # compression methods
    extlen = _u16(hs, p)
    p += 2
    end = p + extlen

    ch = ClientHello(legacy_ver=legacy_ver, ciphers=ciphers)
    while p < end:
        et = _u16(hs, p)
        el = _u16(hs, p + 2)
        body = hs[p + 4 : p + 4 + el]
        p += 4 + el
        ch.exts.append(et)
        if et == _EXT_SNI:
            ch.sni = True
        elif et == _EXT_ALPN:
            q = 2
            while q < len(body):
                ln = body[q]
                ch.alpns.append(body[q + 1 : q + 1 + ln].decode("latin1"))
                q += 1 + ln
        elif et == _EXT_SIGNATURE_ALGORITHMS:
            n = _u16(body, 0)
            ch.sigalgs = [_u16(body, 2 + i) for i in range(0, n, 2)]
        elif et == _EXT_SUPPORTED_VERSIONS:
            n = body[0]
            ch.sup_vers = [_u16(body, 1 + i) for i in range(0, n, 2)]
        elif et == _EXT_SUPPORTED_GROUPS:
            n = _u16(body, 0)
            ch.curves = [_u16(body, 2 + i) for i in range(0, n, 2)]
        elif et == _EXT_EC_POINT_FORMATS:
            n = body[0]
            ch.point_formats = list(body[1 : 1 + n])
    return ch


def compute_ja4(ch: ClientHello) -> str:
    vers = _ng(ch.sup_vers) or [ch.legacy_ver]
    ver = VER.get(max(vers), "00")
    ciphers = _ng(ch.ciphers)
    exts = _ng(ch.exts)
    d = "d" if ch.sni else "i"
    alpn = (ch.alpns[0][0] + ch.alpns[0][-1]) if ch.alpns else "00"
    ja4_a = f"t{ver}{d}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}"
    ja4_b = hashlib.sha256(",".join(sorted(_hex(c) for c in ciphers)).encode()).hexdigest()[:12]
    ext_for_c = sorted(_hex(e) for e in exts if e not in (_EXT_SNI, _EXT_ALPN))
    sig = ",".join(_hex(s) for s in ch.sigalgs)
    c_in = ",".join(ext_for_c) + (("_" + sig) if sig else "")
    ja4_c = hashlib.sha256(c_in.encode()).hexdigest()[:12]
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def compute_ja3(ch: ClientHello) -> tuple[str, str]:
    """Return (ja3_string, md5_hex). Fields: version,ciphers,extensions,curves,point_formats."""

    def dash(xs: list[int]) -> str:
        return "-".join(str(x) for x in xs)

    ja3 = ",".join(
        [
            str(ch.legacy_ver),
            dash(_ng(ch.ciphers)),
            dash(_ng(ch.exts)),
            dash(_ng(ch.curves)),
            dash(ch.point_formats),
        ]
    )
    return ja3, hashlib.md5(ja3.encode()).hexdigest()
