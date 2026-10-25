# Run 2026-10-24

Raw output behind `docs/ANTIBOT_RESEARCH.md`. Environment in `environment.txt`
(Apple M1, macOS 26.6.2, Python 3.15.0, curl_cffi 0.16.3, tls_client 2.0.0,
Playwright 1.64.1, Chromium 156.0.8078.4).

| File | Command |
|------|---------|
| `ja3_diff.txt` | `python ja3_diff.py` |
| `ja3_diff.json` | `python ja3_diff.py --json` (a second run; the banner lines the script prints before the JSON were removed) |
| `browser_fp.txt` | `python browser_fp.py` |
| `browser_fp.json` | `python browser_fp.py --json` |

The `.txt` and `.json` files are two separate runs, so JA3 values for the shuffling
profiles differ between them. JA4, HTTP/2 and PeetPrint are identical in both.

## Against the writeup

- Every JA4 prefix, every HTTP/2 hash, the 6 / 4 / 0 tell counts, the canvas hash
  `3a5a21e78b1724c1` and the SwiftShader renderer match.
- The urllib and requests JA4 extension hashes (third segment) are `0d46a1bf4a7c` and
  `8deb338c2fb1` here (Python 3.15.0). An earlier run on an unrecorded Python/OpenSSL
  produced different values; the writeup has since been updated to this run's numbers.
- curl:chrome150's JA3 was `a80794c4…` and `3088316f…` in the two runs here (the writeup
  cites `a80794c4…`). It varies per connection — expected extension shuffling.
- tls:safari_16_0's JA3 also changed between runs (`d7f83ec8…`, `d2397f7b…`) while
  curl:safari17_0's stayed `773906b0…`. `ja3_diff.py` sets
  `random_tls_extension_order=True` for every tls_client profile, Safari included.
- PeetPrint agreed across both engines for Chrome (`67c3e911…`) and for Safari
  (`b2bafdc6…`).
- `--json` on `ja3_diff.py` prints the banner before the JSON, so its stdout is not
  valid JSON on its own.
