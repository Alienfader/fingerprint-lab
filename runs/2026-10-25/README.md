# Capture run

Joined TLS / HTTP/2 / HTTP / JS records captured by the self-hosted capture server (`phase1_capture.json` (written as `records.json` by the driver, renamed)).

Environment: macOS-26.6.2-arm64-arm-64bit-Mach-O, Python 3.15.0, curl_cffi 0.16.3, tls_client 2.0.0, h2 4.4.1, playwright 1.64.1.

| Client | JA4 | JS layer |
|--------|-----|----------|
| `curl:chrome124` | t13i1515h2_8daaf6152771_02713d6af862 | no |
| `curl:safari17_0` | t13i2013h2_a09f3c656075_14788d8d241b | no |
| `tls:chrome_124` | t13i1515h2_8daaf6152771_02713d6af862 | no |
| `stdlib:urllib` | t13i171000_ab0a1bf427ad_0d46a1bf4a7c | no |
| `browser:chromium` | t13d1516h2_8daaf6152771_27c4a575235d | yes |

## Reproduce

```
python -m capture.driver --out runs/2026-10-25 --clients curl:chrome124,curl:safari17_0,tls:chrome_124,stdlib:urllib,browser:chromium
```
