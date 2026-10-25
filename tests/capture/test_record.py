import json

from capture.record import Record, dump_run


def _full(label="curl:chrome124"):
    return Record(client_label=label, client_addr=("127.0.0.1", 5555),
                  tls={"ja3": "a", "ja3_hash": "b", "ja4": "t13d_x"},
                  http2={"akamai": "1:2|3", "akamai_hash": "h", "alpn": "h2"},
                  http={"header_order": ["a"], "client_hints": {}, "user_agent": "u",
                        "path": "/"},
                  js={"userAgent": "u", "webdriver": False})


def test_record_roundtrips_all_layers():
    d = _full().to_dict()
    assert set(d) >= {"tls", "http2", "http", "js", "client_label", "client_addr",
                      "captured_at"}
    assert d["client_addr"] == ["127.0.0.1", 5555]
    assert json.loads(json.dumps(d)) == d


def test_to_dict_handles_missing_layers():
    d = Record().to_dict()
    assert d["client_addr"] is None and d["tls"] is None
    json.dumps(d)


def test_dump_run_writes_records_and_readme(tmp_path):
    recs = [_full("a"), _full("b")]
    out = tmp_path / "run"
    dump_run(recs, str(out))
    assert json.loads((out / "records.json").read_text()) == [r.to_dict() for r in recs]
    readme = (out / "README.md").read_text()
    assert "python -m capture.driver" in readme
    assert "curl_cffi" in readme and "Python" in readme


def test_dump_run_custom_filename(tmp_path):
    dump_run([_full()], str(tmp_path), filename="phase1_capture.json")
    assert (tmp_path / "phase1_capture.json").exists()
    assert not (tmp_path / "records.json").exists()
    assert "phase1_capture.json" in (tmp_path / "README.md").read_text()
