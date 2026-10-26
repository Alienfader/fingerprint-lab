"""Non-consuming TLS capture + termination server.

Per connection: MSG_PEEK the ClientHello (leaves it in the kernel buffer),
compute JA3/JA4, then hand the untouched socket to the stdlib ssl stack so the
real handshake re-reads the same bytes. Binds loopback by default; no
privileges needed.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
import time
import uuid

import h2.config
import h2.connection
import h2.events
import h2.exceptions

from capture.http2_fp import akamai_fingerprint
from capture.probe import probe_html, valid_nonce
from capture.ja4 import compute_ja3, compute_ja4, normalized_ext_key, parse_client_hello
from capture.record import Record

log = logging.getLogger(__name__)

MAX_RECORD = 5 + 0xFFFF
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


MAX_HEADER_BYTES = 65536
MAX_BODY_BYTES = 262144
REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 413: "Payload Too Large"}


def summarize_headers(pairs: list[tuple[str, str]]) -> dict:
    """Build the record.http layer from (name, value) pairs in received order."""
    ua = next((v for n, v in pairs if n.lower() == "user-agent"), None)
    return {"header_order": [n for n, _ in pairs],
            "client_hints": {n: v for n, v in pairs if n.lower().startswith("sec-ch-")},
            "user_agent": ua}


def parse_h1_headers(raw: bytes) -> list[tuple[str, str]]:
    """Parse an HTTP/1.x request head into ordered (name, value) pairs.

    Raises ValueError if there is no request line or a header line lacks a colon.
    """
    head = raw.split(b"\r\n\r\n", 1)[0]
    lines = head.decode("latin-1").split("\r\n")
    if len(lines) < 1 or len(lines[0].split(" ")) != 3:
        raise ValueError("malformed request line")
    pairs = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise ValueError("malformed header line")
        pairs.append((name.strip(), value.strip()))
    return pairs


class CaptureServer:
    def __init__(self, certfile: str, keyfile: str, host: str = "127.0.0.1",
                 port: int = 0, peek_timeout: float = 5.0, io_timeout: float = 5.0):
        self.host = host
        self.port = port
        self.peek_timeout = peek_timeout
        self.io_timeout = io_timeout
        self.records: dict[str, Record] = {}
        self._lock = threading.Lock()
        self._nonce_records: dict[str, str] = {}  # nonce -> record id (guarded by _lock)
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._ctx.set_alpn_protocols(["h2", "http/1.1"])
        self._lsock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._stop = threading.Event()

    def start(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(32)
        s.settimeout(0.2)
        self._lsock = s
        self.port = s.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._lsock:
            self._lsock.close()
            self._lsock = None
        with self._lock:
            workers = list(self._workers)
        for w in workers:
            w.join(timeout=self.peek_timeout + 2 * self.io_timeout + 1)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            with self._lock:
                self._workers.add(t)
            t.start()

    def _peek_client_hello(self, conn: socket.socket) -> bytes | None:
        """Peek (without consuming) until the full first TLS record is buffered."""
        deadline = time.monotonic() + self.peek_timeout
        last = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._stop.is_set():
                return None
            conn.settimeout(remaining)
            buf = conn.recv(MAX_RECORD, socket.MSG_PEEK)
            if not buf:
                return None
            if buf[0] != 0x16:  # not a TLS handshake record
                return None
            if len(buf) >= 5:
                need = 5 + int.from_bytes(buf[3:5], "big")
                if len(buf) >= need:
                    return buf[:need]
            if len(buf) == last:
                time.sleep(0.01)  # PEEK returns at once; avoid a hot spin
            last = len(buf)

    def _route(self, method: str, path: str, body: bytes,
               rid: str) -> tuple[int, str, bytes]:
        """Return (status, content_type, body). Unknown paths get the default 'ok'."""
        path = path.split("?", 1)[0]
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "":
            kind, nonce = parts[1], parts[2]
            if kind == "probe" and method == "GET":
                if not valid_nonce(nonce):
                    return 400, "text/plain", b"bad nonce"
                with self._lock:
                    self._nonce_records[nonce] = rid
                return 200, "text/html; charset=utf-8", probe_html(nonce).encode()
            if kind == "collect" and method == "POST":
                try:
                    data = json.loads(body.decode("utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError
                except ValueError:  # includes UnicodeDecodeError / JSONDecodeError
                    return 400, "text/plain", b"bad json"
                with self._lock:
                    trid = self._nonce_records.get(nonce, "")
                    target = self.records.get(trid)
                    if target is not None:
                        target.js = data
                    if target is not None and trid != rid:
                        # R7: this POST connection's own record is pure plumbing
                        # (its TLS duplicates the GET connection's); drop it.
                        self.records.pop(rid, None)
                return (204 if target is not None else 400), "text/plain", b""
        return 200, "text/plain", b"ok"

    def _serve_h2(self, tls: ssl.SSLSocket, record: Record, rid: str) -> None:
        """Speak HTTP/2, capture the Akamai fingerprint from the first request,
        route it (reading any request body until end_stream), reply, close."""
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        conn.initiate_connection()
        tls.sendall(conn.data_to_send())
        settings: list[tuple[int, int]] = []
        window: int | None = None
        priorities: list = []
        req: dict | None = None  # {"stream", "method", "path", "body"}
        deadline = time.monotonic() + 2 * self.io_timeout
        while time.monotonic() < deadline and not self._stop.is_set():
            data = tls.recv(65536)  # bounded by tls.settimeout
            if not data:
                return
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.RemoteSettingsChanged) and not settings:
                    settings = [(int(k), int(c.new_value))
                                for k, c in ev.changed_settings.items()]
                elif isinstance(ev, h2.events.WindowUpdated) and ev.stream_id == 0 \
                        and window is None:
                    window = ev.delta
                elif isinstance(ev, h2.events.PriorityUpdated):
                    priorities.append((ev.stream_id, ev.exclusive, ev.depends_on,
                                       ev.weight))
                elif isinstance(ev, h2.events.RequestReceived) and req is None:
                    order = [h[1] for h, _ in ev.headers if h.startswith(":")]
                    s, hx = akamai_fingerprint(settings, window, priorities, order)
                    record.http = summarize_headers(
                        [(n, v) for n, v in ev.headers if not n.startswith(":")])
                    record.http2 = {"akamai": s, "akamai_hash": hx, "alpn": "h2"}
                    hd = dict(ev.headers)
                    record.http["path"] = hd.get(":path", "/")
                    req = {"stream": ev.stream_id, "method": hd.get(":method", "GET"),
                           "path": hd.get(":path", "/"), "body": b""}
                elif isinstance(ev, h2.events.DataReceived):
                    conn.acknowledge_received_data(ev.flow_controlled_length,
                                                   ev.stream_id)
                    if req is not None and ev.stream_id == req["stream"]:
                        req["body"] += ev.data
                elif isinstance(ev, h2.events.StreamEnded) and req is not None \
                        and ev.stream_id == req["stream"]:
                    if len(req["body"]) > MAX_BODY_BYTES:
                        status, ctype, payload = 413, "text/plain", b""
                    else:
                        status, ctype, payload = self._route(
                            req["method"], req["path"], req["body"], rid)
                    hdrs = [(":status", str(status)),
                            ("content-length", str(len(payload)))]
                    if payload:
                        hdrs.append(("content-type", ctype))
                    conn.send_headers(req["stream"], hdrs, end_stream=not payload)
                    if payload:
                        conn.send_data(req["stream"], payload, end_stream=True)
                    tls.sendall(conn.data_to_send())
                    conn.close_connection()
                    tls.sendall(conn.data_to_send())
                    return
            out = conn.data_to_send()  # SETTINGS acks etc.
            if out:
                tls.sendall(out)

    def _serve_h1(self, tls: ssl.SSLSocket, record: Record, addr: tuple,
                  rid: str) -> None:
        """Read the request (head + Content-Length body), capture header order/client
        hints, route, reply."""
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < MAX_HEADER_BYTES:
            chunk = tls.recv(65536)  # bounded by tls.settimeout
            if not chunk:
                break
            buf += chunk
        try:
            pairs = parse_h1_headers(buf)
            record.http = summarize_headers(pairs)
        except ValueError as e:
            log.warning("h1 request parse failed from %s: %s (%d bytes)",
                        addr, e, len(buf))
            tls.sendall(RESPONSE)
            return
        method, path = buf.split(b" ", 2)[0].decode("latin-1"), \
            buf.split(b" ", 2)[1].decode("latin-1")
        record.http["path"] = path
        head, _, body = buf.partition(b"\r\n\r\n")
        try:
            clen = int(next((v for n, v in pairs if n.lower() == "content-length"), 0))
        except ValueError:
            clen = -1
        if clen < 0 or clen > MAX_BODY_BYTES:
            status, ctype, payload = 413 if clen > 0 else 400, "text/plain", b""
        else:
            while len(body) < clen:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                body += chunk
            status, ctype, payload = self._route(method, path, body[:clen], rid)
        tls.sendall(("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                     "Connection: close\r\n\r\n" % (status, REASONS.get(status, "OK"),
                                                     ctype, len(payload))).encode()
                    + payload)

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        tls = None
        try:
            try:
                rec_bytes = self._peek_client_hello(conn)
            except OSError:
                return  # peek timeout / reset: no ClientHello received
            if rec_bytes is None:
                return  # benign: EOF, timeout, or non-TLS first byte
            try:
                ch = parse_client_hello(rec_bytes)
                ja3, ja3_hash = compute_ja3(ch)
                ja4 = compute_ja4(ch)
                ja4_norm = normalized_ext_key(ch)
            except Exception as e:  # ClientHello present but unparseable
                log.warning("ClientHello parse failed from %s: %s (%d bytes)",
                            addr, type(e).__name__, len(rec_bytes))
                return
            record = Record(client_addr=addr,
                            tls={"ja3": ja3, "ja3_hash": ja3_hash, "ja4": ja4,
                                 "ja4_norm": ja4_norm})
            rid = uuid.uuid4().hex
            with self._lock:
                self.records[rid] = record
            conn.settimeout(self.io_timeout)
            tls = self._ctx.wrap_socket(conn, server_side=True)
            tls.settimeout(self.io_timeout)
            if tls.selected_alpn_protocol() == "h2":
                self._serve_h2(tls, record, rid)
            else:
                self._serve_h1(tls, record, addr, rid)
        except h2.exceptions.H2Error as e:
            log.warning("h2 protocol error from %s: %s", addr, type(e).__name__)
        except (OSError, ssl.SSLError):
            pass
        finally:
            for s in (tls, conn):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            with self._lock:
                self._workers.discard(threading.current_thread())
