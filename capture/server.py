"""Non-consuming TLS capture + termination server.

Per connection: MSG_PEEK the ClientHello (leaves it in the kernel buffer),
compute JA3/JA4, then hand the untouched socket to the stdlib ssl stack so the
real handshake re-reads the same bytes. Binds loopback by default; no
privileges needed.
"""
from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
import uuid

from capture.ja4 import compute_ja3, compute_ja4, parse_client_hello
from capture.record import Record

log = logging.getLogger(__name__)

MAX_RECORD = 5 + 0xFFFF
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class CaptureServer:
    def __init__(self, certfile: str, keyfile: str, host: str = "127.0.0.1",
                 port: int = 0, peek_timeout: float = 5.0, io_timeout: float = 5.0):
        self.host = host
        self.port = port
        self.peek_timeout = peek_timeout
        self.io_timeout = io_timeout
        self.records: dict[str, Record] = {}
        self._lock = threading.Lock()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._ctx.set_alpn_protocols(["http/1.1"])
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
            except Exception as e:  # ClientHello present but unparseable
                log.warning("ClientHello parse failed from %s: %s (%d bytes)",
                            addr, type(e).__name__, len(rec_bytes))
                return
            record = Record(client_addr=addr,
                            tls={"ja3": ja3, "ja3_hash": ja3_hash, "ja4": ja4})
            with self._lock:
                self.records[uuid.uuid4().hex] = record
            conn.settimeout(self.io_timeout)
            tls = self._ctx.wrap_socket(conn, server_side=True)
            tls.settimeout(self.io_timeout)
            tls.recv(65536)
            tls.sendall(RESPONSE)
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
