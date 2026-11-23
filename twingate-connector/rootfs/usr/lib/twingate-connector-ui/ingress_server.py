"""Read-only web server for a Home Assistant add-on page shown through ingress.

This module holds the parts that do not depend on the add-on: it serves a
fixed set of files from one directory and JSON documents produced by
callbacks, accepts connections only from the Supervisor's ingress proxy, and
sets restrictive security headers on every response. It uses the Python
standard library only (Python 3.9 or later).

Ingress rules followed here (Home Assistant developer documentation, "Add a
web interface with ingress"): only accept connections from 172.30.32.2, use
relative URLs, and honour the X-Ingress-Path header that Home Assistant adds
to every request. The page template may contain the marker
<!-- ingress-base --> in its head; it is replaced by a <base> element that
points at the ingress path, so relative URLs also resolve when the page is
opened without a trailing slash.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import sys
import threading
import time
from http import HTTPStatus
from urllib.parse import urlsplit

# The Supervisor's ingress proxy connects from this address. Home Assistant
# authenticates the user before a request reaches the add-on.
INGRESS_PROXY_ADDRESS = "172.30.32.2"

# X-Ingress-Path is "/api/hassio_ingress/<token>"; the token is URL-safe base64.
_INGRESS_PATH = re.compile(r"/api/hassio_ingress/[A-Za-z0-9_-]{1,256}")

# A Content-Length that announces no body.
_ZEROS = re.compile(r"0+")

BASE_MARKER = b"<!-- ingress-base -->"

CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}

# No inline script or style, no external origins. frame-ancestors 'self'
# allows the Home Assistant frontend (same origin as the ingress URL) to show
# the page in its iframe.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "base-uri 'self'",
        "form-action 'none'",
        "frame-ancestors 'self'",
    )
)

SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
)


def log(message: str) -> None:
    """Writes one line to standard error, which ends up in the add-on log."""
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def json_bytes(document: object) -> bytes:
    """Encodes a JSON document as ASCII with <, > and & escaped."""
    text = json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def ingress_base_path(value: str | None) -> str | None:
    """Returns the X-Ingress-Path value if it has the expected form."""
    if value and _INGRESS_PATH.fullmatch(value):
        return value
    return None


class App:
    """Routes of the page: static files, the page template and JSON callbacks.

    files maps a request path to a file name in www_dir. index_file is served
    for "/" with the ingress base inserted. json_routes maps a request path to
    a callable that receives the request headers and returns a JSON document.
    """

    def __init__(self, www_dir: str, files: dict[str, str], index_file: str, json_routes: dict) -> None:
        self.files: dict[str, tuple[bytes, str]] = {}
        for path, name in files.items():
            self.files[path] = self._load(www_dir, name)
        self.index, _ = self._load(www_dir, index_file)
        self.json_routes = dict(json_routes)

    @staticmethod
    def _load(www_dir: str, name: str) -> tuple[bytes, str]:
        if "/" in name or name.startswith("."):
            raise ValueError(f"invalid file name {name!r}")
        with open(os.path.join(www_dir, name), "rb") as handle:
            content = handle.read()
        extension = os.path.splitext(name)[1].lower()
        return content, CONTENT_TYPES.get(extension, "application/octet-stream")

    def render_index(self, ingress_path: str | None) -> bytes:
        base = b""
        if ingress_path:
            base = b'<base href="' + ingress_path.encode("ascii") + b'/">'
        return self.index.replace(BASE_MARKER, base, 1)


class _RefusalLog:
    """Logs refused connections, at most once a minute per address."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def note(self, address: str) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last.get(address, -3600.0) < 60.0:
                return
            if len(self._last) > 256:
                self._last.clear()
            self._last[address] = now
        log(f"Web UI: refused a connection from {address}; only the Home Assistant ingress proxy ({INGRESS_PROXY_ADDRESS}) may connect.")


class IngressHTTPServer(http.server.ThreadingHTTPServer):
    """HTTP server that drops every connection not made by the ingress proxy."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, port: int, app: App, allowed_address: str = INGRESS_PROXY_ADDRESS) -> None:
        self.app = app
        self.allowed_address = allowed_address
        self._refusals = _RefusalLog()
        super().__init__(("0.0.0.0", port), _Handler)

    def verify_request(self, request, client_address) -> bool:
        # Called before anything is read from the connection; returning
        # False closes it without a response.
        if client_address[0] == self.allowed_address:
            return True
        self._refusals.note(str(client_address[0]))
        return False


class _Handler(http.server.BaseHTTPRequestHandler):
    server: IngressHTTPServer

    protocol_version = "HTTP/1.1"
    server_version = "addon-ui"
    sys_version = ""
    timeout = 30
    error_content_type = "text/plain; charset=utf-8"
    error_message_format = "%(code)d %(message)s\n"

    def version_string(self) -> str:
        return self.server_version

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        # Requests are not logged.
        return

    def log_error(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self._serve(send_body=True)

    def do_HEAD(self) -> None:
        self._serve(send_body=False)

    def _announces_body(self) -> bool:
        """Whether the request says it has a body (which is never read)."""
        if self.headers.get("Transfer-Encoding") is not None:
            return True
        return any(not _ZEROS.fullmatch(value.strip()) for value in self.headers.get_all("Content-Length", []))

    def _serve(self, send_body: bool) -> None:
        app = self.server.app
        path = urlsplit(self.path).path or "/"

        # GET and HEAD bodies are not read. Their bytes would be taken as the
        # next request on this connection, so it is closed after the response.
        if self._announces_body():
            self.close_connection = True

        if path == "/":
            ingress_path = ingress_base_path(self.headers.get("X-Ingress-Path"))
            self._respond(HTTPStatus.OK, app.render_index(ingress_path), CONTENT_TYPES[".html"], send_body)
            return

        if path in app.files:
            content, content_type = app.files[path]
            self._respond(HTTPStatus.OK, content, content_type, send_body)
            return

        callback = app.json_routes.get(path)
        if callback is not None:
            try:
                document = callback(self.headers)
            except Exception as error:
                log(f"Web UI: failed to build {path}: {type(error).__name__}: {error}")
                self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, json_bytes({"error": "internal error"}), CONTENT_TYPES[".json"], send_body)
                return
            self._respond(HTTPStatus.OK, json_bytes(document), CONTENT_TYPES[".json"], send_body)
            return

        self._respond(HTTPStatus.NOT_FOUND, b"404 Not Found\n", "text/plain; charset=utf-8", send_body)

    def _respond(self, status: HTTPStatus, body: bytes, content_type: str, send_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(body)


def serve(port: int, app: App) -> None:
    """Serves the app until the process is stopped."""
    server = IngressHTTPServer(port, app)
    log(f"Web UI: listening on port {port} for the Home Assistant ingress proxy.")
    try:
        server.serve_forever(poll_interval=1.0)
    finally:
        server.server_close()
