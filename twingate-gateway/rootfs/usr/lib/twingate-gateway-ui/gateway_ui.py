"""Web UI of the Twingate Gateway add-on, shown through Home Assistant ingress.

Serves a read-only status page and the JSON document behind it. The data
comes from:

- /run/twingate-gateway/status.json, written by /run.sh at startup: options
  without secret values (request header names only), the CA certificate
  (never its key), the Gateway version recorded when the image was built and
  the startup check of the Twingate network;
- the Gateway itself: GET /healthz on its TLS listener and its Prometheus
  metrics on 127.0.0.1:9090;
- the audit log relay (audit_relay.py), which follows the audit log and
  sends summaries of the newest entries without headers or query strings
  over a Unix socket, and a heartbeat every 5 seconds that also says whether
  s6-log keeps the copy of the audit log it reads. They are kept in memory
  only;
- a request to the Twingate signing-key URL that the Gateway fetches its
  keys from: every 15 minutes, or every 2 minutes while it fails;
- Docker Hub's list of the tags of twingate/gateway, read once a day, which
  says which Gateway release a rebuild of the add-on would install;
- the Home Assistant API proxy (supervisor_proxy.py), which sends its state
  and summaries of the newest proxied requests (Twingate user, request,
  decision; no query strings, webhook IDs masked, no tokens) over a second
  Unix socket, at least every 5 seconds. They are kept in memory only.

The process runs as an unprivileged user with an empty environment.
Python standard library only.
"""

from __future__ import annotations

import calendar
import contextlib
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ingress_server

WWW_DIR = "/usr/share/twingate-gateway-ui"
STATUS_FILE = "/run/twingate-gateway/status.json"
AUDIT_SOCKET = "/run/twingate-gateway-ui/audit.sock"
PROXY_SOCKET = "/run/twingate-gateway-proxy-ui/proxy.sock"
METRICS_URL = "http://127.0.0.1:9090/metrics"
GATEWAY_ADDRESS = ("127.0.0.1", 8443)
DEFAULT_PORT = 8100

LIVE_CACHE_SECONDS = 2.0
SIGNING_KEY_CHECK_INTERVAL = 900.0
SIGNING_KEY_RETRY_INTERVAL = 120.0
AUDIT_STALE_SECONDS = 15.0
MAX_RECORDS = 100
MAX_METRICS_BYTES = 8 * 1024 * 1024
MAX_JWKS_BYTES = 256 * 1024

FILES = {
    "/twingate-docs-theme.css": "twingate-docs-theme.css",
    "/app.js": "app.js",
    "/icon.png": "icon.png",
}

_NO_PROXY = urllib.request.ProxyHandler({})
_PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?")
_NETWORK = re.compile(r"[a-z0-9]{1,63}")
_HEADER_NAME = re.compile(r"[-!#$%&'*+.^_`|~0-9A-Za-z]{1,128}")
_IPV4 = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
_FINGERPRINT = re.compile(r"[0-9A-F]{2}(:[0-9A-F]{2}){31}")
_REQUEST_ID = re.compile(r"[0-9A-Za-z.-]{1,64}")
_METHOD = re.compile(r"[A-Z]{1,16}|\?")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_HOSTED_NETWORK = ipaddress.ip_network("172.30.32.0/23")
_PROXY_METHOD = re.compile(r"[A-Z]{1,16}|\?")
_PROXY_DECISIONS = ("read", "mcp", "write", "denied", "blocked", "invalid", "unauthenticated", "limited", "error", "closed")
_PROXY_KINDS = ("http", "ws", "ws-cmd")
_PROXY_COUNTS = ("requests", "allowed", "denied", "blocked", "unauthenticated", "invalid", "limited", "errors")
# The three toggles of the API proxy's access level.
_PROXY_ACCESS = ("read", "mcp", "write")

# The release check. The Dockerfile takes the Gateway from the image tag
# twingate/gateway:<major> on Docker Hub. Docker Hub's tag list (one page of
# up to 100 tags, newest first) shows which release that tag points to now.
DOCKER_HUB = "hub.docker.com"
GATEWAY_TAGS_PATH = "/v2/namespaces/twingate/repositories/gateway/tags"
GATEWAY_TAGS_URL = f"https://{DOCKER_HUB}{GATEWAY_TAGS_PATH}?page_size=100"
# Sent with the request instead of anything that names the add-on.
GENERIC_USER_AGENT = "Python-urllib"
UPDATE_FIRST_CHECK_DELAY = 15.0
UPDATE_CHECK_INTERVAL = 86400.0
# After 1, 2, and 3 or more failed checks in a row.
UPDATE_RETRY_INTERVALS = (300.0, 900.0, 3600.0)
# While the running version is not known yet (no network request then).
UPDATE_VERSION_WAIT = 30.0
UPDATE_LOG_INTERVAL = 86400.0
UPDATE_TIMEOUT = 10.0
UPDATE_DEADLINE = 30.0
MAX_TAG_PAGES = 3
MAX_TAG_PAGE_BYTES = 1024 * 1024
MAX_TAGS_PER_PAGE = 500
MAX_TAG_NAME = 128
MAX_IMAGES_PER_TAG = 32
_FINAL_VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------


def _text(value: object, limit: int = 256) -> str | None:
    if isinstance(value, str):
        return value[:limit]
    return None


def _match(pattern: re.Pattern, value: object) -> str | None:
    if isinstance(value, str) and pattern.fullmatch(value):
        return value
    return None


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _now() -> float:
    return round(time.time(), 3)


# ----------------------------------------------------------------------------
# Startup status written by /run.sh
# ----------------------------------------------------------------------------


def _iso_epoch(value: object) -> float | None:
    """Parses OpenSSL's ISO 8601 output, for example 2036-11-20 12:00:00Z."""
    if not isinstance(value, str):
        return None
    for layout in ("%Y-%m-%d %H:%M:%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return float(calendar.timegm(time.strptime(value, layout)))
        except ValueError:
            continue
    return None


def _clean_certificate(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    pem = raw.get("pem")
    if not isinstance(pem, str) or "PRIVATE" in pem or not _PEM_CERTIFICATE.fullmatch(pem):
        pem = None
    not_after = _text(raw.get("not_after"), 40)
    return {
        "source": raw.get("source") if raw.get("source") in ("addon", "custom") else None,
        "certificate_file": _text(raw.get("certificate_file"), 512),
        "subject": _text(raw.get("subject"), 512),
        "fingerprint_sha256": _match(_FINGERPRINT, raw.get("fingerprint_sha256")),
        "not_after": not_after,
        "not_after_epoch": _iso_epoch(not_after),
        "pem": pem,
    }


def load_startup_status() -> dict | None:
    """Reads the status file and keeps only the expected, non-secret fields."""
    try:
        with open(STATUS_FILE, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None

    names = raw.get("request_header_names")
    header_names = [name for name in names if _match(_HEADER_NAME, name)] if isinstance(names, list) else []
    ips = raw.get("certificate_ip_addresses")
    ip_addresses = [ip for ip in ips if _match(_IPV4, ip)] if isinstance(ips, list) else []

    check = raw.get("network_check") if isinstance(raw.get("network_check"), dict) else {}
    static = raw.get("static_certificate")
    static_certificate = None
    if isinstance(static, dict):
        not_after = _text(static.get("not_after"), 40)
        static_certificate = {"not_after": not_after, "not_after_epoch": _iso_epoch(not_after)}

    host_port = raw.get("host_port")
    if not _valid_port(host_port):
        host_port = None

    return {
        "addon_version": _text(raw.get("addon_version"), 64),
        "addon_slug": _match(_SLUG, raw.get("addon_slug")),
        # The version of the Gateway binary, recorded when the image was built.
        "gateway_version": _match(_VERSION, raw.get("gateway_version")),
        "started_at": _number(raw.get("started_at")),
        "network": _match(_NETWORK, raw.get("network")),
        "network_check": {
            "result": _text(check.get("result"), 32),
            "http_status": _text(check.get("http_status"), 8),
        },
        "log_level": raw.get("log_level") if raw.get("log_level") in ("debug", "info", "warn", "error") else None,
        "audit_log": raw.get("audit_log") if raw.get("audit_log") in ("addon_log", "file") else None,
        "audit_log_file": _text(raw.get("audit_log_file"), 512),
        "audit_stream": raw.get("audit_stream") if raw.get("audit_stream") in ("relay", "file", "none") else "none",
        "request_header_names": header_names,
        "certificate_ip_addresses": ip_addresses,
        "gateway_port": raw.get("gateway_port") if isinstance(raw.get("gateway_port"), int) else 8443,
        "host_port": host_port,
        "host_port_state": raw.get("host_port_state") if raw.get("host_port_state") in ("mapped", "not_mapped", "unknown") else "unknown",
        "ca": _clean_certificate(raw.get("ca")),
        "static_certificate": static_certificate,
        "proxy": _clean_proxy_settings(raw.get("proxy")),
    }


def _valid_port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536


def _clean_proxy_settings(raw: object) -> dict | None:
    """The proxy part of the status file: how to reach it and its access level."""
    if not isinstance(raw, dict):
        return None
    access = raw.get("access") if isinstance(raw.get("access"), dict) else {}
    return {
        "port": raw.get("port") if _valid_port(raw.get("port")) else 8124,
        "host_port": raw.get("host_port") if _valid_port(raw.get("host_port")) else None,
        "host_port_state": raw.get("host_port_state") if raw.get("host_port_state") in ("mapped", "not_mapped", "unknown") else "unknown",
        "hostname": _match(_HOSTNAME, raw.get("hostname")),
        "dns_name": _match(_HOSTNAME, raw.get("dns_name")),
        "token_header": _match(_HEADER_NAME, raw.get("token_header")),
        # As the proxy reads them: anything but true is off.
        "access": {key: access.get(key) is True for key in _PROXY_ACCESS},
    }


# ----------------------------------------------------------------------------
# Gateway health and metrics
# ----------------------------------------------------------------------------


def check_health() -> dict:
    """Sends GET /healthz to the Gateway's TLS listener, as the Docker health check does."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    try:
        with socket.create_connection(GATEWAY_ADDRESS, timeout=3.0) as raw, context.wrap_socket(raw) as tls:
            tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            data = b""
            while b"\r\n" not in data and len(data) < 1024:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError) as error:
        return {"ok": False, "error": type(error).__name__, "checked_at": _now()}
    elapsed = round((time.monotonic() - started) * 1000.0, 1)
    parts = data.split(b"\r\n", 1)[0].split(b" ")
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return {
        "ok": code == 200,
        "http_status": code,
        "latency_ms": elapsed,
        "error": None if code == 200 else "unexpected response",
        "checked_at": _now(),
    }


_SAMPLE = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\S+)?")
_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*,?')
_KEPT_PREFIXES = ("twingate_gateway_", "process_start_time_seconds", "process_resident_memory_bytes", "go_goroutines")


def _unescape(value: str) -> str:
    return value.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def parse_metrics(text: str) -> dict[str, list[tuple[dict, float]]]:
    """Parses the Prometheus text format, keeping the metrics this page shows."""
    samples: dict[str, list[tuple[dict, float]]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or not line.startswith(_KEPT_PREFIXES):
            continue
        match = _SAMPLE.fullmatch(line.strip())
        if not match:
            continue
        name, label_text, raw_value = match.groups()
        labels = {}
        if label_text:
            for label in _LABEL.finditer(label_text):
                labels[label.group(1)] = _unescape(label.group(2))
        try:
            value = float(raw_value)
        except ValueError:
            continue
        if not math.isfinite(value):
            continue
        samples.setdefault(name, []).append((labels, value))
    return samples


def _total(samples: dict, name: str, **match: str) -> float:
    return sum(value for labels, value in samples.get(name, []) if all(labels.get(k) == v for k, v in match.items()))


def _by_class(samples: dict, name: str) -> dict[str, int]:
    classes = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    for labels, value in samples.get(name, []):
        code = labels.get("code", "")
        key = f"{code[0]}xx" if len(code) == 3 and code[0] in "12345" else "other"
        classes[key] += int(value)
    return classes


def _histogram(samples: dict, base: str) -> dict:
    """Mean and the 50th and 95th percentiles of a histogram, over all labels.

    A percentile is given as the upper bound of the bucket it falls in ("at
    most"), or as the largest bound with "above" when it is in the last,
    open bucket. The Gateway's buckets are coarse (the first one for client
    requests ends at 100 ms), so interpolating inside a bucket would invent
    precision.
    """
    count = _total(samples, base + "_count")
    total = _total(samples, base + "_sum")
    buckets: dict[float, float] = {}
    for labels, value in samples.get(base + "_bucket", []):
        try:
            upper = float(labels.get("le", "nan"))
        except ValueError:
            continue
        if not math.isnan(upper):
            buckets[upper] = buckets.get(upper, 0.0) + value
    ordered = sorted(buckets.items())

    def quantile(q: float) -> dict | None:
        if count <= 0 or not ordered:
            return None
        rank = q * count
        lower = 0.0
        for upper, cumulative in ordered:
            if cumulative >= rank:
                if math.isinf(upper):
                    return {"ms": round(lower * 1000.0, 1), "above": True}
                return {"ms": round(upper * 1000.0, 1), "above": False}
            lower = upper
        return None

    return {
        "count": int(count),
        "mean_ms": round(total / count * 1000.0, 1) if count > 0 else None,
        "p50": quantile(0.5),
        "p95": quantile(0.95),
    }


def fetch_metrics() -> dict:
    """Reads the Gateway's metrics; any failure reports them as unavailable.

    Besides connection errors, http.client raises its own exceptions (for
    example BadStatusLine or LineTooLong) and ValueError for a malformed
    response; none of them may turn the status page into an error.
    """
    opener = urllib.request.build_opener(_NO_PROXY)
    try:
        with opener.open(METRICS_URL, timeout=3.0) as response:
            body = response.read(MAX_METRICS_BYTES + 1)
        if len(body) > MAX_METRICS_BYTES:
            return {"available": False, "error": "response too large"}
        return {"available": True, "samples": parse_metrics(body.decode("utf-8", "replace"))}
    except Exception as error:  # noqa: BLE001 - see above
        return {"available": False, "error": type(error).__name__}


def summarize_traffic(samples: dict) -> dict:
    succeeded = int(_total(samples, "twingate_gateway_client_authentication_total", code="200"))
    proxy_closed = int(_total(samples, "twingate_gateway_tcp_connections_total", connection_category="proxy"))
    return {
        "available": True,
        "active_connections": int(_total(samples, "twingate_gateway_active_tcp_connections")),
        "connections": {
            "proxy": proxy_closed,
            "health": int(_total(samples, "twingate_gateway_tcp_connections_total", connection_category="health")),
            "unknown": int(_total(samples, "twingate_gateway_tcp_connections_total", connection_category="unknown")),
        },
        "authentication": {
            "succeeded": succeeded,
            # Failed attempts are not counted by the Gateway. A failed
            # connection is counted as a closed proxy connection without a
            # successful authentication; open authenticated connections make
            # this a lower bound.
            "failed_at_least": max(0, proxy_closed - succeeded),
        },
        "http": {
            "total": int(_total(samples, "twingate_gateway_http_requests_total")),
            "active": int(_total(samples, "twingate_gateway_http_active_requests")),
            "by_class": _by_class(samples, "twingate_gateway_http_requests_total"),
            "latency": _histogram(samples, "twingate_gateway_http_request_duration_seconds"),
        },
        "upstream": {
            "total": int(_total(samples, "twingate_gateway_api_server_requests_total")),
            "active": int(_total(samples, "twingate_gateway_api_server_active_requests")),
            "by_class": _by_class(samples, "twingate_gateway_api_server_requests_total"),
            "latency": _histogram(samples, "twingate_gateway_api_server_request_duration_seconds"),
        },
        "process": {
            "resident_memory_bytes": int(_total(samples, "process_resident_memory_bytes")) or None,
            "goroutines": int(_total(samples, "go_goroutines")) or None,
        },
    }


# ----------------------------------------------------------------------------
# Audit summaries from the relay
# ----------------------------------------------------------------------------


def _clean_record(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    record_id = _match(_REQUEST_ID, raw.get("id"))
    when = _number(raw.get("t"))
    if record_id is None or when is None:
        return None
    status = raw.get("status")
    duration = _number(raw.get("ms"))
    record = {
        "id": record_id,
        "t": when,
        "user": _text(raw.get("user"), 200) or "",
        "method": _match(_METHOD, raw.get("method")) or "?",
        "path": _text(raw.get("path"), 600) or "",
        "q": raw.get("q") is True,
        "pt": raw.get("pt") is True,
        "status": status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else 0,
        "ms": duration if duration is not None and duration >= 0 else None,
        "err": raw.get("err") is True,
    }
    version = _match(_VERSION, raw.get("v"))
    if version:
        record["v"] = version
    return record


class AuditStore:
    """Receives summaries from the relay and keeps the newest ones in memory."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        # Arrival order, to sort entries logged in the same millisecond.
        self._order: dict[str, int] = {}
        self._next = 0
        self._relay: dict = {}
        self._last_message = None
        self._started = time.monotonic()
        self._socket_error: str | None = None

    def start(self) -> None:
        threading.Thread(target=self._run, name="audit", daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                self._receive()
            except OSError as error:
                with self._lock:
                    self._socket_error = type(error).__name__
                time.sleep(2.0)

    def _receive(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(AUDIT_SOCKET)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.bind(AUDIT_SOCKET)
            # The relay runs as another user, in the group that the socket
            # gets from its directory (see the twingate-gateway-ui service).
            os.chmod(AUDIT_SOCKET, 0o660)
            with self._lock:
                self._socket_error = None
            while True:
                data = sock.recv(256 * 1024)
                # A malformed message must not stop the receiver: the page
                # would then report the relay as not responding.
                with contextlib.suppress(Exception):
                    self._handle(data)

    def _handle(self, data: bytes) -> None:
        try:
            message = json.loads(data)
        except ValueError:
            return
        if not isinstance(message, dict) or message.get("type") != "snapshot":
            return
        records = message.get("records")
        relay = message.get("relay") if isinstance(message.get("relay"), dict) else {}
        cleaned = [record for record in map(_clean_record, records[: MAX_RECORDS * 2] if isinstance(records, list) else []) if record]
        with self._lock:
            for record in cleaned:
                if record["id"] not in self._order:
                    self._order[record["id"]] = self._next
                    self._next += 1
                self._records[record["id"]] = record
            if len(self._records) > MAX_RECORDS:
                newest = self._newest()[:MAX_RECORDS]
                self._records = {record["id"]: record for record in newest}
                self._order = {record["id"]: self._order[record["id"]] for record in newest}
            self._relay = {
                "started_at": _number(relay.get("started_at")),
                "entries": int(_number(relay.get("entries")) or 0),
                "last_entry_at": _number(relay.get("last_entry_at")),
                "source": relay.get("source") if relay.get("source") in ("add-on log", "file") else None,
                "file_state": _text(relay.get("file_state"), 80),
                # Whether s6-log keeps the copy of the audit log that the
                # relay reads with audit_log: addon_log (see audit_relay.py).
                "copy": relay.get("copy") if relay.get("copy") in ("ok", "not kept", "no space") else None,
            }
            self._last_message = time.monotonic()

    def _newest(self) -> list[dict]:
        return sorted(self._records.values(), key=lambda item: (item["t"], self._order[item["id"]]), reverse=True)

    def snapshot(self) -> dict:
        with self._lock:
            records = self._newest()
            now = time.monotonic()
            last = self._last_message
            age = None if last is None else round(now - last, 1)
            return {
                "records": records,
                "relay": dict(self._relay),
                "relay_seen": self._last_message is not None,
                "relay_age_seconds": age,
                # Seconds without a message from the relay, counted from the
                # start of the Web UI until the first one arrives.
                "relay_silent_seconds": round(now - (self._started if last is None else last), 1),
                "socket_error": self._socket_error,
            }


# ----------------------------------------------------------------------------
# The Home Assistant API proxy
# ----------------------------------------------------------------------------


def _clean_proxy_record(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    record_id = _match(_REQUEST_ID, raw.get("id"))
    when = _number(raw.get("t"))
    if record_id is None or when is None:
        return None
    status = raw.get("status")
    duration = _number(raw.get("ms"))
    method = raw.get("method")
    return {
        "id": record_id,
        "t": when,
        "kind": raw.get("kind") if raw.get("kind") in _PROXY_KINDS else "http",
        "user": _text(raw.get("user"), 200) or "",
        "method": method if method == "WS" or _match(_PROXY_METHOD, method) else "?",
        "path": _text(raw.get("path"), 600) or "",
        "q": raw.get("q") is True,
        "status": status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else 0,
        "ms": duration if duration is not None and duration >= 0 else None,
        "decision": raw.get("decision") if raw.get("decision") in _PROXY_DECISIONS else "error",
        "detail": _text(raw.get("detail"), 120),
    }


class ProxyStore:
    """Receives the API proxy's state and newest requests; keeps the last snapshot in memory."""

    def __init__(self, path: str = PROXY_SOCKET) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._state: dict = {}
        self._records: list[dict] = []
        self._last_message: float | None = None
        self._started = time.monotonic()
        self._socket_error: str | None = None

    def start(self) -> None:
        threading.Thread(target=self._run, name="proxy", daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                self._receive()
            except OSError as error:
                with self._lock:
                    self._socket_error = type(error).__name__
                time.sleep(2.0)

    def _receive(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.bind(self._path)
            # The proxy runs as api-proxy, in the group the socket gets from
            # its directory (see the twingate-gateway-ui service).
            os.chmod(self._path, 0o660)
            with self._lock:
                self._socket_error = None
            while True:
                data = sock.recv(256 * 1024)
                with contextlib.suppress(Exception):
                    self._handle(data)

    def _handle(self, data: bytes) -> None:
        try:
            message = json.loads(data)
        except (ValueError, RecursionError):
            return
        if not isinstance(message, dict) or message.get("type") != "snapshot":
            return
        proxy = message.get("proxy") if isinstance(message.get("proxy"), dict) else {}
        records = message.get("records")
        cleaned = [record for record in map(_clean_proxy_record, records[-MAX_RECORDS:] if isinstance(records, list) else []) if record]
        keys = proxy.get("keys") if isinstance(proxy.get("keys"), dict) else {}
        counts = proxy.get("counts") if isinstance(proxy.get("counts"), dict) else {}
        state = {
            "state": _text(proxy.get("state"), 40),
            "started_at": _number(proxy.get("started_at")),
            "token": proxy.get("token") is True,
            "websockets": int(_number(proxy.get("websockets")) or 0),
            "keys": {
                "ok": keys.get("ok") is True,
                "keys": int(_number(keys.get("keys")) or 0),
                "checked_at": _number(keys.get("checked_at")),
                "error": _text(keys.get("error"), 80),
            },
            "counts": {name: int(_number(counts.get(name)) or 0) for name in _PROXY_COUNTS},
        }
        with self._lock:
            self._state = state
            self._records = sorted(cleaned, key=lambda item: item["t"], reverse=True)
            self._last_message = time.monotonic()

    def snapshot(self) -> dict:
        with self._lock:
            now = time.monotonic()
            last = self._last_message
            return {
                **self._state,
                "records": list(self._records),
                "reporting": last is not None and now - last < AUDIT_STALE_SECONDS,
                "seen": last is not None,
                "silent_seconds": round(now - (self._started if last is None else last), 1),
                "socket_error": self._socket_error,
            }


# ----------------------------------------------------------------------------
# Signing keys
# ----------------------------------------------------------------------------


class _TwingateRedirects(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to HTTPS addresses on twingate.com, as the Gateway does."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        parts = urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not (host == "twingate.com" or host.endswith(".twingate.com")):
            raise urllib.error.HTTPError(newurl, code, "redirect outside twingate.com", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_signing_keys(network: str) -> dict:
    """Fetches the signing-key set the Gateway verifies Twingate tokens with.

    Any failure, including http.client's own exceptions such as BadStatusLine
    or LineTooLong, is reported as a failed check.
    """
    url = f"https://{network}.twingate.com/api/v1/jwk/ec"
    opener = urllib.request.build_opener(_NO_PROXY, _TwingateRedirects())
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "twingate-gateway-addon"})
    result = {"url": url, "checked_at": _now(), "ok": False, "http_status": None, "keys": None, "error": None}
    try:
        with opener.open(request, timeout=10.0) as response:
            result["http_status"] = response.status
            body = response.read(MAX_JWKS_BYTES + 1)
    except urllib.error.HTTPError as error:
        result["http_status"] = error.code
        result["error"] = f"HTTP {error.code}"
        return result
    except Exception as error:  # noqa: BLE001 - see above
        reason = getattr(error, "reason", None)
        result["error"] = type(reason).__name__ if isinstance(reason, BaseException) else type(error).__name__
        return result
    try:
        document = json.loads(body) if len(body) <= MAX_JWKS_BYTES else None
    except (ValueError, RecursionError):
        document = None
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list):
        result["error"] = "not a key set"
        return result
    result["keys"] = sum(1 for key in keys if isinstance(key, dict) and key.get("kty") == "EC")
    result["ok"] = result["keys"] > 0
    if not result["ok"]:
        result["error"] = "no EC keys"
    return result


class SigningKeyCheck:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._result: dict | None = None
        self._network: str | None = None
        self._wake = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, name="signing-keys", daemon=True).start()

    def note_network(self, network: str | None) -> None:
        with self._lock:
            if network != self._network:
                self._network = network
                self._result = None
                self._wake.set()

    def result(self) -> dict | None:
        with self._lock:
            return dict(self._result) if self._result else None

    def _run(self) -> None:
        self._wake.wait(5.0)
        while True:
            self._wake.clear()
            try:
                interval = self._check()
            except Exception:  # noqa: BLE001 - the check must keep running
                interval = SIGNING_KEY_RETRY_INTERVAL
            self._wake.wait(interval)

    def _check(self) -> float:
        """Checks the signing keys once; returns the seconds until the next check."""
        with self._lock:
            network = self._network
        if network is None:
            # Nobody has opened the page yet: read the network from the
            # status file, which exists once the Gateway has started.
            startup = load_startup_status()
            network = startup["network"] if startup else None
            self.note_network(network)
            self._wake.clear()
        if not network:
            return 10.0
        result = check_signing_keys(network)
        with self._lock:
            if network == self._network:
                self._result = result
        return SIGNING_KEY_CHECK_INTERVAL if result["ok"] else SIGNING_KEY_RETRY_INTERVAL


# ----------------------------------------------------------------------------
# Newer Gateway releases
# ----------------------------------------------------------------------------
#
# The add-on takes the Gateway from twingate/gateway:<major> when it is built,
# so a rebuild installs the release that this tag points to at that moment.
# Docker Hub lists each tag with the digests of its platform images. The tag
# <major> has the same platform images as the version tag of its release (for
# example 2.1.0); the digests of their multi-platform indexes differ, because
# Twingate pushes the two tags from separate builds. Final versions of the
# same major only: -dev, -debug and other suffixes, and other majors, are
# never taken. A new major version is adopted with an add-on release.


class _LookupError(Exception):
    """A release lookup that failed, with a short reason for the status page."""


def final_version(value: object) -> tuple[int, int, int] | None:
    """Parses a final release version such as 2.1.0; anything else is None."""
    if not isinstance(value, str):
        return None
    match = _FINAL_VERSION.fullmatch(value)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None


def is_docker_hub_url(url: object, path: str | None = None) -> bool:
    """Whether url is an HTTPS address on hub.docker.com (and has this path)."""
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and (parts.hostname or "").lower() == DOCKER_HUB
        and port in (None, 443)
        and parts.username is None
        and parts.password is None
        and (path is None or parts.path == path)
    )


class _DockerHubRedirects(urllib.request.HTTPRedirectHandler):
    """Follows at most 3 redirects, and only to HTTPS addresses on hub.docker.com."""

    # Different addresses, and the same address again.
    max_redirections = 3
    max_repeats = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        # urllib reads the whole body of a redirect before it follows it;
        # closing the response first leaves the body unread.
        fp.close()
        if not is_docker_hub_url(newurl):
            raise _LookupError("redirect outside hub.docker.com")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_capped(response, limit: int, deadline: float) -> bytes:
    """Reads a response body of at most limit bytes before the deadline."""
    length = response.headers.get("Content-Length")
    if length and length.strip().isdigit() and int(length) > limit:
        raise _LookupError("response too large")
    chunks = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise _LookupError("too slow")
        # read1 returns what one read of the socket brings, so that a body
        # that trickles in is stopped at the deadline.
        chunk = response.read1(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise _LookupError("response too large")
        chunks.append(chunk)


def _fetch_tag_page(url: str, deadline: float) -> object:
    opener = urllib.request.build_opener(_NO_PROXY, _DockerHubRedirects())
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": GENERIC_USER_AGENT})
    timeout = max(1.0, min(UPDATE_TIMEOUT, deadline - time.monotonic()))
    with opener.open(request, timeout=timeout) as response:
        body = _read_capped(response, MAX_TAG_PAGE_BYTES, deadline)
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise _LookupError("not JSON") from None


def parse_tag_page(document: object) -> tuple[dict[str, frozenset], str | None]:
    """Tag names with the digests of their platform images, and the next page."""
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        raise _LookupError("not a tag list")
    tags: dict[str, frozenset] = {}
    for item in results[:MAX_TAGS_PER_PAGE]:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name"), MAX_TAG_NAME + 1)
        images = item.get("images")
        if not name or len(name) > MAX_TAG_NAME or not isinstance(images, list):
            continue
        digests = frozenset(
            image["digest"] for image in images[:MAX_IMAGES_PER_TAG] if isinstance(image, dict) and _match(_IMAGE_DIGEST, image.get("digest"))
        )
        tags.setdefault(name, digests)
    next_page = document.get("next")
    return tags, next_page if isinstance(next_page, str) else None


def release_of_tag(tags: dict[str, frozenset], major: int) -> tuple[int, int, int] | None:
    """The final version tag <major>.y.z with the platform images of the tag <major>."""
    pointer = tags.get(str(major))
    if not pointer:
        return None
    versions = [version for name, digests in tags.items() if (version := final_version(name)) and version[0] == major and digests & pointer]
    return max(versions) if versions else None


def lookup_gateway_release(major: int) -> dict:
    """Finds the release that twingate/gateway:<major> points to on Docker Hub.

    Only the fixed URL above is requested (and up to two further pages of the
    same list), with a generic User-Agent and nothing that names the add-on or
    the Twingate network; no cookies are kept. Any failure, including
    http.client's own exceptions such as BadStatusLine or LineTooLong, is
    reported as a failed lookup.
    """
    result = {"checked_at": _now(), "ok": False, "latest": None, "error": None}
    deadline = time.monotonic() + UPDATE_DEADLINE
    tags: dict[str, frozenset] = {}
    url = GATEWAY_TAGS_URL
    try:
        for _ in range(MAX_TAG_PAGES):
            page, next_page = parse_tag_page(_fetch_tag_page(url, deadline))
            for name, digests in page.items():
                tags.setdefault(name, digests)
            release = release_of_tag(tags, major)
            if release:
                result["ok"] = True
                result["latest"] = ".".join(str(part) for part in release)
                return result
            if next_page is None:
                break
            if not is_docker_hub_url(next_page, GATEWAY_TAGS_PATH):
                raise _LookupError("next page outside hub.docker.com")
            url = next_page
        result["error"] = f"no release found for tag {major}" if str(major) in tags else f"tag {major} not found"
    except _LookupError as error:
        result["error"] = str(error)
    except urllib.error.HTTPError as error:
        result["error"] = f"HTTP {error.code}"
    except Exception as error:  # noqa: BLE001 - see above
        reason = getattr(error, "reason", None)
        if isinstance(reason, _LookupError):
            result["error"] = str(reason)
        else:
            result["error"] = type(reason).__name__ if isinstance(reason, BaseException) else type(error).__name__
    return result


def rebuild_hint(slug: str | None) -> str:
    """Where to rebuild the add-on, for the add-on log."""
    command = f"'ha apps rebuild {slug}'" if slug else "'ha apps rebuild <slug>'"
    return (
        "open Settings > Apps > Twingate Gateway in Home Assistant, open the menu (three dots) of the Controls card "
        f"on the Info tab and select Rebuild, or run {command}"
    )


class GatewayUpdateCheck:
    """Looks up once a day which Gateway release a rebuild would install.

    The first lookup is made shortly after the start, or as soon as the
    running Gateway version is known; after a failure it is tried again after
    5, 15 and then every 60 minutes. The result of the last successful lookup
    is kept until the next one succeeds. When it is newer than the running
    Gateway, the add-on log says so once, and again at most once a day while
    that remains so.
    """

    def __init__(self, audit: AuditStore | None, lookup=lookup_gateway_release, log=ingress_server.log, clock=time.monotonic) -> None:
        self._audit = audit
        self._lookup = lookup
        self._log = log
        self._clock = clock
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._major: int | None = None
        self._success: dict | None = None
        self._attempt: dict | None = None
        self._failures = 0
        self._logged: tuple[str, str] | None = None
        self._logged_at: float | None = None

    def start(self) -> None:
        threading.Thread(target=self._run, name="gateway-update", daemon=True).start()

    def note_running(self, version: str | None) -> None:
        """Takes the running Gateway version; a new major version starts over."""
        parsed = final_version(version)
        if parsed is None:
            return
        with self._lock:
            if parsed[0] != self._major:
                self._major = parsed[0]
                self._success = None
                self._attempt = None
                self._failures = 0
                self._wake.set()

    def status(self, running: str | None) -> dict:
        """The release check for api/status, compared with the running version."""
        with self._lock:
            major = self._major
            success = dict(self._success) if self._success else None
            attempt = dict(self._attempt) if self._attempt else None
        latest = success["latest"] if success else None
        current = final_version(running)
        newest = final_version(latest)
        available = None
        if current and newest and current[0] == newest[0]:
            available = newest > current
        return {
            "running": running,
            "latest": latest,
            "update_available": available,
            "checked_at": success["checked_at"] if success else None,
            "last_attempt_at": attempt["checked_at"] if attempt else None,
            "last_error": attempt["error"] if attempt and not attempt["ok"] else None,
            "image": f"twingate/gateway:{major}" if major is not None else None,
            "source": f"https://{DOCKER_HUB}{GATEWAY_TAGS_PATH}",
        }

    def _run(self) -> None:
        self._wake.wait(UPDATE_FIRST_CHECK_DELAY)
        while True:
            self._wake.clear()
            try:
                interval = self._check()
            except Exception:  # noqa: BLE001 - the check must keep running
                interval = UPDATE_RETRY_INTERVALS[-1]
            self._wake.wait(interval)

    def _running_version(self) -> tuple[str | None, dict | None]:
        startup = load_startup_status()
        records = self._audit.snapshot()["records"] if self._audit else []
        version, _ = running_gateway_version(startup, records)
        return version, startup

    def _check(self) -> float:
        """Looks up the release once; returns the seconds until the next lookup."""
        version, startup = self._running_version()
        self.note_running(version)
        self._wake.clear()
        running = final_version(version)
        if running is None:
            return UPDATE_VERSION_WAIT
        major = running[0]
        result = self._lookup(major)
        with self._lock:
            if major != self._major:
                return 0.0
            self._attempt = {"checked_at": result["checked_at"], "ok": result["ok"], "error": result["error"]}
            if result["ok"]:
                self._success = {"latest": result["latest"], "checked_at": result["checked_at"]}
                self._failures = 0
            else:
                self._failures += 1
            failures = self._failures
        if not result["ok"]:
            return UPDATE_RETRY_INTERVALS[min(failures, len(UPDATE_RETRY_INTERVALS)) - 1]
        self._log_if_newer(version, result["latest"], (startup or {}).get("addon_slug"))
        return UPDATE_CHECK_INTERVAL

    def _log_if_newer(self, running: str, latest: str, slug: str | None) -> None:
        newest = final_version(latest)
        current = final_version(running)
        if not newest or not current or newest[0] != current[0] or newest <= current:
            return
        now = self._clock()
        with self._lock:
            if self._logged == (running, latest) and self._logged_at is not None and now - self._logged_at < UPDATE_LOG_INTERVAL:
                return
            self._logged = (running, latest)
            self._logged_at = now
        self._log(f"Web UI: Twingate Gateway {latest} is available; this add-on runs Gateway {running}. To update, rebuild the add-on: {rebuild_hint(slug)}.")


# ----------------------------------------------------------------------------
# The status document
# ----------------------------------------------------------------------------


def running_gateway_version(startup: dict | None, records: list[dict]) -> tuple[str | None, str | None]:
    """The Gateway version and where it comes from ("audit" or "build").

    The audit log tells what the running Gateway reports; the version recorded
    when the image was built is used until the first request, or if no audit
    entry is available.
    """
    reported = next((record["v"] for record in records if record.get("v")), None)
    if reported:
        return reported, "audit"
    built = (startup or {}).get("gateway_version")
    if built:
        return built, "build"
    return None, None


def host_hint(headers) -> str | None:
    """The IPv4 address the browser used to open Home Assistant, if it used one.

    Home Assistant forwards the browser's Host header as X-Forwarded-Host. It
    is only a hint for the Gateway address with the host's LAN IP address,
    for a Connector elsewhere: Home Assistant may be reached through another
    address than the host's LAN address.
    """
    value = headers.get("X-Forwarded-Host") if headers is not None else None
    if not isinstance(value, str):
        return None
    host = value.split(",")[0].strip()
    if host.startswith("["):
        return None
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if not _IPV4.fullmatch(host):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.version != 4 or address.is_loopback or address.is_unspecified or address in _HOSTED_NETWORK:
        return None
    return str(address)


class StatusBuilder:
    def __init__(self, audit: AuditStore, signing_keys: SigningKeyCheck, updates: GatewayUpdateCheck, proxy: ProxyStore | None = None) -> None:
        self.audit = audit
        self.signing_keys = signing_keys
        self.updates = updates
        self.proxy = proxy
        self._lock = threading.Lock()
        self._live: dict | None = None
        self._live_at = 0.0
        self._auth_succeeded = 0
        self._auth_changed_at: float | None = None

    def _live_status(self) -> dict:
        with self._lock:
            now = time.monotonic()
            if self._live is not None and now - self._live_at < LIVE_CACHE_SECONDS:
                return self._live
            health = check_health()
            metrics = fetch_metrics()
            samples = metrics.get("samples") or {}
            traffic = summarize_traffic(samples) if metrics["available"] else {"available": False, "error": metrics.get("error")}
            if traffic.get("available"):
                succeeded = traffic["authentication"]["succeeded"]
                if succeeded > self._auth_succeeded:
                    self._auth_changed_at = _now()
                self._auth_succeeded = succeeded
            started = _total(samples, "process_start_time_seconds") or None
            self._live = {
                "health": health,
                "traffic": traffic,
                "gateway_started_at": started,
                "last_authentication_at": self._auth_changed_at,
            }
            self._live_at = now
            return self._live

    def _signing_key_status(self, startup: dict | None, live: dict) -> dict:
        check = self.signing_keys.result()
        traffic = live["traffic"]
        succeeded = traffic["authentication"]["succeeded"] if traffic.get("available") else 0
        startup_check = (startup or {}).get("network_check") or {}
        if succeeded > 0 or (check and check["ok"]):
            state = "ok"
        elif check and check["http_status"] == 404:
            state = "error"
        elif check:
            state = "warning"
        elif startup_check.get("result") == "found":
            state = "pending"
        else:
            state = "unknown"
        return {
            "state": state,
            "authentications_succeeded": succeeded,
            "last_authentication_at": live["last_authentication_at"],
            "startup_check": startup_check,
            "check": check,
        }

    def build(self, headers) -> dict:
        startup = load_startup_status()
        self.signing_keys.note_network(startup["network"] if startup else None)
        live = self._live_status()
        audit = self.audit.snapshot()

        gateway_version, version_source = running_gateway_version(startup, audit["records"])
        self.updates.note_running(gateway_version)
        started = live["gateway_started_at"] or (startup or {}).get("started_at")
        stream = (startup or {}).get("audit_stream", "none")
        # The relay sends a heartbeat every 5 seconds. While it is silent,
        # the request list may be out of date; the Gateway and the audit log
        # do not depend on the relay. A socket error on this side is reported
        # separately, as the relay is not the problem then.
        relay_silent = (
            stream in ("relay", "file")
            and audit["socket_error"] is None
            and audit["relay_silent_seconds"] >= AUDIT_STALE_SECONDS
        )
        return {
            "updated_at": _now(),
            "ready": startup is not None,
            "startup": startup,
            "host_hint": host_hint(headers),
            "health": live["health"],
            "gateway_version": gateway_version,
            "gateway_version_source": version_source,
            "gateway_update": self.updates.status(gateway_version),
            "gateway_started_at": started,
            "uptime_seconds": round(time.time() - started) if started else None,
            "signing_keys": self._signing_key_status(startup, live),
            "traffic": live["traffic"],
            "audit": {
                "stream": stream,
                "connected": audit["relay_age_seconds"] is not None and audit["relay_age_seconds"] < AUDIT_STALE_SECONDS,
                "relay_silent": relay_silent,
                "relay": audit["relay"],
                "relay_age_seconds": audit["relay_age_seconds"],
                "relay_silent_seconds": audit["relay_silent_seconds"],
                "socket_error": audit["socket_error"],
                "records": audit["records"],
            },
            # The API proxy's last report; "reporting" is false while it has
            # been silent for 15 seconds (it reports every 5).
            "proxy": self.proxy.snapshot() if self.proxy else None,
        }


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------


def build_app(builder: StatusBuilder | None) -> ingress_server.App:
    routes = {"/api/status": builder.build} if builder else {}
    return ingress_server.App(WWW_DIR, FILES, "index.html", routes)


def self_check() -> int:
    """Checks the page files and the parsers; used when the image is built."""
    build_app(None)
    sample = (
        "# TYPE twingate_gateway_http_requests_total counter\n"
        'twingate_gateway_http_requests_total{code="200",method="get",resource_type="web_app",type="http"} 3\n'
        'twingate_gateway_http_requests_total{code="502",method="get",resource_type="web_app",type="http"} 1\n'
        'twingate_gateway_http_request_duration_seconds_bucket{code="200",le="0.1"} 2\n'
        'twingate_gateway_http_request_duration_seconds_bucket{code="200",le="+Inf"} 4\n'
        'twingate_gateway_http_request_duration_seconds_sum{code="200"} 0.4\n'
        'twingate_gateway_http_request_duration_seconds_count{code="200"} 4\n'
        "twingate_gateway_active_tcp_connections +Inf\n"
    )
    traffic = summarize_traffic(parse_metrics(sample))
    if traffic["http"]["total"] != 4 or traffic["http"]["by_class"]["5xx"] != 1 or traffic["http"]["latency"]["mean_ms"] != 100.0:
        print(f"self check failed: {traffic}", file=sys.stderr)
        return 1
    if host_hint({"X-Forwarded-Host": "192.168.1.10:8123"}) != "192.168.1.10" or host_hint({"X-Forwarded-Host": "ha.example"}):
        print("self check failed: host hint", file=sys.stderr)
        return 1
    # Docker Hub's tag list as it looked for Gateway 2.1.0 (digests shortened
    # to one repeated character): the tag 2 shares its platform images with
    # 2.1.0; the -dev, -debug and other majors' tags must not count.
    amd64, arm64, old, dev = ("sha256:" + c * 64 for c in "abcd")
    page = {
        "next": None,
        "results": [
            {"name": "latest", "images": [{"digest": amd64}, {"digest": arm64}]},
            {"name": "2", "images": [{"digest": amd64}, {"digest": arm64}]},
            {"name": "2.1.0", "images": [{"digest": amd64}, {"digest": arm64}]},
            {"name": "2.2.0-dev-68c4d81", "images": [{"digest": dev}]},
            {"name": "2.0.1", "images": [{"digest": old}]},
            {"name": "3.0.0", "images": [{"digest": "sha256:" + "e" * 64}]},
            {"name": "<b>", "images": "x"},
        ],
    }
    tags, _ = parse_tag_page(page)
    if release_of_tag(tags, 2) != (2, 1, 0) or release_of_tag(tags, 3) is not None or final_version("2.1.0-dev") or final_version("02.1.0"):
        print("self check failed: release lookup", file=sys.stderr)
        return 1
    if is_docker_hub_url("https://hub.docker.com.example/v2/") or not is_docker_hub_url(GATEWAY_TAGS_URL, GATEWAY_TAGS_PATH):
        print("self check failed: Docker Hub address", file=sys.stderr)
        return 1
    proxy = ProxyStore("/nonexistent/proxy.sock")
    proxy._handle(  # noqa: SLF001 - the receiver without its socket
        json.dumps(
            {
                "type": "snapshot",
                "proxy": {"state": "running", "keys": {"ok": True, "keys": 1}, "counts": {"requests": 2, "denied": 1}},
                "records": [
                    {"id": "p1-1", "t": 1.0, "user": "<b>x</b>", "method": "GET", "path": "/api/states", "status": 200, "decision": "write"},
                    {"id": "not an id!", "t": 2.0},
                    {"id": "p1-2", "t": 3.0, "grant": "root", "method": "<x>", "decision": "allowed-everything"},
                ],
            }
        ).encode()
    )
    snapshot = proxy.snapshot()
    settings = _clean_proxy_settings({"port": 8124, "host_port": True, "hostname": "Bad Name", "access": {"read": True, "mcp": "true", "full": True}})
    if (
        snapshot["state"] != "running"
        or [record["id"] for record in snapshot["records"]] != ["p1-2", "p1-1"]
        or "grant" in snapshot["records"][0]
        or snapshot["records"][0]["method"] != "?"
        or snapshot["records"][0]["decision"] != "error"
        or snapshot["records"][1]["decision"] != "write"
        or not snapshot["reporting"]
        or settings["host_port"] is not None
        or settings["hostname"] is not None
        or settings["access"] != {"read": True, "mcp": False, "write": False}
    ):
        print(f"self check failed: proxy summaries {snapshot} {settings}", file=sys.stderr)
        return 1
    print("gateway_ui: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return self_check()
    port = DEFAULT_PORT
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    audit = AuditStore()
    audit.start()
    signing_keys = SigningKeyCheck()
    signing_keys.start()
    updates = GatewayUpdateCheck(audit)
    updates.start()
    proxy = ProxyStore()
    proxy.start()
    ingress_server.serve(port, build_app(StatusBuilder(audit, signing_keys, updates, proxy)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
