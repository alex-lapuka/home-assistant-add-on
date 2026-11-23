"""Home Assistant API proxy of the Twingate Gateway add-on.

Runs as the s6 service twingate-gateway-proxy, as its own unprivileged user,
and listens on port 8124. The flow is:

    client -> Twingate -> Gateway (verifies the Gateway Access Token, GAT)
           -> this proxy -> Supervisor -> Home Assistant

The Gateway adds the connection's GAT to every request it forwards
(X-Twingate-Gateway-Token: {{jwt}}). The proxy verifies that token on every
request and WebSocket upgrade (gat.py), takes the caller's Twingate username
and groups from it, applies the access rules of the add-on options
(access_rules.py) and passes allowed requests to the Supervisor's Home
Assistant API with the add-on's own Supervisor token:

- REST and MCP: http://supervisor/core/api/... (GET, HEAD, POST and DELETE;
  the Supervisor routes no other methods);
- WebSocket: ws://supervisor/core/websocket. The proxy answers the client's
  authentication phase itself (any non-empty access_token is accepted; the
  caller was identified by its GAT), authenticates to the Supervisor with the
  Supervisor token and then relays messages, applying the rules to each
  command.

Only the request headers the Supervisor passes on are forwarded (Content-Type,
Accept, Last-Event-ID, Mcp-Session-Id, MCP-Protocol-Version,
X-Speech-Content): the GAT header, Authorization, cookies and forwarding
headers sent by the client never reach the Supervisor. A request without a
valid GAT for this proxy gets 401 and nothing else.

Every request and WebSocket command is logged with the Twingate username to
the add-on log (no query strings, webhook IDs masked, no tokens), because
Home Assistant sees one user for all callers. Summaries of the newest ones go
to the Web UI over a Unix datagram socket; sending never blocks.

The Supervisor token arrives on a file descriptor (--token-fd) and is kept in
memory only. It is never logged and never sent anywhere but to the
Supervisor.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import os
import socket
import sys
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import access_rules
import gat

CONFIG_FILE = "/run/twingate-gateway-proxy/config.json"
UI_SOCKET = "/run/twingate-gateway-proxy-ui/proxy.sock"
SUPERVISOR = "http://supervisor"
SUPERVISOR_WEBSOCKET = "ws://supervisor/core/websocket"
GAT_HEADER = "X-Twingate-Gateway-Token"
DEFAULT_PORT = 8124

# The request headers the Supervisor passes on to Home Assistant
# (supervisor/api/proxy.py, FORWARD_HEADERS), and Content-Type.
FORWARD_REQUEST_HEADERS = ("Content-Type", "Accept", "Last-Event-ID", "Mcp-Session-Id", "MCP-Protocol-Version", "X-Speech-Content")
# The response headers the Supervisor passes back.
FORWARD_RESPONSE_HEADERS = ("Content-Type", "Cache-Control", "Mcp-Session-Id", "X-Accel-Buffering")
PROXIED_METHODS = ("GET", "HEAD", "POST", "DELETE")

MAX_BODY_BYTES = 16 * 1024 * 1024  # the Supervisor's MAX_CLIENT_SIZE
MAX_CLIENT_WS_MESSAGE = 4 * 1024 * 1024  # aiohttp's default, as in Home Assistant and the Supervisor
MAX_UPSTREAM_WS_MESSAGE = 64 * 1024 * 1024  # the Supervisor's MAX_MESSAGE_SIZE_FROM_CORE
MAX_HEADER_FIELD = 64 * 1024
# Open WebSocket connections and REST/MCP requests in progress: in all, and
# per Twingate user, so that one caller cannot take every slot. Beyond a
# user's share the answer is 429; beyond the total, 503.
MAX_WEBSOCKETS = 64
MAX_USER_WEBSOCKETS = 16
MAX_REQUESTS = 64
MAX_USER_REQUESTS = 16
AUTH_TIMEOUT = 10.0
UPSTREAM_CONNECT_TIMEOUT = 10.0
# Waiting for a free connection to the Supervisor and connecting, together.
UPSTREAM_POOL_TIMEOUT = 15.0
CONFIG_RETRY_MAX = 30.0
UNAUTHENTICATED_LOG_INTERVAL = 60.0
MAX_RECORDS = 100
MAX_DATAGRAM_BYTES = 120_000
SEND_INTERVAL = 0.5
HEARTBEAT_INTERVAL = 5.0
KEY_CHECK_INTERVAL = 30.0

UNAUTHORIZED_BODY = b"401: Unauthorized"


# Callers whose groups were logged; cleared when it reaches this size.
CALLERS_SEEN_MAX = 1000


def log(message: str) -> None:
    """One line to standard error, which ends up in the add-on log."""
    with contextlib.suppress(OSError, ValueError):
        sys.stderr.write(f"Proxy: {message}\n")
        sys.stderr.flush()


def _printable(value: str, limit: int = 200) -> str:
    """A value from a client or a token, safe for one log line."""
    return "".join(char if char.isprintable() else "?" for char in value[:limit])


class _LibraryLogHandler(logging.Handler):
    """Logs aiohttp's and asyncio's errors as one line without their message.

    aiohttp logs a request it cannot parse with its traceback and the start
    of the offending header value, which could be part of a token; such
    requests come from clients and are dropped. Any other error is logged by
    its type only, at most once a minute.
    """

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self._last = -UNAUTHENTICATED_LOG_INTERVAL

    def emit(self, record: logging.LogRecord) -> None:
        error = record.exc_info[1] if record.exc_info else None
        if error is not None and type(error).__module__.startswith("aiohttp.http"):
            return
        now = time.monotonic()
        if now - self._last < UNAUTHENTICATED_LOG_INTERVAL:
            return
        self._last = now
        log(f"internal error in {record.name} ({type(error).__name__ if error else record.levelname}); the connection was dropped. Logged at most once a minute.")


def quiet_library_logs() -> None:
    handler = _LibraryLogHandler()
    for name in ("aiohttp", "asyncio"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.WARNING)


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------


class Config:
    """The proxy's part of the add-on options, written by /run.sh."""

    def __init__(self, raw: dict) -> None:
        network = raw.get("network")
        if not isinstance(network, str) or not network.isalnum() or not network.islower() or not 0 < len(network) <= 63:
            raise ValueError("network")
        self.network = network
        port = raw.get("port")
        self.port = port if type(port) is int and 0 < port < 65536 else DEFAULT_PORT
        host_port = raw.get("host_port")
        self.host_port = host_port if type(host_port) is int and 0 < host_port < 65536 else None
        hostnames = raw.get("hostnames")
        self.hostnames = [name for name in hostnames if isinstance(name, str) and name] if isinstance(hostnames, list) else []
        groups = raw.get("groups") if isinstance(raw.get("groups"), dict) else {}

        def group_list(key: str) -> list[str]:
            value = groups.get(key)
            return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []

        self.rules = access_rules.Rules(group_list("read"), group_list("mcp"), group_list("full"))


def read_config(path: str) -> Config:
    with open(path, encoding="utf-8") as handle:
        return Config(json.load(handle))


async def wait_for_config(path: str) -> Config:
    """Waits until /run.sh has written the configuration, then reads it."""
    announced = False
    last_error = None
    delay = 1.0
    while True:
        try:
            return await asyncio.to_thread(read_config, path)
        except FileNotFoundError:
            if not announced:
                log("waiting for the add-on options.")
                announced = True
            delay = 1.0
        except (OSError, ValueError) as error:
            # Logged when the error changes; retried less and less often.
            if type(error).__name__ != last_error:
                last_error = type(error).__name__
                log(f"cannot read its configuration ({last_error}); retrying, at most every {CONFIG_RETRY_MAX:.0f} s.")
            delay = min(delay * 2.0, CONFIG_RETRY_MAX)
        await asyncio.sleep(delay)


def read_token(fd: int | None) -> str:
    """Reads the Supervisor token from a file descriptor and closes it."""
    if fd is None:
        return ""
    data = b""
    with contextlib.suppress(OSError):
        while len(data) < 4096:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data += chunk
    with contextlib.suppress(OSError):
        os.close(fd)
    token = data.decode("ascii", "replace").strip()
    return token if token.isprintable() and " " not in token else ""


# ----------------------------------------------------------------------------
# Request log and Web UI feed
# ----------------------------------------------------------------------------


class Journal:
    """The request log: a line in the add-on log, and summaries for the Web UI."""

    def __init__(self) -> None:
        self.records: deque[dict] = deque(maxlen=MAX_RECORDS)
        self.counts = {"requests": 0, "allowed": 0, "denied": 0, "blocked": 0, "unauthenticated": 0, "invalid": 0, "limited": 0, "errors": 0}
        self.websockets = 0
        self.changed = False
        self._ids = itertools.count(1)
        self._started = round(time.time(), 3)
        self._unauthenticated_logged: dict[str, float] = {}
        self.state = "starting"
        self.keys: dict = {}
        self.token_present = False
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        with contextlib.suppress(OSError):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        self.unsent = 0

    def add(self, **record) -> None:
        # Values from clients and tokens (user names, decoded paths, command
        # types) without control, format or line-separator characters.
        for key in ("user", "path", "detail", "method"):
            if isinstance(record.get(key), str):
                record[key] = _printable(record[key], 600)
        record["id"] = f"p{self._started:.0f}-{next(self._ids)}"
        record.setdefault("t", round(time.time(), 3))
        self.records.append(record)
        self.changed = True

    def count(self, decision: str) -> None:
        self.counts["requests"] += 1
        key = decision if decision in self.counts else "allowed" if decision in ("read", "mcp", "full") else "errors"
        self.counts[key] += 1
        self.changed = True

    def unauthenticated(self, remote: str, reason: str, method: str, path: str) -> None:
        """Logs a request without a valid token, at most once a minute per address."""
        # The reason can quote a value from the token (an algorithm name).
        reason = _printable(reason, 160)
        self.counts["requests"] += 1
        self.counts["unauthenticated"] += 1
        self.changed = True
        now = time.monotonic()
        last = self._unauthenticated_logged.get(remote)
        if last is not None and now - last < UNAUTHENTICATED_LOG_INTERVAL:
            return
        if len(self._unauthenticated_logged) > 256:
            self._unauthenticated_logged.clear()
        self._unauthenticated_logged[remote] = now
        log(f"refused a request from {remote} without a valid Twingate token for this proxy: {reason}. Answered 401. (Logged at most once a minute per address.)")
        self.add(kind="http", user="", grant="", method=method, path=path, q=False, status=401, ms=None, decision="unauthenticated", detail=reason[:120])

    def snapshot(self) -> bytes:
        proxy = {
            "started_at": self._started,
            "state": self.state,
            "keys": self.keys,
            "token": self.token_present,
            "counts": dict(self.counts),
            "websockets": self.websockets,
        }
        records = list(self.records)
        while True:
            payload = json.dumps({"type": "snapshot", "proxy": proxy, "records": records}, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            if len(payload) <= MAX_DATAGRAM_BYTES or not records:
                return payload
            records = records[len(records) // 2 :]

    async def feed(self) -> None:
        """Sends the snapshot to the Web UI when it changed, and every 5 seconds."""
        last_heartbeat = 0.0
        while True:
            await asyncio.sleep(SEND_INTERVAL)
            now = time.monotonic()
            if not self.changed and now - last_heartbeat < HEARTBEAT_INTERVAL:
                continue
            self.changed = False
            last_heartbeat = now
            try:
                self.sock.sendto(self.snapshot(), UI_SOCKET)
            except OSError:
                # The Web UI is not running, not reading, or restarting.
                self.unsent += 1


# ----------------------------------------------------------------------------
# The proxy
# ----------------------------------------------------------------------------


class Proxy:
    def __init__(self, config: Config, token: str, journal: Journal, verifier: gat.Verifier) -> None:
        import aiohttp  # noqa: PLC0415 - imported when serving only
        from aiohttp import web  # noqa: F401, PLC0415 - aiohttp.web is used below

        self.aiohttp = aiohttp
        self.config = config
        self.rules = config.rules
        self.token = token
        self.journal = journal
        self._callers_seen: set[tuple[str, tuple[str, ...]]] = set()
        self.verifier = verifier
        self.session: aiohttp.ClientSession | None = None
        self.ws_session: aiohttp.ClientSession | None = None
        self.websockets_open = 0
        self.requests_open = 0
        self.user_websockets: dict[str, int] = {}
        self.user_requests: dict[str, int] = {}

    async def start_session(self) -> None:
        aiohttp = self.aiohttp
        # REST and MCP: at most MAX_REQUESTS connections. A request that
        # cannot get one, or cannot connect, within UPSTREAM_POOL_TIMEOUT
        # fails instead of waiting. No read timeout: event streams stay open.
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, connect=UPSTREAM_POOL_TIMEOUT, sock_connect=UPSTREAM_CONNECT_TIMEOUT, sock_read=None),
            connector=aiohttp.TCPConnector(limit=MAX_REQUESTS, enable_cleanup_closed=True),
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
            auto_decompress=True,
        )
        # WebSockets have their own connections, so that open WebSockets
        # never hold up REST and MCP requests; MAX_WEBSOCKETS limits them.
        self.ws_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, connect=UPSTREAM_POOL_TIMEOUT, sock_connect=UPSTREAM_CONNECT_TIMEOUT, sock_read=None),
            connector=aiohttp.TCPConnector(limit=0, enable_cleanup_closed=True),
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
        )

    def _take(self, kind: str, user: str) -> int:
        """Takes a slot for a request or WebSocket: 0, or the status to answer (429, 503)."""
        per_user, total, limit_user, limit_total = (
            (self.user_websockets, self.websockets_open, MAX_USER_WEBSOCKETS, MAX_WEBSOCKETS)
            if kind == "ws"
            else (self.user_requests, self.requests_open, MAX_USER_REQUESTS, MAX_REQUESTS)
        )
        if per_user.get(user, 0) >= limit_user:
            return 429
        if total >= limit_total:
            return 503
        per_user[user] = per_user.get(user, 0) + 1
        if kind == "ws":
            self.websockets_open += 1
        else:
            self.requests_open += 1
        return 0

    def _release(self, kind: str, user: str) -> None:
        per_user = self.user_websockets if kind == "ws" else self.user_requests
        left = per_user.get(user, 1) - 1
        if left > 0:
            per_user[user] = left
        else:
            per_user.pop(user, None)
        if kind == "ws":
            self.websockets_open -= 1
        else:
            self.requests_open -= 1

    # -- identity ------------------------------------------------------------

    async def identify(self, request) -> tuple[gat.Identity | None, str]:
        values = request.headers.getall(GAT_HEADER, [])
        if not values:
            return None, "no token"
        if len(values) > 1:
            return None, "more than one token header"
        token = values[0].strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        try:
            return self.verifier.verify(token), ""
        except gat.TokenError as error:
            reason = str(error)
            if reason not in ("unknown signing key", "signing keys not available") and not self.verifier.needs_keys(token):
                return None, reason
        # A key ID the proxy does not know yet, or keys that could not be
        # read so far: read the key set again (at most once a minute), then
        # try once more; another task may just have read it.
        if await asyncio.to_thread(self.verifier.keys.refresh, True):
            self.journal.keys = dict(self.verifier.keys.state)
            self.journal.changed = True
        try:
            return self.verifier.verify(token), ""
        except gat.TokenError as retry:
            return None, str(retry)

    def _note_caller(self, identity: gat.Identity, label: str) -> None:
        """Log a caller's Twingate groups once per caller and set of groups.

        The groups decide the grants, and nothing else shows which groups a
        token carries, for example the token of a service account.
        """
        key = (identity.username, identity.groups)
        if key in self._callers_seen:
            return
        if len(self._callers_seen) >= CALLERS_SEEN_MAX:
            self._callers_seen.clear()
        self._callers_seen.add(key)
        groups = ", ".join(_printable(group, 100) for group in identity.groups[:50]) or "(none)"
        more = f" and {len(identity.groups) - 50} more" if len(identity.groups) > 50 else ""
        log(f"caller {_printable(identity.username)} (Twingate user ID {_printable(identity.user_id, 100)}): Twingate groups in its token: {groups}{more}; grants here: {label}.")

    # -- entry point ---------------------------------------------------------

    async def handle(self, request):
        web = self.aiohttp.web
        raw_path = request.url.raw_path
        has_query = bool(request.url.raw_query_string)
        remote = request.remote or "?"
        identity, reason = await self.identify(request)
        shown_path = self._shown_path(raw_path)
        if identity is None:
            self.journal.unauthenticated(remote, reason, request.method if request.method.isalpha() else "?", shown_path)
            return web.Response(status=401, body=UNAUTHORIZED_BODY, content_type="text/plain")

        grants = self.rules.grants(identity.groups)
        label = access_rules.grant_label(grants)
        self._note_caller(identity, label)
        started = time.monotonic()
        if access_rules.cross_site_browser_request(request.headers.get("Origin"), request.headers.get("Sec-Fetch-Site"), request.headers.get("Host")):
            self._record(identity, label, request.method, shown_path, has_query, 403, started, "blocked", "from a web page of another site")
            return self._json(403, "Forbidden: the Twingate Gateway add-on refuses requests from web pages of other sites.")
        path = access_rules.canonical_path(raw_path)
        if path is None:
            return self._finish(identity, label, request.method, shown_path, has_query, 400, started, "invalid", self._json(400, "Bad Request: unclear request path."))
        shown_path = _printable(access_rules.mask_path(path), 300)
        if not path.startswith("/api/"):
            response = self._json(404, "Not Found: this proxy serves the Home Assistant API (/api/...) only.")
            return self._finish(identity, label, request.method, shown_path, has_query, 404, started, "invalid", response)

        if path == access_rules.WEBSOCKET_PATH and request.headers.get("Upgrade", "").lower() == "websocket":
            return await self.websocket(request, identity, grants, label)

        allowed, why = access_rules.decide_rest(request.method, path, grants)
        if not allowed:
            message = (
                "Forbidden: blocked by the Twingate Gateway add-on for every caller."
                if why == "blocked"
                else "Forbidden: your Twingate groups do not have a grant in the Twingate Gateway add-on that allows this request."
            )
            return self._finish(identity, label, request.method, shown_path, has_query, 403, started, why, self._json(403, message))
        if request.method not in PROXIED_METHODS:
            response = self._json(405, "Method Not Allowed")
            response.headers["Allow"] = ", ".join(PROXIED_METHODS)
            return self._finish(identity, label, request.method, shown_path, has_query, 405, started, "invalid", response)
        refused = self._take("http", identity.username)
        if refused:
            message = "Too Many Requests: too many requests of this Twingate user in progress." if refused == 429 else "Service Unavailable: too many requests in progress."
            return self._finish(identity, label, request.method, shown_path, has_query, refused, started, "limited", self._json(refused, message))
        try:
            return await self.forward(request, identity, label, why, path, shown_path, has_query, started)
        finally:
            self._release("http", identity.username)

    def _shown_path(self, raw_path: str) -> str:
        """The path for logs before it was checked: decoded if possible, masked, shortened."""
        path = access_rules.canonical_path(raw_path) or raw_path
        return _printable(access_rules.mask_path(path), 300)

    def _json(self, status: int, message: str):
        return self.aiohttp.web.json_response({"message": message}, status=status)

    def _finish(self, identity, label, method, shown_path, has_query, status, started, decision, response):
        self._record(identity, label, method, shown_path, has_query, status, started, decision)
        return response

    def _record(self, identity, label, method, shown_path, has_query, status, started, decision, detail=None):
        elapsed = round((time.monotonic() - started) * 1000.0, 1)
        self.journal.count(decision)
        outcome = {"blocked": "blocked for every caller", "denied": "denied", "invalid": "refused", "error": "failed", "limited": "limited"}.get(decision, "")
        suffix = f" ({outcome})" if outcome else ""
        query = "?…" if has_query else ""
        log(f"{_printable(identity.username)} [{label}] {_printable(method, 16)} {shown_path}{query} -> {status}{suffix} in {elapsed:.0f} ms{f'; {detail}' if detail else ''}")
        self.journal.add(
            kind="http",
            user=identity.username[:200],
            grant=label,
            method=method if method.isalpha() and len(method) <= 16 else "?",
            path=shown_path[:600],
            q=has_query,
            status=status,
            ms=elapsed,
            decision=decision,
        )

    # -- REST and MCP --------------------------------------------------------

    async def forward(self, request, identity, label, why, path, shown_path, has_query, started):
        from yarl import URL  # noqa: PLC0415

        aiohttp = self.aiohttp
        web = aiohttp.web
        if not self.token:
            return self._finish(identity, label, request.method, shown_path, has_query, 503, started, "error", self._json(503, "Service Unavailable: the add-on has no Supervisor token."))
        body = None
        if request.method in ("POST", "DELETE") and request.can_read_body:
            try:
                body = await request.read()
            except web.HTTPRequestEntityTooLarge:
                return self._finish(identity, label, request.method, shown_path, has_query, 413, started, "invalid", self._json(413, "Request Entity Too Large"))
        headers = {name: request.headers[name] for name in FORWARD_REQUEST_HEADERS if name in request.headers}
        if access_rules.is_mcp_path(path) and (request.method == "POST" or body):
            # Never passed on without being read: UTF-8 JSON only, with a
            # Content-Type that makes Home Assistant read it the same way.
            if not access_rules.mcp_content_type_ok(request.headers.get("Content-Type")):
                response = self._json(400, "Bad Request: MCP requests must be application/json in UTF-8.")
                return self._finish(identity, label, request.method, shown_path, has_query, 400, started, "invalid", response)
            outcome, message_id = access_rules.inspect_mcp_body(body or b"")
            if outcome == "invalid":
                response = self._json(400, "Bad Request: the body must be a JSON-RPC message in UTF-8.")
                return self._finish(identity, label, request.method, shown_path, has_query, 400, started, "invalid", response)
            if outcome == "blocked":
                self._record(identity, label, request.method, shown_path, has_query, 200, started, "blocked", "MCP tool call refused")
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "error": {
                            "code": -32600,
                            "message": "Blocked by the Twingate Gateway add-on: this tool reaches the Supervisor, or calls an action of the hassio or backup domain.",
                        },
                    }
                )
            headers["Content-Type"] = "application/json"
        headers["Authorization"] = f"Bearer {self.token}"
        target = SUPERVISOR + "/core" + request.url.raw_path
        if request.url.raw_query_string:
            target += "?" + request.url.raw_query_string
        # encoded=True sends the path as received, byte for byte, as the
        # Supervisor does; it was checked by canonical_path().
        url = URL(target, encoded=True)
        expires_in = max(0.0, identity.expires_at - time.time())
        response = None
        deadline = asyncio.timeout(expires_in)
        try:
            async with deadline, self.session.request(request.method, url, headers=headers, data=body, allow_redirects=False) as upstream:
                if upstream.status == 401:
                    # The Supervisor refused the add-on's token; Home
                    # Assistant itself never answers it 401.
                    response = self._json(502, "Bad Gateway: the Supervisor refused the add-on's access to Home Assistant.")
                    return self._finish(identity, label, request.method, shown_path, has_query, 502, started, "error", response)
                response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
                for name in FORWARD_RESPONSE_HEADERS:
                    if name in upstream.headers:
                        response.headers[name] = upstream.headers[name]
                length = upstream.headers.get("Content-Length")
                if length and length.isdigit() and "Content-Encoding" not in upstream.headers:
                    response.content_length = int(length)
                await response.prepare(request)
                if request.method != "HEAD":
                    async for chunk in upstream.content.iter_any():
                        await response.write(chunk)
                await response.write_eof()
        except aiohttp.ServerTimeoutError as error:
            # aiohttp's own timeouts (they are TimeoutErrors too): no free
            # connection to the Supervisor in time, or it did not connect.
            if response is not None and response.prepared:
                response.force_close()
                self._record(identity, label, request.method, shown_path, has_query, response.status, started, why, f"stream ended: {type(error).__name__}")
                return response
            status = 503 if isinstance(error, aiohttp.ConnectionTimeoutError) else 504
            response = self._json(status, "Service Unavailable: the Supervisor did not answer in time." if status == 503 else "Gateway Timeout")
            return self._finish(identity, label, request.method, shown_path, has_query, status, started, "error", response)
        except TimeoutError:
            if not deadline.expired():
                return self._finish(identity, label, request.method, shown_path, has_query, 504, started, "error", self._json(504, "Gateway Timeout"))
            # The token expired while the response was streaming; the
            # Gateway closes the client connection at that moment too.
            if response is not None and response.prepared:
                response.force_close()
                self._record(identity, label, request.method, shown_path, has_query, response.status, started, why, "closed when the Twingate token expired")
                return response
            return self._finish(identity, label, request.method, shown_path, has_query, 401, started, "error", web.Response(status=401, body=UNAUTHORIZED_BODY, content_type="text/plain"))
        except (aiohttp.ClientError, OSError) as error:
            if response is not None and response.prepared:
                response.force_close()
                self._record(identity, label, request.method, shown_path, has_query, response.status, started, why, f"stream ended: {type(error).__name__}")
                return response
            return self._finish(
                identity, label, request.method, shown_path, has_query, 502, started, "error", self._json(502, "Bad Gateway: the Supervisor could not be reached.")
            )
        self._record(identity, label, request.method, shown_path, has_query, response.status, started, why)
        return response

    # -- WebSocket -----------------------------------------------------------

    async def websocket(self, request, identity, grants, label):
        aiohttp = self.aiohttp
        started = time.monotonic()
        path = access_rules.WEBSOCKET_PATH
        if access_rules.READ not in grants and access_rules.FULL not in grants:
            response = self._json(403, "Forbidden: the WebSocket API needs the Read or Full grant in the Twingate Gateway add-on.")
            return self._finish(identity, label, "GET", path, False, 403, started, "denied", response)
        if not self.token:
            return self._finish(identity, label, "GET", path, False, 503, started, "error", self._json(503, "Service Unavailable: the add-on has no Supervisor token."))
        refused = self._take("ws", identity.username)
        if refused:
            message = (
                "Too Many Requests: too many WebSocket connections of this Twingate user."
                if refused == 429
                else "Service Unavailable: too many WebSocket connections."
            )
            return self._finish(identity, label, "GET", path, False, refused, started, "limited", self._json(refused, message))

        try:
            # Connect to the Supervisor first: if it cannot be reached, the
            # client gets 502 instead of an upgraded connection that closes.
            try:
                upstream = await self.ws_session.ws_connect(
                    SUPERVISOR_WEBSOCKET,
                    max_msg_size=MAX_UPSTREAM_WS_MESSAGE,
                    autoping=True,
                    timeout=aiohttp.ClientWSTimeout(ws_close=10.0),
                )
            except (aiohttp.ClientError, OSError, TimeoutError):
                return self._finish(identity, label, "GET", path, False, 502, started, "error", self._json(502, "Bad Gateway: the Supervisor could not be reached."))
            try:
                return await self._websocket_session(request, upstream, identity, grants, label, started)
            finally:
                if not upstream.closed:
                    await upstream.close()
        finally:
            self._release("ws", identity.username)

    async def _receive_json(self, ws, seconds: float) -> dict | None:
        try:
            message = await ws.receive(timeout=seconds)
        except TimeoutError:
            return None
        if message.type != self.aiohttp.WSMsgType.TEXT:
            return None
        try:
            value = json.loads(message.data)
        except (ValueError, RecursionError):
            return None
        return value if isinstance(value, dict) else None

    async def _websocket_session(self, request, upstream, identity, grants, label, started):
        aiohttp = self.aiohttp
        web = aiohttp.web
        path = access_rules.WEBSOCKET_PATH
        required = await self._receive_json(upstream, AUTH_TIMEOUT)
        if not required or required.get("type") != "auth_required":
            return self._finish(identity, label, "GET", path, False, 502, started, "error", self._json(502, "Bad Gateway: unexpected answer from the Supervisor."))
        ha_version = required.get("ha_version")

        client = web.WebSocketResponse(heartbeat=30.0, max_msg_size=MAX_CLIENT_WS_MESSAGE, autoping=True)
        await client.prepare(request)
        self.journal.websockets += 1
        self._record(identity, label, "GET", path, False, 101, started, "read" if access_rules.FULL not in grants else "full", "WebSocket opened")
        stats = {"forwarded": 0, "refused": 0}
        reason = "closed"
        try:
            await client.send_str(json.dumps({"type": "auth_required", "ha_version": ha_version}, separators=(",", ":")))
            outcome = await self._client_auth(client)
            if outcome != "ok":
                reason = "authentication phase failed"
                return client
            await upstream.send_str(json.dumps({"type": "auth", "access_token": self.token}, separators=(",", ":")))
            reply = await self._receive_json(upstream, AUTH_TIMEOUT)
            if not reply or reply.get("type") != "auth_ok":
                await client.send_str(json.dumps({"type": "auth_invalid", "message": "Home Assistant cannot be reached through the Supervisor"}, separators=(",", ":")))
                reason = "the Supervisor refused the connection"
                return client
            await client.send_str(json.dumps({"type": "auth_ok", "ha_version": reply.get("ha_version", ha_version)}, separators=(",", ":")))
            reason = await self._relay(client, upstream, identity, grants, label, stats)
            return client
        except (aiohttp.ClientError, OSError, RuntimeError, ValueError) as error:
            # One side went away during the authentication phase.
            reason = f"connection lost ({type(error).__name__})"
            return client
        finally:
            self.journal.websockets -= 1
            if not client.closed:
                await client.close()
            if not upstream.closed:
                await upstream.close()
            elapsed = time.monotonic() - started
            log(
                f"{_printable(identity.username)} [{label}] WebSocket closed after {elapsed:.0f} s ({reason}): "
                f"{stats['forwarded']} commands forwarded, {stats['refused']} refused"
            )
            self.journal.add(
                kind="ws",
                user=identity.username[:200],
                grant=label,
                method="WS",
                path="closed",
                q=False,
                status=0,
                ms=round(elapsed * 1000.0, 1),
                decision="closed",
                detail=f"{stats['forwarded']} forwarded, {stats['refused']} refused; {reason}"[:120],
            )

    async def _client_auth(self, client) -> str:
        """The client's authentication phase, answered as Home Assistant answers it."""
        ws_type = self.aiohttp.WSMsgType
        try:
            message = await client.receive(timeout=AUTH_TIMEOUT)
        except TimeoutError:
            return "close"
        if message.type != ws_type.TEXT:
            return "close"
        outcome, text = access_rules.check_client_auth(message.data)
        if outcome == "invalid":
            await client.send_str(json.dumps({"type": "auth_invalid", "message": text}, separators=(",", ":")))
        return outcome

    async def _relay(self, client, upstream, identity, grants, label, stats) -> str:
        """Relays messages both ways until one side closes or the token expires."""
        ws_type = self.aiohttp.WSMsgType
        name = _printable(identity.username)
        full = access_rules.FULL in grants

        async def client_to_upstream() -> str:
            while True:
                message = await client.receive()
                if message.type == ws_type.TEXT:
                    decision = access_rules.decide_ws_frame(message.data, grants)
                    if decision.close:
                        return "invalid JSON from the client"
                    for command_id, command_type, allowed, why in decision.commands:
                        shown = _printable(command_type, 80)
                        if allowed:
                            stats["forwarded"] += 1
                        else:
                            stats["refused"] += 1
                        outcome = "" if allowed else {"blocked": " (blocked for every caller)", "invalid": " (malformed)"}.get(why, " (denied)")
                        log(f"{name} [{label}] WebSocket {shown} id={command_id}{outcome}")
                        self.journal.count(why)
                        self.journal.add(
                            kind="ws-cmd", user=identity.username[:200], grant=label, method="WS", path=shown, q=False,
                            status=0, ms=None, decision=why, detail=f"id {command_id}",
                        )
                    if decision.forward is not None:
                        await upstream.send_str(decision.forward)
                    for reply in decision.replies:
                        await client.send_str(json.dumps(reply, separators=(",", ":")))
                elif message.type == ws_type.BINARY:
                    # Binary frames feed handlers that commands such as
                    # assist_pipeline/run register; only Full can start them.
                    if full:
                        await upstream.send_bytes(message.data)
                elif message.type in (ws_type.CLOSE, ws_type.CLOSING, ws_type.CLOSED):
                    return "closed by the client"
                elif message.type == ws_type.ERROR:
                    return "client connection error"

        async def upstream_to_client() -> str:
            while True:
                message = await upstream.receive()
                if message.type == ws_type.TEXT:
                    await client.send_str(message.data)
                elif message.type == ws_type.BINARY:
                    await client.send_bytes(message.data)
                elif message.type in (ws_type.CLOSE, ws_type.CLOSING, ws_type.CLOSED):
                    return "closed by Home Assistant"
                elif message.type == ws_type.ERROR:
                    return "Home Assistant connection error"

        tasks = [asyncio.ensure_future(client_to_upstream()), asyncio.ensure_future(upstream_to_client())]
        expires_in = max(0.0, identity.expires_at - time.time())
        done, pending = await asyncio.wait(tasks, timeout=expires_in, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if not done:
            await client.close(code=1008, message=b"Twingate token expired")
            return "the Twingate token expired"
        task = done.pop()
        try:
            return task.result()
        except Exception as error:  # noqa: BLE001 - a failed send ends the connection
            return f"{type(error).__name__}"


# ----------------------------------------------------------------------------
# Serving
# ----------------------------------------------------------------------------


async def keep_keys(verifier: gat.Verifier, journal: Journal) -> None:
    """Reads the signing keys at start, then every hour (every minute while failing)."""
    while True:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(verifier.keys.refresh)
        state = dict(verifier.keys.state)
        if state != journal.keys:
            # Logged when the outcome changes, not at every retry.
            if (state.get("ok"), state.get("error")) != (journal.keys.get("ok"), journal.keys.get("error")):
                if state.get("ok") and not state.get("error"):
                    log(f"Twingate signing keys loaded ({state.get('keys')}).")
                elif state.get("ok"):
                    log(f"could not read the Twingate signing keys again ({state.get('error')}); the keys read before stay in use.")
                else:
                    log(f"cannot read the Twingate signing keys ({state.get('error')}); requests are refused until they can be read.")
            journal.keys = state
            journal.changed = True
        await asyncio.sleep(KEY_CHECK_INTERVAL)


async def serve(port: int, token: str) -> None:
    from aiohttp import web  # noqa: PLC0415

    quiet_library_logs()
    journal = Journal()
    journal.token_present = bool(token)
    feed = asyncio.ensure_future(journal.feed())
    journal.state = "waiting for the options"
    config = await wait_for_config(CONFIG_FILE)
    binding = gat.Binding(config.hostnames, config.port, config.host_port)
    verifier = gat.Verifier(config.network, binding, gat.KeyStore(config.network))
    proxy = Proxy(config, token, journal, verifier)
    await proxy.start_session()

    async def on_prepare(_request, response) -> None:
        # aiohttp names itself in the Server header unless it is set.
        response.headers["Server"] = ""

    app = web.Application(client_max_size=MAX_BODY_BYTES)
    app.on_response_prepare.append(on_prepare)
    app.router.add_route("*", "/{tail:.*}", proxy.handle)
    runner = web.AppRunner(
        app, access_log=None, handle_signals=False, shutdown_timeout=3.0, max_field_size=MAX_HEADER_FIELD, max_line_size=16 * 1024
    )
    await runner.setup()
    # The Gateway connects from the add-on's own address on the Supervisor's
    # network, or through a published host port.
    site = web.TCPSite(runner, "0.0.0.0", port, reuse_address=True)  # noqa: S104
    await site.start()
    keys = asyncio.ensure_future(keep_keys(verifier, journal))
    journal.state = "running"
    journal.changed = True
    if not token:
        log("has no Supervisor token; every authorized request is answered 503.")
    log(f"listening on port {port} for the Gateway. Accepted Resources: address {', '.join(config.hostnames) or '(none)'} with upstream port {config.port}"
        + (f", or an IPv4 address with upstream port {config.host_port} (published host port)" if config.host_port else "") + ".")
    for line in config.rules.describe():
        log(f"access rule: {line}")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (15, 2):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signum, stop.set)
    await stop.wait()
    keys.cancel()
    feed.cancel()
    await runner.cleanup()
    for session in (proxy.session, proxy.ws_session):
        if session:
            await session.close()


# ----------------------------------------------------------------------------
# Build-time check
# ----------------------------------------------------------------------------


def self_check() -> int:
    """Checks the rules, the token verification and that aiohttp loads; used at build time."""
    import base64  # noqa: PLC0415
    import hashlib  # noqa: PLC0415
    import hmac  # noqa: PLC0415

    import aiohttp  # noqa: F401, PLC0415 - compiles and checks the package
    from aiohttp import web  # noqa: F401, PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: PLC0415

    failures: list[str] = []

    def expect(name: str, condition: bool) -> None:
        if not condition:
            failures.append(name)

    rules = access_rules.Rules([], ["Agents"], ["Admins"])
    expect("empty read gives everyone Read", rules.grants(["Other"]) == {access_rules.READ})
    expect("full includes read and mcp", rules.grants(["Admins"]) == {access_rules.READ, access_rules.MCP, access_rules.FULL})
    strict = access_rules.Rules(["Readers"], ["Agents"], [])
    expect("non-empty read: no list, no grant", strict.grants(["Other"]) == frozenset())
    expect("union of groups", strict.grants(["Readers", "Agents"]) == {access_rules.READ, access_rules.MCP})
    read = frozenset({access_rules.READ})
    full = frozenset({access_rules.READ, access_rules.MCP, access_rules.FULL})
    mcp = frozenset({access_rules.MCP})
    expect("read GET states", access_rules.decide_rest("GET", "/api/states", read)[0])
    expect("read POST services denied", not access_rules.decide_rest("POST", "/api/services/light/turn_on", read)[0])
    expect("read POST template denied", not access_rules.decide_rest("POST", "/api/template", read)[0])
    expect("full POST template", access_rules.decide_rest("POST", "/api/template", full)[0])
    expect("render_template denied for read", access_rules.decide_ws_frame('{"id":20,"type":"render_template","template":"x"}', read).forward is None)
    expect("auth/current_user for read", access_rules.decide_ws_frame('{"id":21,"type":"auth/current_user"}', read).forward is not None)
    expect("auth/sign_path still blocked", access_rules.decide_ws_frame('{"id":22,"type":"auth/sign_path","path":"/x"}', full).forward is None)
    expect("event_type list refused, no error", access_rules.decide_ws_frame('{"id":23,"type":"subscribe_events","event_type":[]}', read).replies[0]["error"]["code"] == "unauthorized")
    for raw in ("/api/states%3fx", "/api/states%23x", "/api/services/light%3F/x"):
        expect(f"query or fragment escape {raw}", access_rules.canonical_path(raw) is None)
    inspect = access_rules.inspect_mcp_body

    def tool(name: str, arguments: object) -> bytes:
        return json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": name, "arguments": arguments}}).encode()

    expect("call_action hassio", inspect(tool("homeassistant__call_action", {"action": "hassio.host_reboot"})) == ("blocked", 5))
    expect("call_action Backup", inspect(tool("homeassistant__call_action", {"action": " Backup.create"})) == ("blocked", 5))
    expect("call_action missing", inspect(tool("homeassistant__call_action", {})) == ("blocked", 5))
    expect("call_action not text", inspect(tool("other__call_action", {"action": ["hassio.x"]})) == ("blocked", 5))
    expect("call_action light", inspect(tool("homeassistant__call_action", {"action": "light.turn_on"})) == ("ok", None))
    expect("mcp utf-7 refused", not access_rules.mcp_content_type_ok("application/json; charset=utf-7"))
    expect("mcp utf-8 ok", access_rules.mcp_content_type_ok("application/json; charset=UTF-8") and access_rules.mcp_content_type_ok("application/json"))
    expect("mcp latin-1 body refused", inspect(b'{"method":"tools/call","x":"' + bytes([0xE9]) + b'"}') == ("invalid", None))
    expect("mcp scalar refused", inspect(b"5") == ("invalid", None) and inspect(b"[1]") == ("invalid", None) and inspect(b"") == ("invalid", None))
    expect("mcp only mcp", access_rules.decide_rest("POST", "/api/mcp", mcp)[0] and not access_rules.decide_rest("GET", "/api/states", mcp)[0])
    expect("read no mcp", not access_rules.decide_rest("POST", "/api/mcp", read)[0])
    for blocked_path in (
        "/api/hassio/addons",
        "/api/hassio_ingress/x/y",
        "/api/HASSIO_auth",
        "/api/services/HassIO/host_reboot",
        "/api/backup/download/x",
        "/api/onboarding/users",
        "/api/repairs/issues/fix",
    ):
        expect(f"blocked {blocked_path}", access_rules.decide_rest("POST", blocked_path, full) == (False, "blocked"))
    expect("full other service", access_rules.decide_rest("POST", "/api/services/light/turn_on", full)[0])
    for bad in ("/api/%2e%2e/x", "/api/services/hassio%2Fhost_reboot", "//api/x", "/api/./x", "/api/%252e", "/api/x%", "/api/\\x"):
        expect(f"unclear path {bad}", access_rules.canonical_path(bad) is None)
    expect("decoded once", access_rules.canonical_path("/api/services/%68assio/x") == "/api/services/hassio/x")
    expect("webhook masked", access_rules.mask_path("/api/webhook/secret") == "/api/webhook/***")
    frame = access_rules.decide_ws_frame('[{"id":1,"type":"get_states"},{"id":2,"type":"call_service","domain":"light","service":"turn_on"}]', read)
    expect("array split", frame.forward == '[{"id":1,"type":"get_states"}]' and len(frame.replies) == 1 and frame.replies[0]["id"] == 2)
    frame = access_rules.decide_ws_frame('{"id":3,"type":"call_service","domain":"Hassio","service":"host_reboot"}', full)
    expect("hassio action blocked", frame.forward is None and frame.replies[0]["error"]["code"] == "unauthorized")
    nested = {"id": 4, "type": "execute_script", "sequence": [{"choose": [{"conditions": [], "sequence": [{"action": "hassio.addon_stop"}]}]}]}
    expect("nested hassio blocked", access_rules.decide_ws_frame(json.dumps(nested), full).forward is None)
    templated = {"id": 5, "type": "execute_script", "sequence": [{"action": "{{ 'hassio' }}.addon_stop"}]}
    expect("templated action blocked", access_rules.decide_ws_frame(json.dumps(templated), full).forward is None)
    notify = {"id": 6, "type": "execute_script", "sequence": [{"action": "notify.phone", "data": {"data": {"actions": [{"action": "URI"}]}}}]}
    expect("action key in data allowed", access_rules.decide_ws_frame(json.dumps(notify), full).forward is not None)
    expect("supervisor/api blocked", access_rules.decide_ws_frame('{"id":7,"type":"supervisor/api","endpoint":"/x","method":"get"}', full).forward is None)
    expect("subscribe all events denied for read", access_rules.decide_ws_frame('{"id":8,"type":"subscribe_events"}', read).forward is None)
    expect("subscribe state_changed for read", access_rules.decide_ws_frame('{"id":9,"type":"subscribe_events","event_type":"state_changed"}', read).forward is not None)
    expect("invalid json closes", access_rules.decide_ws_frame("{", read).close)
    expect("auth placeholder", access_rules.check_client_auth('{"type":"auth","access_token":"x"}') == ("ok", None))
    expect("auth empty", access_rules.check_client_auth('{"type":"auth","access_token":""}')[0] == "invalid")
    cross = access_rules.cross_site_browser_request
    expect("no browser headers", not cross(None, None, "ha-api.int"))
    expect("same origin", not cross("http://ha-api.int", "same-origin", "ha-api.int") and not cross("https://HA-API.int:443", None, "ha-api.int"))
    expect("other origin", cross("https://evil.example", None, "ha-api.int") and cross("null", None, "ha-api.int") and cross("http://ha-api.int:8080", None, "ha-api.int"))
    expect("cross-site fetch", cross(None, "cross-site", "ha-api.int") and cross(None, "same-site", "ha-api.int") and not cross(None, "none", "ha-api.int"))
    expect("mcp hassio tool", access_rules.inspect_mcp_body(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hassio__get_logs"}}') == ("blocked", 1))
    expect("mcp other tool", access_rules.inspect_mcp_body(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"GetLiveContext"}}') == ("ok", None))

    # Token verification with a key made here.
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}]}
    now = time.time()

    def claims(**changes) -> dict:
        value = {
            "iss": "twingate", "aud": ["net"], "iat": int(now) - 5, "exp": int(now) + 600, "typ": "GAT", "ver": "1", "rnw": int(now) + 60,
            "cpk": "cGs=", "user": {"id": "u1", "username": "alice", "groups": ["Admins"]}, "device": {"id": "d1"},
            "resource": {"id": "r1", "type": "WEB_APP", "address": "local-twingate-gateway", "gateway_metadata": {
                "downstream": {"port": 80, "tls_mode": "NONE"}, "upstream": {"port": 8124, "tls_mode": "NONE"}}},
        }
        value.update(changes)
        return value

    def sign(payload: dict, alg: str = "ES256", kid: str = "k1") -> str:
        signing_input = f"{b64(json.dumps({'alg': alg, 'kid': kid, 'typ': 'JWT'}).encode())}.{b64(json.dumps(payload).encode())}"
        if alg == "HS256":
            return signing_input + "." + b64(hmac.new(b"secret", signing_input.encode(), hashlib.sha256).digest())
        if alg == "none":
            return signing_input + "."
        r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    store = gat.KeyStore("net", fetch=lambda _network: gat.parse_jwks(jwks))
    store.refresh()
    verifier = gat.Verifier("net", gat.Binding(["local-twingate-gateway"], 8124, None), store)

    def rejected(token: str) -> bool:
        try:
            verifier.verify(token)
        except gat.TokenError:
            return True
        return False

    expect("valid token", verifier.verify(sign(claims())).username == "alice")
    expect("expired", rejected(sign(claims(exp=int(now) - 1))))
    expect("wrong audience", rejected(sign(claims(aud=["other"]))))
    expect("wrong issuer", rejected(sign(claims(iss="twingate-dev"))))
    expect("alg none", rejected(sign(claims(), alg="none")))
    expect("alg HS256", rejected(sign(claims(), alg="HS256")))
    other = claims()
    other["resource"] = dict(other["resource"], gateway_metadata={"downstream": {"port": 80, "tls_mode": "NONE"}, "upstream": {"port": 8123, "tls_mode": "NONE"}})
    expect("other port", rejected(sign(other)))
    tampered = sign(claims())
    expect("bad signature", rejected(tampered[:-4] + ("AAAA" if not tampered.endswith("AAAA") else "BBBB")))
    expect("unknown kid", rejected(sign(claims(), kid="other")))
    if failures:
        print(f"self check failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("supervisor_proxy: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return self_check()
    port = DEFAULT_PORT
    fd = None
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    if "--token-fd" in argv:
        fd = int(argv[argv.index("--token-fd") + 1])
    token = read_token(fd)
    asyncio.run(serve(port, token))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
