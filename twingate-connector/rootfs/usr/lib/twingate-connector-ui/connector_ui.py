"""Web UI of the Twingate Connector add-on, shown through Home Assistant ingress.

Serves a read-only status page and the JSON document behind it. The data
comes from:

- /run/twingate-connector/status.json, written by /run.sh before it starts
  the Connector: the options without the tokens, the Connector version and
  the process ID of the Connector;
- /proc: whether that process is running and when it started;
- the Connector's Prometheus metrics on 127.0.0.1 (TWINGATE_METRICS_PORT);
- the log relay (log_relay.py), which sends the Connector's latest state,
  its recent warnings and errors (with IP and email addresses masked) and,
  when connection logs are on, summaries of recent connections over a Unix
  socket. They are kept in memory only.

The add-on's name and slug, shown on the page, and the port to listen on
(ingress_port) come from the add-on's config.yml, which the image contains.

The page shows the Connector's own view. Whether Twingate sees the Connector
as online is shown in the Twingate Admin Console.

The process runs as the unprivileged user twingate-ui with an empty
environment. It can neither read the Connector's log folder nor signal the
log relay, which runs as another user. Python standard library only.
"""

from __future__ import annotations

import contextlib
import html
import json
import math
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ingress_server

WWW_DIR = "/usr/share/twingate-connector-ui"
STATUS_FILE = "/run/twingate-connector/status.json"
RELAY_SOCKET = "/run/twingate-connector-ui/relay.sock"
CONNECTOR_BIN = "/usr/bin/twingate-connector"
# The kernel keeps the first 15 characters of a program's file name.
CONNECTOR_NAME = os.path.basename(CONNECTOR_BIN)[:15]
# The add-on's config.yml, copied into the image (see the Dockerfile). Its
# name, slug and ingress_port are the only place where they are set, so that
# a copy of the add-on with another name, slug and port (the Twingate
# Connector (Exit) add-on, made by scripts/sync-connector-exit.sh) differs
# from this add-on in config.yml only.
ADDON_CONFIG = "/usr/share/twingate-connector-ui/config.yml"
DEFAULT_METRICS_PORT = 9999

LIVE_CACHE_SECONDS = 2.0
RELAY_STALE_SECONDS = 15.0
RATE_WINDOW_SECONDS = 60.0
RATE_MIN_SECONDS = 8.0
METRICS_SAMPLE_SECONDS = 10.0
MAX_CONNECTIONS = 100
MAX_PROBLEMS = 50
MAX_HISTORY = 30
MAX_METRICS_BYTES = 1024 * 1024

FILES = {
    "/twingate-docs-theme.css": "twingate-docs-theme.css",
    "/app.js": "app.js",
    "/icon.png": "icon.png",
}

LOG_LEVELS = {"error": 3, "warn": 4, "info": 5, "debug": 7}

_NO_PROXY = urllib.request.ProxyHandler({})
_NETWORK = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_VERSION = re.compile(r"[0-9A-Za-z.+~-]{1,40}")
_STATE = re.compile(r"[A-Za-z][A-Za-z ]{0,30}")
_KEY = re.compile(r"[a-z]{1,10}\|[^\n]{0,700}")
_LEVEL = re.compile(r"error|warning")
_CONNECTION_ID = re.compile(r"[0-9A-Za-z._:-]{1,80}")
_WORD = re.compile(r"[a-z0-9_/.-]{1,40}")
_ADDRESS = re.compile(r"[0-9A-Fa-f.:]{2,45}")
_HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
_ERROR_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,59}")
# A top-level key of config.yml with its value on the same line, and the
# forms of that value understood here: "double-quoted" or 'single-quoted'
# without escapes, or plain, each optionally followed by a comment.
_CONFIG_KEY = re.compile(r"(name|slug|ingress_port):[ \t]+(\S.*?)[ \t]*")
_CONFIG_VALUE = re.compile(r'"([^"\\]*)"(?:[ \t]+#.*)?|\'([^\']*)\'(?:[ \t]+#.*)?|([^\s"\'#|>&*!%@`{}\[\],][^#]*?)(?:[ \t]+#.*)?')
_SLUG = re.compile(r"[a-z0-9_][a-z0-9_-]{0,63}")
_PORT = re.compile(r"[1-9][0-9]{0,4}")


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


def _count(value: object) -> int | None:
    number = _number(value)
    if number is None or number < 0:
        return None
    return int(number)


def _now() -> float:
    return round(time.time(), 3)


# ----------------------------------------------------------------------------
# The add-on's name, slug and ingress port, from config.yml
# ----------------------------------------------------------------------------


def load_addon_config(path: str = ADDON_CONFIG) -> dict:
    """Reads name, slug and ingress_port from the add-on's config.yml.

    Only the top-level keys with a one-line value are read (Python's standard
    library has no YAML parser). Any other form, or a missing or invalid
    value, raises ValueError, which fails the image build (self_check).
    """
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            key_match = _CONFIG_KEY.fullmatch(line.rstrip("\r\n"))
            if not key_match:
                continue
            key, raw = key_match.groups()
            value_match = _CONFIG_VALUE.fullmatch(raw)
            if key in values:
                raise ValueError(f"{path}: {key} is set more than once")
            if not value_match:
                raise ValueError(f"{path}: cannot read the value of {key}: {raw}")
            values[key] =next(group for group in value_match.groups() if group is not None)
    name = values.get("name", "")
    slug = values.get("slug", "")
    port = values.get("ingress_port", "")
    if not 0 < len(name) <= 100 or not _SLUG.fullmatch(slug) or not _PORT.fullmatch(port) or int(port) > 65535:
        raise ValueError(f"{path}: need name, slug and ingress_port (1 to 65535), got {values}")
    return {"name": name, "slug": slug, "ingress_port": int(port)}


def render_page(template: bytes, addon: dict) -> bytes:
    """Puts the add-on's name and slug into the page (index.html)."""
    page = template
    for marker, value in ((b"{{addon_name}}", addon["name"]), (b"{{addon_slug}}", addon["slug"])):
        page = page.replace(marker, html.escape(value, quote=True).encode("utf-8"))
    if b"{{" in page:
        raise ValueError("index.html has an unknown {{...}} marker")
    return page


# ----------------------------------------------------------------------------
# Startup status written by /run.sh
# ----------------------------------------------------------------------------


def load_startup_status() -> dict | None:
    """Reads the status file and keeps only the expected, non-secret fields."""
    try:
        with open(STATUS_FILE, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None

    log_level = raw.get("log_level") if raw.get("log_level") in LOG_LEVELS else None
    metrics_port = raw.get("metrics_port")
    if not (isinstance(metrics_port, int) and not isinstance(metrics_port, bool) and 0 < metrics_port < 65536):
        metrics_port = None
    pid = raw.get("pid")
    if not (isinstance(pid, int) and not isinstance(pid, bool) and pid > 1):
        pid = None

    return {
        "addon_version": _match(_VERSION, raw.get("addon_version")),
        "connector_version": _match(_VERSION, raw.get("connector_version")),
        "started_at": _number(raw.get("started_at")),
        "pid": pid,
        "network": _match(_NETWORK, raw.get("network")),
        "log_level": log_level,
        "log_level_number": LOG_LEVELS.get(log_level),
        "hostname_label": _match(_HOSTNAME, raw.get("hostname_label")),
        "deployed_by_label": _match(_HOSTNAME, raw.get("deployed_by_label")),
        "connection_logs": raw.get("connection_logs") is True,
        "metrics_port": metrics_port,
        "log_relay": raw.get("log_relay") is True,
    }


# ----------------------------------------------------------------------------
# The Connector process
# ----------------------------------------------------------------------------


def _boot_time() -> float | None:
    try:
        with open("/proc/stat", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _process_start(pid: int) -> float | None:
    """Start time of a process from /proc/<pid>/stat (field 22, clock ticks after boot)."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
        ticks = int(fields[19])
        boot = _boot_time()
        if boot is None:
            return None
        return round(boot + ticks / os.sysconf("SC_CLK_TCK"), 3)
    except (OSError, ValueError, IndexError):
        return None


def _program(pid: int) -> str | None:
    """The process name: the file name of the program it runs, cut to 15 characters."""
    try:
        with open(f"/proc/{pid}/comm", "rb") as handle:
            return handle.read(64).strip().decode("utf-8", "replace")
    except OSError:
        return None


def _find_connector() -> int | None:
    with contextlib.suppress(OSError):
        for name in os.listdir("/proc"):
            if name.isdigit() and _program(int(name)) == CONNECTOR_NAME:
                return int(name)
    return None


def check_process(startup: dict | None) -> dict:
    """Whether the Connector runs. /run.sh starts it with exec, so it keeps the PID in the status file."""
    pid = (startup or {}).get("pid")
    program = _program(pid) if pid else None
    if program != CONNECTOR_NAME:
        found = _find_connector()
        if found is not None:
            pid, program = found, CONNECTOR_NAME
    if program == CONNECTOR_NAME:
        # The process started as /run.sh, which installed the Connector first;
        # it wrote the status file just before it started the Connector.
        started = _process_start(pid)
        if pid == (startup or {}).get("pid") and startup.get("started_at"):
            started = max(started or 0, startup["started_at"])
        return {"state": "running", "started_at": started, "checked_at": _now()}
    if program is not None:
        # The PID still runs /run.sh, which is installing the Connector.
        return {"state": "starting", "started_at": None, "checked_at": _now()}
    return {"state": "stopped" if startup else "starting", "started_at": None, "checked_at": _now()}


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


_SAMPLE = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\S+)?")
_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*,?')


def _unescape(value: str) -> str:
    return value.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def parse_metrics(text: str) -> dict[str, list[tuple[dict, float]]]:
    """Parses the Prometheus and OpenMetrics text formats, keeping twingate_ samples."""
    samples: dict[str, list[tuple[dict, float]]] = {}
    for line in text.splitlines():
        if not line.startswith("twingate_"):
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
        if math.isfinite(value):
            samples.setdefault(name, []).append((labels, value))
    return samples


def _first(samples: dict, *names: str) -> float | None:
    for name in names:
        values = samples.get(name)
        if values:
            return sum(value for _, value in values)
    return None


def _by_transport(samples: dict, *names: str) -> dict:
    """Bytes per transport label: direct, relay/tcp, relay/quic (and relay in older Connectors)."""
    result = {"direct": 0, "relay_tcp": 0, "relay_quic": 0, "relay_other": 0, "other": 0}
    for name in names:
        for labels, value in samples.get(name, []):
            transport = labels.get("transport", "")
            if transport == "direct":
                key = "direct"
            elif transport == "relay/tcp":
                key = "relay_tcp"
            elif transport == "relay/quic":
                key = "relay_quic"
            elif transport.startswith("relay"):
                key = "relay_other"
            else:
                key = "other"
            result[key] += int(value)
        if samples.get(name):
            break
    result["relay"] = result["relay_tcp"] + result["relay_quic"] + result["relay_other"]
    result["total"] = result["direct"] + result["relay"] + result["other"]
    return result


def summarize_metrics(samples: dict) -> dict:
    uptime = _first(samples, "twingate_uptime_seconds", "twingate_connector_uptime_seconds")
    resources = _first(samples, "twingate_num_resources")
    regions = _first(samples, "twingate_num_relay_regions")
    return {
        "available": True,
        "uptime_seconds": int(uptime) if uptime is not None else None,
        "inbound": _by_transport(samples, "twingate_inbound_bytes_total", "twingate_inbound_bytes"),
        "outbound": _by_transport(samples, "twingate_outbound_bytes_total", "twingate_outbound_bytes"),
        "resources": int(resources) if resources is not None else None,
        "relay_regions": int(regions) if regions is not None else None,
    }


def fetch_metrics(port: int) -> dict:
    """Reads the metrics. Any failure, even an odd response, only makes them unavailable."""
    opener = urllib.request.build_opener(_NO_PROXY)
    try:
        with opener.open(f"http://127.0.0.1:{port}/metrics", timeout=3.0) as response:
            body = response.read(MAX_METRICS_BYTES + 1)
        if len(body) > MAX_METRICS_BYTES:
            return {"available": False, "error": "response too large"}
        return summarize_metrics(parse_metrics(body.decode("utf-8", "replace")))
    except urllib.error.URLError as error:
        reason = error.reason
        return {"available": False, "error": type(reason).__name__ if isinstance(reason, BaseException) else type(error).__name__}
    except Exception as error:  # noqa: BLE001
        return {"available": False, "error": type(error).__name__}


class RateTracker:
    """Average transfer rate over the last minute, from successive metric reads."""

    def __init__(self) -> None:
        self._samples: list[tuple[float, int, int]] = []

    def add(self, metrics: dict) -> dict | None:
        if not metrics.get("available"):
            return None
        now = time.monotonic()
        inbound = metrics["inbound"]["total"]
        outbound = metrics["outbound"]["total"]
        if self._samples and (inbound < self._samples[-1][1] or outbound < self._samples[-1][2]):
            # The counters went back: the Connector restarted.
            self._samples.clear()
        self._samples.append((now, inbound, outbound))
        self._samples = [sample for sample in self._samples if now - sample[0] <= RATE_WINDOW_SECONDS]
        first = self._samples[0]
        elapsed = now - first[0]
        if elapsed < RATE_MIN_SECONDS:
            return None
        return {
            "inbound_bps": round((inbound - first[1]) / elapsed, 1),
            "outbound_bps": round((outbound - first[2]) / elapsed, 1),
            "window_seconds": round(elapsed),
        }


# ----------------------------------------------------------------------------
# Snapshots from the log relay
# ----------------------------------------------------------------------------


def _clean_history(raw: object) -> list[dict]:
    history = []
    for entry in raw[-MAX_HISTORY:] if isinstance(raw, list) else []:
        if isinstance(entry, dict):
            state = _match(_STATE, entry.get("state"))
            when = _number(entry.get("t"))
            if state and when:
                history.append({"state": state, "t": when})
    return history


def _clean_state(raw: object) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    return {
        "current": _match(_STATE, raw.get("current")),
        "since": _number(raw.get("since")),
        "online_since": _number(raw.get("online_since")),
        "last_online_at": _number(raw.get("last_online_at")),
        "changes": _count(raw.get("changes")) or 0,
        "history": _clean_history(raw.get("history")),
    }


def _clean_problem(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    key = _match(_KEY, raw.get("key"))
    level = _match(_LEVEL, raw.get("level"))
    last = _number(raw.get("last"))
    if not key or not level or not last:
        return None
    return {
        "key": key,
        "level": level,
        "source": _text(raw.get("source"), 80) or "",
        "message": _text(raw.get("message"), 400) or "",
        "first": _number(raw.get("first")) or last,
        "last": last,
        "count": _count(raw.get("count")) or 1,
    }


def _clean_connection(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    connection_id = _match(_CONNECTION_ID, raw.get("id"))
    when = _number(raw.get("t"))
    updated = _number(raw.get("updated"))
    if not connection_id or not when:
        return None
    port = _count(raw.get("port"))
    duration = _number(raw.get("ms"))
    result = raw.get("result")
    return {
        "id": connection_id,
        "t": when,
        "updated": updated or when,
        "result": result if result in ("open", "closed", "failed", "denied", "other") else "other",
        "event": _match(_WORD, raw.get("event")) or "",
        "user": _text(raw.get("user"), 200) or "",
        "resource": _text(raw.get("resource"), 255) or "",
        "resource_ip": _match(_ADDRESS, raw.get("resource_ip")) or "",
        "port": port if port is not None and port <= 65535 else None,
        "protocol": _match(_WORD, raw.get("protocol")) or "",
        "path": _match(_WORD, raw.get("path")) or "",
        "proto": _match(_WORD, raw.get("proto")) or "",
        "rx": _count(raw.get("rx")),
        "tx": _count(raw.get("tx")),
        "ms": duration if duration is not None and duration >= 0 else None,
        "location": _text(raw.get("location"), 200) or "",
        "error": _text(raw.get("error"), 300) or "",
    }


def _merge_problem(old: dict | None, new: dict) -> dict:
    """Adds the counts of a message group seen by an earlier relay."""
    if not old:
        return new
    return dict(new, count=old["count"] + new["count"], first=min(old["first"], new["first"]))


class RelayStore:
    """Receives snapshots from the relay and keeps the latest one in memory.

    When the relay restarts, its new snapshots start without the problems and
    connections it had seen; those of the previous relay are kept here and
    merged, so that the page does not lose them.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._relay_id: float | None = None
        self._relay: dict = {}
        self._state: dict = _clean_state(None)
        self._problems: list[dict] = []
        self._counts = {"error": 0, "warning": 0}
        self._connections: list[dict] = []
        self._events = 0
        self._unsupported = False
        self._carried_problems: dict[str, dict] = {}
        self._carried_counts = {"error": 0, "warning": 0}
        self._carried_connections: dict[str, dict] = {}
        self._carried_events = 0
        self._last_message: float | None = None
        self._socket_error: str | None = None
        self._bad_messages = 0
        self._started = time.monotonic()

    def start(self) -> None:
        threading.Thread(target=self._run, name="relay", daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                self._receive()
            except Exception as error:  # noqa: BLE001 - keep receiving
                with self._lock:
                    self._socket_error = type(error).__name__
                time.sleep(2.0)

    def _receive(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(RELAY_SOCKET)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.bind(RELAY_SOCKET)
            # The relay runs as another user. The folder of the socket gives
            # it the relay's group (see the twingate-connector-ui service);
            # that group may send.
            os.chmod(RELAY_SOCKET, 0o620)
            with self._lock:
                self._socket_error = None
            while True:
                data = sock.recv(256 * 1024)
                try:
                    self._handle(data)
                except Exception:  # noqa: BLE001 - one odd snapshot is skipped
                    with self._lock:
                        self._bad_messages += 1

    def _carry_over(self) -> None:
        """Keeps what the previous relay had seen. Called with the lock held."""
        for problem in self._problems:
            self._carried_problems[problem["key"]] = _merge_problem(self._carried_problems.get(problem["key"]), problem)
        for level in self._carried_counts:
            self._carried_counts[level] += self._counts.get(level, 0)
        for connection in self._connections:
            self._carried_connections[connection["id"]] = connection
        self._carried_events += self._events
        newest = sorted(self._carried_connections.values(), key=lambda item: item["updated"], reverse=True)[:MAX_CONNECTIONS]
        self._carried_connections = {item["id"]: item for item in newest}
        recent = sorted(self._carried_problems.values(), key=lambda item: item["last"], reverse=True)[:MAX_PROBLEMS]
        self._carried_problems = {item["key"]: item for item in recent}

    def _handle(self, data: bytes) -> None:
        try:
            message = json.loads(data)
        except ValueError:
            return
        if not isinstance(message, dict) or message.get("type") != "snapshot":
            return
        relay = message.get("relay") if isinstance(message.get("relay"), dict) else {}
        problems = message.get("problems") if isinstance(message.get("problems"), dict) else {}
        connections = message.get("connections") if isinstance(message.get("connections"), dict) else {}
        problem_items = problems.get("items") if isinstance(problems.get("items"), list) else []
        connection_items = connections.get("items") if isinstance(connections.get("items"), list) else []
        counts = problems.get("counts") if isinstance(problems.get("counts"), dict) else {}
        state = _clean_state(message.get("state"))
        cleaned_problems = [item for item in map(_clean_problem, problem_items[: MAX_PROBLEMS * 2]) if item]
        cleaned_connections = [item for item in map(_clean_connection, connection_items[: MAX_CONNECTIONS * 2]) if item]
        relay_id = _number(relay.get("started_at"))
        with self._lock:
            if self._relay_id is not None and relay_id != self._relay_id:
                self._carry_over()
                if state["current"] is None and self._state["current"] is not None:
                    # The new relay could not read the saved state.
                    state = self._state
            self._relay_id = relay_id
            self._relay = {
                "started_at": relay_id,
                "lines": _count(relay.get("lines")) or 0,
                "last_line_at": _number(relay.get("last_line_at")),
                "parse_errors": _count(relay.get("parse_errors")) or 0,
                "source_error": _match(_ERROR_NAME, relay.get("source_error")),
            }
            self._state = state
            self._problems = cleaned_problems
            self._counts = {"error": _count(counts.get("error")) or 0, "warning": _count(counts.get("warning")) or 0}
            self._connections = cleaned_connections
            self._events = _count(connections.get("events")) or 0
            self._unsupported = self._unsupported or connections.get("unsupported") is True
            self._last_message = time.monotonic()

    def snapshot(self) -> dict:
        with self._lock:
            problems = dict(self._carried_problems)
            for problem in self._problems:
                problems[problem["key"]] = _merge_problem(problems.get(problem["key"]), problem)
            connections = dict(self._carried_connections)
            for connection in self._connections:
                connections[connection["id"]] = connection
            now = time.monotonic()
            age = None if self._last_message is None else round(now - self._last_message, 1)
            return {
                "relay": dict(self._relay),
                "connected": age is not None and age < RELAY_STALE_SECONDS,
                # Just after the Web UI started, the relay's next snapshot is
                # still on its way (it sends one at least every 5 seconds).
                "pending": age is None and now - self._started < RELAY_STALE_SECONDS,
                "age_seconds": age,
                "socket_error": self._socket_error,
                "bad_messages": self._bad_messages,
                "state": dict(self._state),
                "problems": {
                    "counts": {level: self._carried_counts[level] + self._counts[level] for level in self._counts},
                    "items": sorted(problems.values(), key=lambda item: item["last"], reverse=True)[:MAX_PROBLEMS],
                },
                "connections": {
                    "events": self._carried_events + self._events,
                    "unsupported": self._unsupported,
                    "items": sorted(connections.values(), key=lambda item: item["t"], reverse=True)[:MAX_CONNECTIONS],
                },
            }


# ----------------------------------------------------------------------------
# The status document
# ----------------------------------------------------------------------------


def connection_totals(items: list[dict]) -> dict:
    return {
        "shown": len(items),
        "open": sum(1 for item in items if item["result"] == "open"),
        "failed": sum(1 for item in items if item["result"] in ("failed", "denied")),
        "users": len({item["user"] for item in items if item["user"]}),
    }


class StatusBuilder:
    def __init__(self, relay: RelayStore) -> None:
        self.relay = relay
        self.rates = RateTracker()
        self._lock = threading.Lock()
        self._live: dict | None = None
        self._live_at = 0.0

    def start(self) -> None:
        threading.Thread(target=self._sample, name="metrics", daemon=True).start()

    def _sample(self) -> None:
        """Reads the metrics every 10 seconds, so that the rate is known when the page opens."""
        while True:
            time.sleep(METRICS_SAMPLE_SECONDS)
            try:
                startup = load_startup_status()
                if check_process(startup)["state"] == "running":
                    self._metrics(startup)
            except Exception:  # noqa: BLE001, S112 - keep sampling; the page shows metric errors
                continue

    def _metrics(self, startup: dict | None) -> dict:
        with self._lock:
            now = time.monotonic()
            if self._live is not None and now - self._live_at < LIVE_CACHE_SECONDS:
                return self._live
            port = (startup or {}).get("metrics_port") or DEFAULT_METRICS_PORT
            metrics = fetch_metrics(port)
            metrics["rate"] = self.rates.add(metrics)
            self._live = metrics
            self._live_at = now
            return metrics

    def build(self, _headers) -> dict:
        # Each source fails on its own, so that one odd value cannot turn
        # the whole status into an error.
        try:
            startup = load_startup_status()
        except Exception:  # noqa: BLE001
            startup = None
        try:
            process = check_process(startup)
        except Exception as error:  # noqa: BLE001
            process = {"state": "unknown", "started_at": None, "checked_at": _now(), "error": type(error).__name__}
        if process["state"] == "running":
            try:
                metrics = self._metrics(startup)
            except Exception as error:  # noqa: BLE001
                metrics = {"available": False, "error": type(error).__name__}
        else:
            metrics = {"available": False, "error": "not running"}
        relay = self.relay.snapshot()
        enabled = bool(startup and startup["connection_logs"])
        # Summaries are only shown while connection logs are on.
        items = relay["connections"]["items"] if enabled else []
        return {
            "updated_at": _now(),
            "ready": startup is not None,
            "startup": startup,
            "process": process,
            "state": relay["state"],
            "metrics": metrics,
            "problems": relay["problems"],
            "connections": {
                "enabled": enabled,
                "unsupported": relay["connections"]["unsupported"],
                "events": relay["connections"]["events"] if enabled else 0,
                "totals": connection_totals(items),
                "items": items,
            },
            "relay": {
                "expected": bool(startup and startup["log_relay"]),
                "connected": relay["connected"],
                "pending": relay["pending"],
                "age_seconds": relay["age_seconds"],
                "socket_error": relay["socket_error"],
                "source_error": relay["relay"].get("source_error") if relay["connected"] else None,
                "lines": relay["relay"].get("lines", 0),
            },
        }


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------


def build_app(builder: StatusBuilder | None, addon: dict) -> ingress_server.App:
    routes = {"/api/status": builder.build} if builder else {}
    app = ingress_server.App(WWW_DIR, FILES, "index.html", routes)
    app.index = render_page(app.index, addon)
    return app


def self_check() -> int:
    """Checks config.yml, the page files and the parsers; used when the image is built."""
    try:
        addon = load_addon_config()
        build_app(None, addon)
    except (OSError, ValueError) as error:
        print(f"self check failed: {error}", file=sys.stderr)
        return 1
    sample = (
        "# HELP twingate_inbound_bytes Total bytes received from resources to connector.\n"
        "# TYPE twingate_inbound_bytes counter\n"
        'twingate_inbound_bytes_total{transport="relay/quic"} 100\n'
        'twingate_inbound_bytes_total{transport="direct"} 2000\n'
        'twingate_inbound_bytes_total{transport="relay/tcp"} 30\n'
        'twingate_outbound_bytes_total{transport="direct"} 5\n'
        "twingate_uptime_seconds 34\n"
        "twingate_num_resources 3\n"
        "twingate_num_relay_regions 2\n"
        "# EOF\n"
    )
    metrics = summarize_metrics(parse_metrics(sample))
    expected = (metrics["inbound"]["total"], metrics["inbound"]["relay"], metrics["outbound"]["direct"], metrics["uptime_seconds"], metrics["resources"], metrics["relay_regions"])
    if expected != (2130, 130, 5, 34, 3, 2):
        print(f"self check failed: {metrics}", file=sys.stderr)
        return 1
    store = RelayStore()
    store._handle(b'{"type":"snapshot","relay":{"started_at":1},"state":{"current":"Online","since":5},'
                  b'"problems":{"counts":{"warning":2},"items":[{"key":"warning|x|m","level":"warning","message":"m","last":6,"count":2}]},'
                  b'"connections":{"events":1,"items":[{"id":"a-1","t":7,"result":"closed","user":"u@example.com"}]}}')
    store._handle(b'{"type":"snapshot","relay":{"started_at":2},"state":{"current":"Online","since":5},'
                  b'"problems":{"counts":{"warning":1},"items":[{"key":"warning|x|m","level":"warning","message":"m","last":8,"count":1}]},'
                  b'"connections":{"events":0,"items":[]}}')
    view = store.snapshot()
    if view["problems"]["items"][0]["count"] != 3 or len(view["connections"]["items"]) != 1 or view["problems"]["counts"]["warning"] != 3:
        print(f"self check failed: relay restart {view}", file=sys.stderr)
        return 1
    print(f"connector_ui: ok ({addon['name']}, {addon['slug']}, port {addon['ingress_port']})")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return self_check()
    addon = load_addon_config()
    port = addon["ingress_port"]
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    relay = RelayStore()
    relay.start()
    builder = StatusBuilder(relay)
    builder.start()
    ingress_server.serve(port, build_app(builder, addon))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
