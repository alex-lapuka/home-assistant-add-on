"""Log relay of the Twingate Connector add-on.

Runs as the s6 service twingate-connector-relay, as the unprivileged user
twingate-relay. The relay is not in the path of the Connector's log: the
twingate-connector-log service (s6-log) reads the Connector's standard
output and standard error, copies every line unchanged to the add-on log
and also keeps the latest lines in a small rotated folder in memory
(LOG_DIR), each line prefixed with a TAI64N timestamp. The relay only reads
that folder, so a relay that stops, hangs, crashes or cannot start never
holds up the Connector or its log.

From the lines it reads, the relay keeps, in memory only:

- the Connector's own state from its "State: <name>" lines, with the time
  of each line and the recent state changes;
- the recent warning and error lines, grouped by message, with IP addresses
  and email addresses masked;
- when the add-on option connection_logs is on, a summary of each connection
  from the Connector's "ANALYTICS {json}" lines: time, user, Resource, path,
  bytes, duration, location (city, region, country) and the result. The
  client's public IP address, the device ID and the coordinates are dropped.

The relay saves its own state (the Connector's state and state changes, the
start times of open connections and its position in the log folder; no
personal data) in STATE_DIR, at the moment it sends a snapshot. A restarted
relay continues after the last line of its last snapshot: it neither reads
a line twice nor skips the lines written while it was down, as long as they
are still in the log folder. The relay sends snapshots to the Web UI over a
Unix datagram socket. Sending never blocks: if the Web UI is not running or
not reading, snapshots are dropped for the Web UI only.

Python standard library only.
"""

from __future__ import annotations

import collections
import contextlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import sys
import time

LOG_DIR = "/dev/shm/twingate-connector-log"
STATE_DIR = "/dev/shm/twingate-connector-relay"
STATE_FILE = f"{STATE_DIR}/state.json"
UI_SOCKET = "/run/twingate-connector-ui/relay.sock"

MAX_LINE_BYTES = 1024 * 1024
MAX_PARSED_LINE_BYTES = 8192
MAX_HISTORY = 30
MAX_PROBLEMS = 50
MAX_CONNECTIONS = 100
MAX_MESSAGE_CHARS = 400
MAX_DATAGRAM_BYTES = 120_000
READ_CHUNK = 256 * 1024
POLL_INTERVAL = 0.25
SEND_INTERVAL = 0.5
HEARTBEAT_INTERVAL = 5.0
# s6-log labels each line with a TAI64N timestamp: 2**62 plus the TAI
# seconds. TAI has been 37 seconds ahead of UTC since 2017.
TAI64_UNIX_OFFSET = 2**62 + 37

_STATE_LINE = re.compile(r"State: ([A-Za-z][A-Za-z ]{0,30}?)\s*")
# "[WARN] [libsdwan] [controller] message", optionally after a timestamp in
# brackets (TWINGATE_TIMESTAMP_FORMAT 1 or 2).
_LOG_LINE = re.compile(r"(?:\[[0-9 .:+TZ-]{1,40}\]\s*)?\[(ERROR|ERR|CRITICAL|CRIT|FATAL|WARNING|WARN)\]\s*((?:\[[^\]\s]{1,40}\]\s*)*)(.*)")
_TAI64N = re.compile(rb"@([0-9a-f]{16})([0-9a-f]{8}) ")
_ANALYTICS_PREFIX = b"ANALYTICS "
_UNSUPPORTED_TIER = b"Network analytics is not supported in your Twingate product tier"
_DIGITS = re.compile(r"\d+")
_CONNECTION_ID = re.compile(r"[0-9A-Za-z._:-]{1,80}")
_WORD = re.compile(r"[a-z0-9_/.-]{1,40}")
_ADDRESS = re.compile(r"[0-9A-Fa-f.:]{2,45}")

# Personal data in warning and error messages. IP addresses are masked with
# their port; candidates that are not valid addresses (times such as
# 22:52:36, MAC addresses, version numbers with three parts) stay.
_BRACKETED_IP = re.compile(r"\[([0-9A-Fa-f:.]{2,45}(?:%[\w.-]{1,20})?)\](?::\d{1,5})?")
_IPV6 = re.compile(r"(?<![\w:.%])((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4})?)(%[\w.-]{1,20})?(?![\w:%]|\.\d)")
_IPV4 = re.compile(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?![\w:]|\.\d)")
_EMAIL = re.compile(r"[^\s\"'`(),;:<>\[\]{}@]+@[\w-]+(?:\.[\w-]+)*")
MASKED_IP = "[IP]"
MASKED_EMAIL = "[email]"

LEVELS = {
    "ERROR": "error",
    "ERR": "error",
    "CRITICAL": "error",
    "CRIT": "error",
    "FATAL": "error",
    "WARNING": "warning",
    "WARN": "warning",
}


def _now() -> float:
    return round(time.time(), 3)


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    # Control characters are dropped; the Web UI shows text nodes only.
    cleaned = "".join(ch for ch in value[: limit * 2] if ch >= " " and ch != "\x7f")
    return cleaned[:limit]


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value < 2**63:
        return value
    if isinstance(value, float) and math.isfinite(value) and 0 <= value < 2**63:
        return int(value)
    return None


def _real(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return float(value)


def _epoch_ms(value: object) -> float | None:
    """Converts a millisecond timestamp to seconds, if it is plausible."""
    number = _int(value)
    if number is None or not 1_500_000_000_000 <= number <= 4_100_000_000_000:
        return None
    return round(number / 1000.0, 3)


def _location(value: object) -> str:
    """City, region and country from the stringified geoip JSON."""
    if not isinstance(value, str) or len(value) > 4096:
        return ""
    try:
        document = json.loads(value)
    except ValueError:
        return ""
    geoip = document.get("geoip") if isinstance(document, dict) else None
    if not isinstance(geoip, dict):
        return ""
    parts = [_text(geoip.get(key), 60) for key in ("city", "region", "country")]
    return ", ".join(part for part in parts if part)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _mask_bracketed(match: re.Match) -> str:
    return MASKED_IP if _is_ip(match.group(1).split("%", 1)[0]) else match.group(0)


def _mask_ipv6(match: re.Match) -> str:
    candidate = match.group(1)
    if any(ch in "0123456789abcdefABCDEF" for ch in candidate) and _is_ip(candidate):
        return MASKED_IP
    return match.group(0)


def _mask_ipv4(match: re.Match) -> str:
    return MASKED_IP if _is_ip(match.group(1)) else match.group(0)


def mask_personal(text: str) -> str:
    """Masks IPv4 and IPv6 addresses (with a port) and email addresses."""
    text = _BRACKETED_IP.sub(_mask_bracketed, text)
    text = _IPV6.sub(_mask_ipv6, text)
    text = _IPV4.sub(_mask_ipv4, text)
    return _EMAIL.sub(MASKED_EMAIL, text)


def split_timestamp(raw: bytes) -> tuple[float | None, bytes]:
    """Removes s6-log's TAI64N label and returns the line's time (Unix seconds)."""
    match = _TAI64N.match(raw)
    if not match:
        return None, raw
    seconds = int(match.group(1), 16) - TAI64_UNIX_OFFSET
    when = round(seconds + int(match.group(2), 16) / 1e9, 3)
    if not 1_500_000_000 <= when <= 4_100_000_000:
        when = None
    return when, raw[match.end() :]


def parse_state(line: str) -> str | None:
    match = _STATE_LINE.fullmatch(line)
    return match.group(1) if match else None


def parse_problem(line: str) -> dict | None:
    match = _LOG_LINE.fullmatch(line)
    if not match:
        return None
    level = LEVELS[match.group(1)]
    sources = re.findall(r"\[([^\]\s]{1,40})\]", match.group(2))
    # Masked before the message is cut, so that no part of an address stays.
    message = _text(mask_personal(match.group(3).strip()), MAX_MESSAGE_CHARS)
    source = mask_personal(" ".join(sources[:3]))
    return {
        "key": f"{level}|{source}|{_DIGITS.sub('#', message)}",
        "level": level,
        "source": _text(source, 80),
        "message": message,
    }


def parse_analytics(payload: bytes) -> dict | None:
    """Returns the summary of one ANALYTICS event, or None.

    Only the fields below are copied. connection.client_ip (the user's public
    address), device.id, the geoip coordinates, the connector and remote
    network names and the relays are never read into the summary.
    """
    try:
        event = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    connection = event.get("connection") if isinstance(event.get("connection"), dict) else {}
    resource = event.get("resource") if isinstance(event.get("resource"), dict) else {}
    user = event.get("user") if isinstance(event.get("user"), dict) else {}

    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not _WORD.fullmatch(event_type):
        event_type = "unknown"
    when = _epoch_ms(event.get("timestamp"))
    connection_id = connection.get("id")
    if not isinstance(connection_id, str) or not _CONNECTION_ID.fullmatch(connection_id):
        connection_id = None

    def word(value: object) -> str:
        return value if isinstance(value, str) and _WORD.fullmatch(value) else ""

    resource_ip = connection.get("resource_ip")
    port = _int(connection.get("resource_port"))
    return {
        "id": connection_id,
        "event": event_type,
        "t": when,
        "user": _text(user.get("email"), 200),
        "resource": _text(resource.get("address"), 255),
        "resource_ip": resource_ip if isinstance(resource_ip, str) and _ADDRESS.fullmatch(resource_ip) else "",
        "port": port if port is not None and port <= 65535 else None,
        "protocol": word(connection.get("protocol")),
        "path": word(connection.get("tunnel_path")),
        "proto": word(connection.get("tunnel_proto")),
        "rx": _int(connection.get("rx")),
        "tx": _int(connection.get("tx")),
        "duration": _int(connection.get("duration")),
        "location": _location(event.get("location")),
        "error": _text(event.get("error_message") or connection.get("error_message"), 300),
    }


RESULTS = {
    "established_connection": "open",
    "closed_connection": "closed",
    "failed_to_connect": "failed",
    "denied_access": "denied",
}


class Connections:
    """One summary per connection, merged from its established and closed events."""

    def __init__(self) -> None:
        self.items: collections.OrderedDict[str, dict] = collections.OrderedDict()
        self.started: dict[str, float] = {}
        # Unit of connection.duration in milliseconds, learnt by comparing it
        # with the time between the established and closed events. Twingate
        # does not document it; until it is known, a closed connection whose
        # established event was not seen has no duration.
        self.duration_unit_ms: float | None = None
        self.events = 0
        self.serial = 0

    def add(self, event: dict, seen: float | None = None) -> None:
        self.events += 1
        when = event["t"] or seen or _now()
        connection_id = event["id"]
        if connection_id is None:
            self.serial += 1
            connection_id = f"event-{int(when * 1000)}-{self.serial}"
        result = RESULTS.get(event["event"], "other")
        item = self.items.pop(connection_id, None) or {"id": connection_id, "t": when}
        if result == "open":
            self.started[connection_id] = when
            item["t"] = when
        start = self.started.get(connection_id)
        item.update(
            {
                "updated": when,
                "result": result,
                "event": event["event"],
            }
        )
        for key in ("user", "resource", "resource_ip", "port", "protocol", "path", "proto", "location", "error"):
            if event[key] not in ("", None):
                item[key] = event[key]
        for key in ("rx", "tx"):
            if event[key] is not None:
                item[key] = event[key]
        if result in ("closed", "failed", "denied"):
            item["ms"] = self._duration(start, when, event["duration"])
            if item["ms"] is not None and start is None:
                item["t"] = round(when - item["ms"] / 1000.0, 3)
            elif start is not None:
                item["t"] = start
            self.started.pop(connection_id, None)
        self.items[connection_id] = item
        while len(self.items) > MAX_CONNECTIONS:
            self.items.popitem(last=False)
        if len(self.started) > MAX_CONNECTIONS * 4:
            for old_id in list(self.started)[: len(self.started) - MAX_CONNECTIONS * 4]:
                del self.started[old_id]

    def _duration(self, start: float | None, end: float, reported: int | None) -> float | None:
        if start is not None:
            measured = max(0.0, (end - start) * 1000.0)
            if reported and measured >= 2000.0:
                ratio = reported / measured
                for unit in (1.0, 1000.0, 0.001):
                    if unit / 2 <= ratio <= unit * 2:
                        self.duration_unit_ms = unit
                        break
            return round(measured, 1)
        if reported is not None and self.duration_unit_ms:
            return round(reported / self.duration_unit_ms, 1)
        return None


class LogFollower:
    """Reads the lines that s6-log appends to its log folder, across rotations.

    s6-log writes to <folder>/current. When current is full, s6-log renames
    it to @<TAI64N>.s and starts a new current, and it deletes the oldest of
    these files beyond its size limit. The follower keeps the file it reads
    open, so a renamed or deleted file is still read to its end before the
    next one. Its position is the file's inode and the offset after the
    last complete line read.
    """

    def __init__(self, directory: str, start: tuple[int, int] | str = "beginning") -> None:
        self.directory = directory
        self.start = start
        self.handle = None
        self.inode: int | None = None
        self.offset = 0
        self.pending = bytearray()
        self.skip_partial = False
        self.error: str | None = None

    def position(self) -> list[int] | None:
        if self.inode is not None:
            return [self.inode, self.offset]
        if isinstance(self.start, tuple):
            return list(self.start)
        return None

    def close(self) -> None:
        if self.handle is not None:
            with contextlib.suppress(OSError):
                self.handle.close()
        self.handle = None

    def _files(self) -> list[tuple[str, os.stat_result]]:
        """The archived files, oldest first, then current."""
        names = sorted(name for name in os.listdir(self.directory) if name.startswith("@") and name[-2:] in (".s", ".u"))
        names.append("current")
        files = []
        for name in names:
            try:
                files.append((name, os.stat(os.path.join(self.directory, name))))
            except FileNotFoundError:
                continue
        return files

    def _open(self, name: str, inode: int, offset: int) -> bool:
        """Opens a listed file, if it is still the same file."""
        try:
            handle = open(os.path.join(self.directory, name), "rb", buffering=0)  # noqa: SIM115
        except FileNotFoundError:
            return False
        if os.fstat(handle.fileno()).st_ino != inode:
            # current was renamed in the meantime; the caller lists again.
            handle.close()
            return False
        skip_partial = False
        if offset:
            handle.seek(offset - 1)
            skip_partial = handle.read(1) != b"\n"
        self.close()
        self.handle = handle
        self.inode = inode
        self.offset = offset
        self.pending.clear()
        self.skip_partial = skip_partial
        return True

    def _open_first(self) -> bool:
        files = self._files()
        if not files:
            return False
        if isinstance(self.start, tuple):
            inode, offset = self.start
            for name, info in files:
                if info.st_ino == inode and info.st_size >= offset:
                    return self._open(name, inode, offset)
            # The file was deleted while the relay was down; every remaining
            # file is newer.
        elif self.start == "end":
            name, info = files[-1]
            return self._open(name, info.st_ino, info.st_size)
        name, info = files[0]
        return self._open(name, info.st_ino, 0)

    def _open_next(self) -> bool:
        files = self._files()
        following = files
        for index, (_, info) in enumerate(files):
            if info.st_ino == self.inode:
                following = files[index + 1 :]
                break
        # Otherwise the finished file was deleted already: every remaining
        # file is newer.
        return any(self._open(name, info.st_ino, 0) for name, info in following)

    def _replaced(self) -> bool:
        """Whether s6-log writes to another file than the one being read."""
        try:
            return os.stat(os.path.join(self.directory, "current")).st_ino != self.inode
        except FileNotFoundError:
            # Between a rename and the new current. A missing folder (s6-log
            # gave it up) raises, and the relay reports it.
            os.stat(self.directory)
            return False

    def _split(self, data: bytes, lines: list[bytes]) -> None:
        self.pending += data
        start = 0
        while True:
            end = self.pending.find(b"\n", start)
            if end < 0:
                break
            if self.skip_partial:
                self.skip_partial = False
            else:
                lines.append(bytes(self.pending[start:end]))
            start = end + 1
        if start:
            del self.pending[:start]
            self.offset += start
        if len(self.pending) > MAX_LINE_BYTES:
            self.offset += len(self.pending)
            self.pending.clear()
            self.skip_partial = True

    def read(self, budget: int = READ_CHUNK) -> list[bytes]:
        """Returns the complete lines written since the last call, about budget bytes at most."""
        lines: list[bytes] = []
        if self.handle is None and not self._open_first():
            return lines
        total = 0
        while total < budget:
            data = self.handle.read(budget - total)
            if not data:
                if not self._replaced():
                    break
                # The lines written just before the file was renamed.
                data = self.handle.read(budget - total)
                if not data:
                    if self.pending and not self.skip_partial:
                        # An unfinished line at the end of a finished file.
                        lines.append(bytes(self.pending))
                    self.offset += len(self.pending)
                    self.pending.clear()
                    self.skip_partial = False
                    if not self._open_next():
                        break
                    continue
            total += len(data)
            self._split(data, lines)
        return lines


class Relay:
    def __init__(self, saved_state: bool = True, from_end: bool = False) -> None:
        self.started_at = _now()
        self.saved_state = saved_state
        self.stopping = False
        self.changed = True
        self.last_send = 0.0
        self.last_heartbeat = -HEARTBEAT_INTERVAL
        self.last_saved: str | None = None
        self.lines = 0
        self.last_line_at: float | None = None
        self.unsent = 0
        self.parse_errors = 0
        self.read_errors = 0
        self.state: str | None = None
        self.state_since: float | None = None
        self.last_online_at: float | None = None
        self.online_since: float | None = None
        self.history: collections.deque[dict] = collections.deque(maxlen=MAX_HISTORY)
        self.state_changes = 0
        self.problems: collections.OrderedDict[str, dict] = collections.OrderedDict()
        self.problem_counts = {"error": 0, "warning": 0}
        self.connections = Connections()
        self.analytics_unsupported = False
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        with contextlib.suppress(OSError):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        position = None
        if saved_state:
            try:
                position = self.load_state()
            except Exception:  # noqa: BLE001 - start without the saved state
                self.state = None
        if position is not None:
            start: tuple[int, int] | str = position
        elif from_end:
            # Restarted without a saved state: lines already read by the
            # previous relay must not be counted twice.
            start = "end"
        else:
            # First start: the folder holds only lines this relay has not seen.
            start = "beginning"
        self.follower = LogFollower(LOG_DIR, start)

    # -- saved state -----------------------------------------------------------

    def load_state(self) -> tuple[int, int] | None:
        try:
            with open(STATE_FILE, encoding="utf-8") as handle:
                saved = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(saved, dict):
            return None
        state = saved.get("state")
        if isinstance(state, str) and parse_state(f"State: {state}") == state:
            self.state = state
        for name in ("state_since", "last_online_at", "online_since"):
            value = _real(saved.get(name))
            if value is not None:
                setattr(self, name, value)
        changes = saved.get("state_changes")
        if isinstance(changes, int) and not isinstance(changes, bool) and changes >= 0:
            self.state_changes = changes
        history = saved.get("history")
        if isinstance(history, list):
            for entry in history[-MAX_HISTORY:]:
                if (
                    isinstance(entry, dict)
                    and isinstance(entry.get("state"), str)
                    and parse_state(f"State: {entry['state']}") == entry["state"]
                    and _real(entry.get("t")) is not None
                ):
                    self.history.append({"state": entry["state"], "t": float(entry["t"])})
        started = saved.get("started")
        if isinstance(started, dict):
            for connection_id, when in list(started.items())[-MAX_CONNECTIONS * 4 :]:
                if isinstance(connection_id, str) and _CONNECTION_ID.fullmatch(connection_id) and _real(when) is not None:
                    self.connections.started[connection_id] = float(when)
        unit = saved.get("duration_unit_ms")
        if unit in (1.0, 1000.0, 0.001):
            self.connections.duration_unit_ms = unit
        self.analytics_unsupported = saved.get("analytics_unsupported") is True
        position = saved.get("position")
        if (
            isinstance(position, list)
            and len(position) == 2
            and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in position)
        ):
            return position[0], position[1]
        return None

    def save_state(self) -> None:
        if not self.saved_state:
            return
        document = json.dumps(
            {
                "state": self.state,
                "state_since": self.state_since,
                "last_online_at": self.last_online_at,
                "online_since": self.online_since,
                "state_changes": self.state_changes,
                "history": list(self.history),
                "started": self.connections.started,
                "duration_unit_ms": self.connections.duration_unit_ms,
                "analytics_unsupported": self.analytics_unsupported,
                "position": self.follower.position(),
            },
            separators=(",", ":"),
        )
        if document == self.last_saved:
            return
        tmp = f"{STATE_FILE}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(document)
            os.replace(tmp, STATE_FILE)
            self.last_saved = document
        except Exception:  # noqa: BLE001, S110
            # Not essential: a restarted relay would start without the state.
            pass

    # -- input -----------------------------------------------------------------

    def add_line(self, raw: bytes) -> None:
        when, raw = split_timestamp(raw)
        now = _now()
        # A line's time from s6-log, but never in the future.
        when = now if when is None or when > now else when
        self.lines += 1
        self.last_line_at = when
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if raw.startswith(_ANALYTICS_PREFIX):
            event = parse_analytics(raw[len(_ANALYTICS_PREFIX) :])
            if event is not None:
                self.connections.add(event, when)
                self.changed = True
            return
        if _UNSUPPORTED_TIER in raw and not self.analytics_unsupported:
            self.analytics_unsupported = True
            self.changed = True
        if len(raw) > MAX_PARSED_LINE_BYTES:
            return
        line = raw.decode("utf-8", "replace")
        state = parse_state(line)
        if state is not None:
            self.set_state(state, when)
            return
        problem = parse_problem(line)
        if problem is not None:
            self.add_problem(problem, when)

    def set_state(self, state: str, when: float) -> None:
        if state != self.state:
            self.state_changes += 1
            self.state_since = when
            if state == "Online":
                self.online_since = when
            elif self.state == "Online":
                self.last_online_at = when
                self.online_since = None
        self.state = state
        if state == "Online":
            self.last_online_at = when
        self.history.append({"state": state, "t": when})
        self.changed = True

    def add_problem(self, problem: dict, when: float) -> None:
        self.problem_counts[problem["level"]] += 1
        entry = self.problems.pop(problem["key"], None)
        if entry is None:
            entry = {"key": problem["key"], "first": when, "count": 0}
        entry.update(
            {
                "level": problem["level"],
                "source": problem["source"],
                "message": problem["message"],
                "last": when,
                "count": entry["count"] + 1,
            }
        )
        self.problems[problem["key"]] = entry
        while len(self.problems) > MAX_PROBLEMS:
            self.problems.popitem(last=False)
        self.changed = True

    def read_log(self) -> int:
        """Reads and summarizes new lines; returns how many were read."""
        try:
            lines = self.follower.read()
        except Exception as error:  # noqa: BLE001 - the folder may be missing or unreadable
            self.read_errors += 1
            if self.follower.error != type(error).__name__:
                self.follower.error = type(error).__name__
                self.changed = True
            return 0
        if self.follower.error is not None and self.follower.handle is not None:
            self.follower.error = None
            self.changed = True
        for line in lines:
            try:
                self.add_line(line)
            except Exception:  # noqa: BLE001 - a bad line must never stop the relay
                self.parse_errors += 1
        return len(lines)

    # -- output to the Web UI --------------------------------------------------

    def snapshot(self, connections: list[dict]) -> dict:
        return {
            "type": "snapshot",
            "relay": {
                "started_at": self.started_at,
                "lines": self.lines,
                "last_line_at": self.last_line_at,
                "unsent": self.unsent,
                "parse_errors": self.parse_errors,
                "source_error": self.follower.error,
            },
            "state": {
                "current": self.state,
                "since": self.state_since,
                "online_since": self.online_since,
                "last_online_at": self.last_online_at,
                "changes": self.state_changes,
                "history": list(self.history),
            },
            "problems": {
                "counts": dict(self.problem_counts),
                "items": list(self.problems.values()),
            },
            "connections": {
                "events": self.connections.events,
                "unsupported": self.analytics_unsupported,
                "items": connections,
            },
        }

    def maybe_send(self, now: float) -> None:
        due = self.changed and now - self.last_send >= SEND_INTERVAL
        if not due and now - self.last_heartbeat < HEARTBEAT_INTERVAL:
            return
        connections = list(self.connections.items.values())
        while True:
            payload = json.dumps(self.snapshot(connections), ensure_ascii=True, separators=(",", ":")).encode("ascii")
            if len(payload) <= MAX_DATAGRAM_BYTES or not connections:
                break
            connections = connections[len(connections) // 2 :]
        self.last_send = now
        self.last_heartbeat = now
        self.changed = False
        try:
            self.sock.sendto(payload, UI_SOCKET)
        except OSError:
            # The Web UI is not running, not reading, or restarting.
            self.unsent += 1
        # Saved together with the snapshot: a restarted relay continues
        # after the lines this snapshot covers.
        self.save_state()

    # -- main loop -------------------------------------------------------------

    def stop(self, _signum, _frame) -> None:
        self.stopping = True

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        while not self.stopping:
            read = self.read_log()
            try:
                self.maybe_send(time.monotonic())
            except Exception:  # noqa: BLE001 - the Web UI is secondary
                self.unsent += 1
            if not read:
                time.sleep(POLL_INTERVAL)
        with contextlib.suppress(Exception):
            self.maybe_send(time.monotonic() + HEARTBEAT_INTERVAL)
        self.follower.close()
        return 0


def self_check() -> int:
    """Checks the parsers on lines in the Connector's formats; used when the image is built."""
    problems = []
    if parse_state("State: Online") != "Online" or parse_state("[INFO] [connector] State: Online") is not None:
        problems.append("state")
    warning = parse_problem("[WARN] [libsdwan] [controller] operator(): failed to get public keys: DNS resolve error (-4), code -1")
    if not warning or warning["level"] != "warning" or warning["source"] != "libsdwan controller":
        problems.append(f"warning: {warning}")
    stamped = parse_problem("[2026-11-22T22:52:36.156843+00:00] [ERROR] [connector] something failed 12345")
    if not stamped or stamped["level"] != "error" or not stamped["key"].endswith("something failed #"):
        problems.append(f"error: {stamped}")
    if parse_problem("[INFO] [connector] State: Online") is not None:
        problems.append("info line taken as a problem")
    masked = {
        "peer 192.0.2.10:443 and 10.1.2.3 failed.": "peer [IP] and [IP] failed.",
        "relay [2001:db8::1]:8443 and fe80::1%eth0, ::ffff:192.0.2.1": "relay [IP] and [IP], [IP]",
        "user alice.smith+home@example.co.uk denied": "user [email] denied",
        "at 22:52:36, MAC 00:11:22:33:44:55, version 0.199.0, std::string": "at 22:52:36, MAC 00:11:22:33:44:55, version 0.199.0, std::string",
    }
    for text, expected in masked.items():
        if mask_personal(text) != expected:
            problems.append(f"masking: {mask_personal(text)!r}")
    leaked = parse_problem("[WARN] [libsdwan] [192.0.2.7] connection from 198.51.100.23:5000 by bob@example.com refused")
    if not leaked or any(value in json.dumps(leaked) for value in ("192.0.2.7", "198.51.100.23", "bob@example.com")):
        problems.append(f"problem keeps personal data: {leaked}")
    when, rest = split_timestamp(b"@400000006b03a2852c89c0c2 hello")
    if rest != b"hello" or when is None or abs(when - 1795400288.747) > 0.01:
        problems.append(f"timestamp: {when} {rest!r}")
    line = (
        b'{"connection": {"cbct_freshness": -97, "client_ip": "192.0.2.10", "duration": 3034753, '
        b'"id": "e755ba99988db558-24", "protocol": "tcp", "resource_ip": "10.0.0.5", "resource_port": 443, '
        b'"rx": 234867, "tunnel_path": "direct", "tunnel_proto": "quic/udp", "tx": 23363}, '
        b'"connector": {"id": "84014", "name": "nondescript-caterpillar"}, "device": {"id": "200903"}, '
        b'"event_type": "closed_connection", "location": "{\\"geoip\\":{\\"city\\":\\"Seattle\\",\\"country\\":\\"US\\",'
        b'\\"lat\\":47.6062,\\"lon\\":-122.3321,\\"region\\":\\"WA\\"}}", "relays": [], '
        b'"remote_network": {"id": "6938", "name": "AWS Network"}, "resource": {"address": "app.website.com", '
        b'"applied_rule": "*.website.com", "id": "2255492"}, "timestamp": 1698356150045, '
        b'"user": {"email": "user@example.com", "id": "113256"}}'
    )
    event = parse_analytics(line)
    expected = {"id": "e755ba99988db558-24", "event": "closed_connection", "user": "user@example.com", "port": 443, "rx": 234867, "location": "Seattle, WA, US"}
    if event is None or any(event.get(key) != value for key, value in expected.items()):
        problems.append(f"analytics: {event}")
    if event is not None and (b"192.0.2.10" in json.dumps(event).encode() or b"47.6062" in json.dumps(event).encode() or b"200903" in json.dumps(event).encode()):
        problems.append("analytics summary keeps the client IP, coordinates or device ID")
    connections = Connections()
    opened = dict(event or {}, event="established_connection", t=1698356100.0, rx=None, tx=None)
    connections.add(opened)
    connections.add(dict(event or {}, t=1698356150.045))
    item = connections.items.get("e755ba99988db558-24", {})
    if item.get("result") != "closed" or item.get("ms") != 50045.0:
        problems.append(f"connection merge: {item}")
    if problems:
        print(f"self check failed: {problems}", file=sys.stderr)
        return 1
    print("log_relay: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return self_check()
    return Relay(saved_state="--no-saved-state" not in argv, from_end="--from-end" in argv).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
