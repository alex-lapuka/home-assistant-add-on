"""Audit log relay of the Twingate Gateway add-on.

Runs as the s6 service twingate-gateway-relay and only reads files; the
Gateway never waits for it. With the add-on option audit_log: addon_log, the
Gateway writes its audit log to its standard output, and s6-log (the
twingate-gateway-log service) copies every line to the add-on log and to a
small logdir in memory, /dev/shm/twingate-gateway-audit. The relay follows
the file current in that logdir, and reports to the Web UI when the copy is
not kept (the logdir is missing or was not made by s6-log's run script, which
then copies to the add-on log only) or when /dev/shm has no space left for
it. With audit_log: file, the Gateway writes the audit log to
/config/audit.log itself and the relay follows that file. Both are rotated by
renaming, which the relay follows. When the relay starts, it reads the end of
the file again; the Web UI recognizes entries it already has by their
request ID.

For each audit entry the relay keeps, in memory only, a summary without
headers, query string, host or client address: time, Twingate user name,
method, path, status and duration. The ID in a Home Assistant webhook path
(/api/webhook/<id>) is masked, because anyone who knows it can trigger the
webhook. It sends the newest summaries to the Web UI over a Unix datagram
socket. Sending never blocks: if the Web UI is not running or not reading,
the summaries are dropped for the Web UI only. An error in one task (a
summary, the status file, the audit log file, sending to the Web UI) is
logged and skipped instead of stopping the relay.

Python standard library only.
"""

from __future__ import annotations

import collections
import contextlib
import errno
import grp
import json
import os
import pwd
import re
import signal
import socket
import stat
import sys
import tempfile
import time
from datetime import datetime
from urllib.parse import unquote, urlsplit

STATUS_FILE = "/run/twingate-gateway/status.json"
UI_SOCKET = "/run/twingate-gateway-ui/audit.sock"
# The logdir s6-log keeps the copy of the audit log in with audit_log:
# addon_log, and the owner, group and mode its run script gives it.
COPY_DIR = "/dev/shm/twingate-gateway-audit"
COPY_OWNER = "audit-log"
COPY_GROUP = "audit-relay"
COPY_MODE = 0o2750
AUDIT_COPY = COPY_DIR + "/current"
# With less free space in /dev/shm, new entries may be missing from the copy.
COPY_MIN_FREE_BYTES = 64 * 1024

MAX_RECORDS = 100
MAX_LINE_BYTES = 1024 * 1024
MAX_PATH_CHARS = 512
MAX_USER_CHARS = 200
MAX_DATAGRAM_BYTES = 120_000
FILE_BACKFILL_BYTES = 512 * 1024
FILE_READ_BYTES = 256 * 1024
FILE_READS_PER_POLL = 4
LOOP_INTERVAL = 0.5
SEND_INTERVAL = 0.5
HEARTBEAT_INTERVAL = 5.0
STATUS_POLL_INTERVAL = 2.0
ERROR_LOG_INTERVAL = 60.0

WEBHOOK_PREFIX = "/api/webhook/"
WEBHOOK_MASK = "***"

_REQUEST_ID = re.compile(r"[0-9A-Za-z-]{1,64}")
_METHOD = re.compile(r"[A-Z]{1,16}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")


def parse_time(value: object) -> float | None:
    """Parses a zap ISO 8601 time such as 2026-11-23T10:00:00.123+0100."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except ValueError:
            return None


def printable(value: str) -> str:
    """Replaces control, format (such as bidi overrides) and line-separator characters with "?"."""
    return "".join(char if char.isprintable() else "?" for char in value)


def mask_path(path: str) -> str:
    """Masks the webhook ID in a path such as /api/webhook/<id>.

    The path is compared after percent-decoding and ignoring case, as a
    request for /api/%77ebhook/<id> also reaches the webhook. Everything after
    the prefix is masked; Home Assistant has no webhook paths below the ID.
    """
    decoded = unquote(path)
    start = decoded.lower().find(WEBHOOK_PREFIX)
    if start < 0:
        return path
    return decoded[: start + len(WEBHOOK_PREFIX)] + WEBHOOK_MASK


def summarize(line: bytes) -> dict | None:
    """Returns the summary of one Gateway audit log line, or None.

    Only the fields below are copied. Request and response headers, the query
    string, the host part of the URL, the client address and the connection
    are never read into the summary, and a webhook ID in the path is masked.
    """
    if b'"audit"' not in line:
        return None
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(entry, dict) or entry.get("logger") != "audit":
        return None

    url = entry.get("url")
    path = ""
    has_query = False
    if isinstance(url, str):
        try:
            # The URL is usually a path. Given to urlsplit as it is, a path
            # that starts with // would be read as a host name.
            parts = urlsplit("http://gateway" + url if url.startswith("/") else url)
            path = parts.path
            has_query = bool(parts.query or parts.fragment)
        except ValueError:
            path = ""
    path = printable(mask_path(path))
    truncated = len(path) > MAX_PATH_CHARS
    path = path[:MAX_PATH_CHARS]

    user = entry.get("user")
    username = ""
    if isinstance(user, dict) and isinstance(user.get("username"), str):
        username = printable(user["username"][:MAX_USER_CHARS])

    method = entry.get("method")
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        method = "?"

    status = 0
    response = entry.get("response")
    if isinstance(response, dict):
        code = response.get("status_code")
        if isinstance(code, int) and 0 <= code <= 999:
            status = code

    started = parse_time(entry.get("requested_at"))
    finished = parse_time(entry.get("ts"))
    duration = None
    if started is not None and finished is not None:
        duration = max(0.0, round((finished - started) * 1000.0, 1))
    when = started if started is not None else finished
    if when is None:
        return None

    request_id = entry.get("request_id")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        request_id = f"{when:.6f}-{method}-{status}"

    summary = {
        "id": request_id,
        "t": round(when, 3),
        "user": username,
        "method": method,
        "path": path,
        "q": has_query,
        "status": status,
        "ms": duration,
        "err": entry.get("levelname") == "error",
    }
    if truncated:
        summary["pt"] = True
    version = entry.get("version")
    if isinstance(version, str) and _VERSION.fullmatch(version):
        summary["v"] = version
    return summary


def copy_state(directory: str, owner: int | None, group: int | None) -> str:
    """Whether s6-log keeps the copy of the audit log: "ok", "not kept" or "no space".

    s6-log's run script makes the logdir in /dev/shm, which every user can
    write to, with the owner, group and mode checked here. It removes the
    logdir when s6-log copies to the add-on log only, and does not use one
    that someone else made: the relay does not read such a logdir either.
    When /dev/shm has (almost) no space left, s6-log cannot write new entries
    to the copy and keeps them in memory until it can.
    """
    try:
        info = os.lstat(directory)
        space = os.statvfs(directory)
    except OSError:
        return "not kept"
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner
        or info.st_gid != group
        or stat.S_IMODE(info.st_mode) != COPY_MODE
    ):
        return "not kept"
    if space.f_bavail * space.f_frsize < COPY_MIN_FREE_BYTES:
        return "no space"
    return "ok"


def copy_ids() -> tuple[int | None, int | None]:
    """The user and group IDs of the copy's owner and group, None if unknown."""
    try:
        owner = pwd.getpwnam(COPY_OWNER).pw_uid
    except KeyError:
        owner = None
    try:
        group = grp.getgrnam(COPY_GROUP).gr_gid
    except KeyError:
        group = None
    return owner, group


class FileTail:
    """Follows a log file that is rotated by renaming, as s6-log and the Gateway do.

    A file is read from near its end (FILE_BACKFILL_BYTES) when it is
    opened, and from the start when it replaces the file being read after a
    rotation.
    """

    def __init__(self) -> None:
        self.path: str | None = None
        self.handle = None
        self.inode: int | None = None
        self.pending = bytearray()
        self.skip_partial = False
        self.state = "not used"

    def close(self) -> None:
        if self.handle is not None:
            with contextlib.suppress(OSError):
                self.handle.close()
        self.handle = None
        self.inode = None
        self.pending.clear()

    def poll(self, path: str | None, on_line) -> None:
        if path != self.path:
            self.close()
            self.path = path
            self.state = "not used" if path is None else "waiting for the file"
        if path is None:
            return
        try:
            if self.handle is None:
                self._open(path, backfill=True)
                if self.handle is None:
                    return
            if not self._read(on_line, FILE_READS_PER_POLL):
                return
            # At the end of the open file: follow a rotation or truncation.
            try:
                current = os.stat(path)
            except FileNotFoundError:
                # Between renaming the file and creating the next one; the
                # next poll looks again.
                return
            if current.st_ino != self.inode:
                # The writer renames the file only after its last write to
                # it, so whatever was added since the read above is complete:
                # read it before moving on to the new file.
                self._read(on_line, None)
                self.close()
                self._open(path, backfill=False)
            elif current.st_size < self.handle.tell():
                self.handle.seek(0)
                self.pending.clear()
        except OSError as error:
            self.close()
            self.state = f"cannot read the file ({errno.errorcode.get(error.errno, 'error')})"

    def _read(self, on_line, limit: int | None) -> bool:
        """Reads at most limit chunks (None: no limit); True at the end of the file."""
        count = 0
        while limit is None or count < limit:
            data = self.handle.read(FILE_READ_BYTES)
            if not data:
                return True
            self._feed(data, on_line)
            count += 1
        return False

    def _open(self, path: str, backfill: bool) -> None:
        try:
            handle = open(path, "rb")  # noqa: SIM115
        except FileNotFoundError:
            self.state = "waiting for the file"
            return
        info = os.fstat(handle.fileno())
        self.skip_partial = False
        if backfill and info.st_size > FILE_BACKFILL_BYTES:
            handle.seek(info.st_size - FILE_BACKFILL_BYTES)
            self.skip_partial = True
        self.handle = handle
        self.inode = info.st_ino
        self.pending.clear()
        self.state = "reading"

    def _feed(self, data: bytes, on_line) -> None:
        self.pending += data
        while True:
            end = self.pending.find(b"\n")
            if end < 0:
                break
            line = bytes(self.pending[:end])
            del self.pending[: end + 1]
            if self.skip_partial:
                self.skip_partial = False
                continue
            on_line(line)
        if len(self.pending) > MAX_LINE_BYTES:
            self.pending.clear()
            self.skip_partial = True


class Relay:
    def __init__(self) -> None:
        self.records: collections.OrderedDict[str, dict] = collections.OrderedDict()
        self.changed = False
        self.last_send = 0.0
        self.last_heartbeat = 0.0
        self.last_status_poll = -STATUS_POLL_INTERVAL
        self.status_mtime: float | None = None
        # The audit log file with audit_log: file; None means the copy that
        # s6-log writes (AUDIT_COPY).
        self.audit_file: str | None = None
        self.copy_owner, self.copy_group = copy_ids()
        # See copy_state(); None with audit_log: file.
        self.copy_state: str | None = None
        self.last_copy_check = -STATUS_POLL_INTERVAL
        self.stopping = False
        self.tail = FileTail()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        with contextlib.suppress(OSError):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        self.stats = {
            "started_at": round(time.time(), 3),
            "entries": 0,
            "last_entry_at": None,
            "unsent": 0,
        }
        self.errors = 0
        self.last_error_log = -ERROR_LOG_INTERVAL

    def guarded(self, task: str, function, *args) -> None:
        """Runs a task that must not stop the relay; errors are logged and skipped.

        Only the type of the error is logged, never its message, which could
        quote an audit entry.
        """
        try:
            function(*args)
        except Exception as error:  # noqa: BLE001 - the relay must go on
            self.errors += 1
            now = time.monotonic()
            if now - self.last_error_log >= ERROR_LOG_INTERVAL:
                self.last_error_log = now
                with contextlib.suppress(OSError, ValueError):
                    sys.stderr.write(f"Audit relay: {task} failed ({type(error).__name__}); {self.errors} errors so far.\n")
                    sys.stderr.flush()

    # -- input ---------------------------------------------------------------

    def add_line(self, line: bytes) -> None:
        self.guarded("summarizing an audit entry", self._add_line, line)

    def _add_line(self, line: bytes) -> None:
        summary = summarize(line)
        if summary is None:
            return
        self.stats["entries"] += 1
        self.stats["last_entry_at"] = round(time.time(), 3)
        if summary["id"] in self.records:
            return
        self.records[summary["id"]] = summary
        while len(self.records) > MAX_RECORDS:
            self.records.popitem(last=False)
        self.changed = True

    def poll_status(self, now: float) -> None:
        if now - self.last_status_poll < STATUS_POLL_INTERVAL:
            return
        self.last_status_poll = now
        try:
            mtime = os.stat(STATUS_FILE).st_mtime
        except OSError:
            self.status_mtime = None
            self.audit_file = None
            return
        if mtime == self.status_mtime:
            return
        self.status_mtime = mtime
        self.audit_file = None
        try:
            with open(STATUS_FILE, encoding="utf-8") as handle:
                status = json.load(handle)
        except (OSError, ValueError):
            self.status_mtime = None
            return
        if isinstance(status, dict) and status.get("audit_log") == "file":
            path = status.get("audit_log_file")
            if isinstance(path, str) and path.startswith("/") and "\n" not in path:
                self.audit_file = path

    def check_copy(self, now: float) -> None:
        if now - self.last_copy_check < STATUS_POLL_INTERVAL:
            return
        self.last_copy_check = now
        state = None if self.audit_file else copy_state(COPY_DIR, self.copy_owner, self.copy_group)
        if state != self.copy_state:
            self.copy_state = state
            # Sent with the next snapshot, not only with the heartbeat.
            self.changed = True

    def poll_file(self) -> None:
        if self.audit_file:
            path = self.audit_file
        else:
            # A logdir that s6-log does not keep is not read.
            path = None if self.copy_state == "not kept" else AUDIT_COPY
        self.tail.poll(path, self.add_line)

    # -- output to the Web UI ------------------------------------------------

    def maybe_send(self, now: float) -> None:
        due = self.changed and now - self.last_send >= SEND_INTERVAL
        if not due and now - self.last_heartbeat < HEARTBEAT_INTERVAL:
            return
        records = list(self.records.values())
        relay = {
            "started_at": self.stats["started_at"],
            "entries": self.stats["entries"],
            "last_entry_at": self.stats["last_entry_at"],
            "unsent": self.stats["unsent"],
            "source": "file" if self.audit_file else "add-on log",
            "file_state": self.tail.state,
            "copy": None if self.audit_file else self.copy_state,
        }
        while True:
            payload = json.dumps(
                {"type": "snapshot", "relay": relay, "records": records},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(payload) <= MAX_DATAGRAM_BYTES or not records:
                break
            records = records[len(records) // 2 :]
        self.last_send = now
        self.last_heartbeat = now
        self.changed = False
        try:
            self.sock.sendto(payload, UI_SOCKET)
        except OSError:
            # The Web UI is not running, not reading, or restarting.
            self.stats["unsent"] += 1

    # -- main loop -----------------------------------------------------------

    def stop(self, _signum, _frame) -> None:
        self.stopping = True

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        while not self.stopping:
            now = time.monotonic()
            self.guarded("reading the status file", self.poll_status, now)
            self.guarded("checking the copy of the audit log", self.check_copy, now)
            self.guarded("reading the audit log", self.poll_file)
            self.guarded("sending to the Web UI", self.maybe_send, now)
            time.sleep(LOOP_INTERVAL)
        return 0


def self_check() -> int:
    """Checks the summaries and following a file; used when the image is built."""
    line = (
        b'{"levelname":"info","ts":"2026-01-01T00:00:01.250Z","logger":"audit",'
        b'"message":"API request completed","version":"2.1.0","request_id":"0f0e",'
        b'"requested_at":"2026-01-01T00:00:01.000Z","method":"GET",'
        b'"url":"/api/states?token=secret","proto":"HTTP/1.1","remote_addr":"10.0.0.1:1",'
        b'"user":{"id":"1","username":"user@example.com","groups":[]},"conn_id":"c",'
        b'"request":{"headers":{"Authorization":["secret"]}},'
        b'"response":{"status_code":200,"headers":{}}}'
    )
    summary = summarize(line)
    expected = {"path": "/api/states", "q": True, "status": 200, "ms": 250.0, "user": "user@example.com"}
    if summary is None or any(summary.get(key) != value for key, value in expected.items()):
        print(f"self check failed: {summary}", file=sys.stderr)
        return 1
    if b"secret" in json.dumps(summary).encode():
        print("self check failed: secret in summary", file=sys.stderr)
        return 1
    for url in ("/api/webhook/secret-id", "/api/webhook/secret-id?x=1", "/API/%77ebhook/secret-id/more", "//api/webhook/secret%2Fid"):
        webhook = summarize(line.replace(b"/api/states?token=secret", url.encode()))
        if webhook is None or "secret" in webhook["path"] or not webhook["path"].lower().endswith("/api/webhook/***"):
            print(f"self check failed: webhook ID not masked: {webhook}", file=sys.stderr)
            return 1
    relay = Relay()
    relay.add_line(b'["audit",' + b"[" * 100_000 + b"]" * 100_001)
    if relay.records:
        print("self check failed: deeply nested line", file=sys.stderr)
        return 1
    lines = check_file_tail()
    if lines != [b"one", b"two", b"three", b"four"]:
        print(f"self check failed: following a rotated file gave {lines}", file=sys.stderr)
        return 1
    states = check_copy_state()
    if states != ["ok", "not kept", "not kept", "not kept"]:
        print(f"self check failed: copy states {states}", file=sys.stderr)
        return 1
    odd = summarize(line.replace(b'"username":"user@example.com"', b'"username":"a\\u202eb\\u2028c\\u0085d"').replace(b"/api/states?", b"/api/x\\u202ey?"))
    if odd is None or odd["user"] != "a?b?c?d" or odd["path"] != "/api/x?y":
        print(f"self check failed: characters not replaced: {odd}", file=sys.stderr)
        return 1
    print("audit_relay: ok")
    return 0


def check_copy_state() -> list[str]:
    """The copy's state for a logdir as made by s6-log's run script, then three that are not."""
    with tempfile.TemporaryDirectory() as directory:
        os.chmod(directory, COPY_MODE)
        uid, gid = os.getuid(), os.getgid()
        states = [copy_state(directory, uid, gid), copy_state(directory, uid + 1, gid)]
        os.chmod(directory, 0o700)
        states.append(copy_state(directory, uid, gid))
        states.append(copy_state(os.path.join(directory, "missing"), uid, gid))
    return states


def check_file_tail() -> list[bytes]:
    """Follows a file across a partial line, a rotation and an overlong line."""
    lines: list[bytes] = []
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "current")
        tail = FileTail()
        with open(path, "wb") as handle:
            handle.write(b"one\ntw")
        tail.poll(path, lines.append)
        with open(path, "ab") as handle:
            handle.write(b"o\n")
        os.rename(path, os.path.join(directory, "@1.s"))
        with open(path, "wb") as handle:
            handle.write(b"three\n" + b"x" * (2 * MAX_LINE_BYTES) + b"\nfour\n")
        for _ in range(8):
            tail.poll(path, lines.append)
        tail.close()
    return lines


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return self_check()
    return Relay().run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
