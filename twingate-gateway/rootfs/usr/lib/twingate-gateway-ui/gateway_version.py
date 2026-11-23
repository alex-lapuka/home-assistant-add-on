"""Finds the version of the Twingate Gateway binary when the image is built.

    gateway_version.py --detect BINARY

prints the version of the Gateway binary, for example 2.1.0, or nothing when
it cannot be found out. It always exits 0, so that the image is built either
way; the Web UI then shows the version the Gateway reports in its audit log.

The Gateway has no version flag or endpoint. Every JSON line it logs carries
the version it was built with in the field "version", the same value as in
its audit log. (Twingate's release build sets it with -ldflags. The Go build
information in the binary does not contain it: the release is built with
-trimpath, which leaves the linker flags out, and the module version there is
a pseudo-version.) This script starts the Gateway with a throwaway
configuration, takes the version from its first log line and stops it.

Nothing leaves the build: the only requests the Gateway makes before it would
open its listener go to https://<network>.twingate.com through Go's standard
proxy settings, which point here to a port on the loopback interface where
nothing listens, so they fail at once. The configuration names CA files that
do not exist, so the Gateway stops with an error before it opens a port.

    gateway_version.py --check

tests the parser; used when the image is built. Python standard library only.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time

# The values the Web UI accepts for a Gateway version (as in gateway_ui.py).
VERSION_PATTERN = re.compile(r"[0-9A-Za-z.+-]{1,32}")
DETECT_SECONDS = 30.0
MAX_OUTPUT_BYTES = 1024 * 1024
UNREACHABLE_PROXY = "http://127.0.0.1:9"

# A complete configuration for a Web App Gateway that cannot start: the CA
# files do not exist. The system log at debug level writes a first line right
# after the configuration is loaded.
CONFIG = {
    "twingate": {"network": "build"},
    "port": 8443,
    "log": {
        "system": {"level": "debug", "output": {"stderr": {}}},
        "audit": {"output": {"stderr": {}}},
    },
    "tls": {
        "automation": {
            "issuer": {
                "local": {
                    "certificateFile": "/nonexistent/twingate-gateway-ca.crt",
                    "privateKeyFile": "/nonexistent/twingate-gateway-ca.key",
                }
            }
        }
    },
    "webApp": {},
}


def version_from_log_line(line: bytes) -> str | None:
    """The "version" field of a JSON log line of the Gateway, if it has one."""
    try:
        entry = json.loads(line)
    except (ValueError, RecursionError):
        return None
    version = entry.get("version") if isinstance(entry, dict) else None
    if isinstance(version, str) and VERSION_PATTERN.fullmatch(version):
        return version
    return None


def _first_version(process: subprocess.Popen, deadline: float) -> str | None:
    """Reads the Gateway's output until a line has its version."""
    buffer = b""
    received = 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                return None
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                return version_from_log_line(buffer) if buffer else None
            received += len(chunk)
            if received > MAX_OUTPUT_BYTES:
                return None
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                version = version_from_log_line(line)
                if version:
                    return version


def detect(binary: str, seconds: float = DETECT_SECONDS) -> str | None:
    """Starts the Gateway and returns the version from its first log line."""
    with tempfile.TemporaryDirectory(prefix="gateway-version-") as directory:
        config = os.path.join(directory, "config.json")
        with open(config, "w", encoding="utf-8") as handle:
            json.dump(CONFIG, handle)
        # Only these variables: Go sends HTTP and HTTPS requests through the
        # proxy, and the Gateway reads TWINGATE_* variables as settings.
        environment = {
            "PATH": "/usr/bin:/bin",
            "HTTPS_PROXY": UNREACHABLE_PROXY,
            "https_proxy": UNREACHABLE_PROXY,
            "HTTP_PROXY": UNREACHABLE_PROXY,
            "http_proxy": UNREACHABLE_PROXY,
            "NO_PROXY": "",
            "no_proxy": "",
        }
        process = subprocess.Popen(  # noqa: S603 - fixed arguments
            [binary, "start", "--config", config],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            cwd=directory,
        )
        try:
            return _first_version(process, time.monotonic() + seconds)
        finally:
            process.kill()
            process.wait()
            process.stdout.close()


def self_check() -> int:
    """Checks the parser with lines in the Gateway's format."""
    line = (
        b'{"levelname":"debug","ts":"2026-11-23T11:26:15.364Z","logger":"system",'
        b'"caller":"cmd/start.go:67","message":"Gateway start called","version":"2.1.0",'
        b'"config":{"config":"/tmp/config.json"}}'
    )
    cases = [
        (line, "2.1.0"),
        (b'{"version":"2.1.0-dev-68c4d81"}', "2.1.0-dev-68c4d81"),
        (b'{"version":"<b>"}', None),
        (b'{"version":2}', None),
        (b"Error: failed to create proxy", None),
        (b"[" * 100000, None),
    ]
    for value, expected in cases:
        if version_from_log_line(value) != expected:
            print(f"self check failed: {value[:60]!r}", file=sys.stderr)
            return 1
    print("gateway_version: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        return self_check()
    if len(argv) != 2 or argv[0] != "--detect":
        print("usage: gateway_version.py --detect BINARY | --check", file=sys.stderr)
        return 2
    # The image is built whether or not the version can be found out.
    try:
        version = detect(argv[1])
    except Exception as error:  # noqa: BLE001 - see above
        print(f"gateway_version: could not run {argv[1]}: {type(error).__name__}: {error}", file=sys.stderr)
        version = None
    if version is None:
        print("gateway_version: the Gateway logged no version; the Web UI shows the version from the audit log instead.", file=sys.stderr)
        return 0
    print(f"gateway_version: Twingate Gateway {version}", file=sys.stderr)
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
