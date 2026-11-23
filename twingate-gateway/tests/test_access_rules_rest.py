"""REST decisions per grant (access_rules.decide_rest).

The tables below are the REST access policy: a change to what a grant
allows must change them.
"""

import unittest

from support import GRANTS, access_rules

ALL_GRANTS = tuple(GRANTS)
ALLOWED_REASONS = ("read", "mcp", "full")

# The Read allow-list, entry by entry: (method, pattern). HEAD is allowed
# wherever GET is.
EXPECTED_READ_REST = (
    ("GET", r"/api/"),
    ("GET", r"/api/config"),
    ("GET", r"/api/core/state"),
    ("GET", r"/api/components"),
    ("GET", r"/api/states"),
    ("GET", r"/api/states/[^/]+"),
    ("GET", r"/api/services"),
    ("GET", r"/api/events"),
    ("GET", r"/api/history/period(?:/[^/]+)?"),
    ("GET", r"/api/logbook(?:/[^/]+)?"),
    ("GET", r"/api/calendars"),
    ("GET", r"/api/calendars/[^/]+"),
    ("GET", r"/api/config/config_entries/entry"),
)

# One or more paths for each entry of the allow-list.
READ_PATHS = (
    "/api/",
    "/api/config",
    "/api/core/state",
    "/api/components",
    "/api/states",
    "/api/states/sensor.outside_temperature",
    "/api/services",
    "/api/events",
    "/api/history/period",
    "/api/history/period/2026-11-23T00:00:00+00:00",
    "/api/logbook",
    "/api/logbook/2026-11-23T00:00:00+00:00",
    "/api/calendars",
    "/api/calendars/calendar.family",
    "/api/config/config_entries/entry",
)

# Blocked for every caller, Full included, whatever the method.
ALWAYS_BLOCKED_PATHS = (
    # Core's proxies into the Supervisor, its ingress proxy and Supervisor
    # login endpoints.
    "/api/hassio",
    "/api/hassio/",
    "/api/hassio/supervisor/info",
    "/api/hassio/host/reboot",
    "/api/hassio/addons/core_ssh/start",
    "/api/hassio/backups/new/full",
    "/api/hassio_ingress/abc123/",
    "/api/hassio_auth",
    "/api/hassio_auth/password_reset",
    "/api/hassio_push/discovery/abc",
    "/api/hassio_anything",
    "/API/HASSIO/host/reboot",
    "/api/HassIO_Ingress/abc123/",
    # Backups: download and upload.
    "/api/backup",
    "/api/backup/",
    "/api/backup/download/abc123",
    "/api/backup/upload",
    "/API/Backup/download/abc123",
    # Onboarding: the owner account and restores.
    "/api/onboarding",
    "/api/onboarding/users",
    "/api/onboarding/backup/restore",
    "/api/Onboarding/users",
    # Repair flows.
    "/api/repairs/issues/fix",
    "/api/repairs/issues/fix/0123abcd",
    "/API/Repairs/Issues/Fix",
    # Actions of the hassio and backup domains, with any case and spaces.
    "/api/services/hassio/host_reboot",
    "/api/services/hassio/host_shutdown",
    "/api/services/hassio/addon_stop",
    "/api/services/hassio/backup_full",
    "/api/services/hassio/restore_full",
    "/api/services/backup/create",
    "/api/services/backup/create_automatic",
    "/api/services/HASSIO/host_reboot",
    "/api/services/Backup/create",
    "/api/services/ hassio /host_reboot",
    "/api/services/hassio",
    "/api/services/hassio/",
    "/api/services/hassio/host_reboot/more",
    "/API/SERVICES/HASSIO/HOST_REBOOT",
)

# (grant, method, path, expected reason); the request is allowed when the
# reason is read, mcp or full.
REST_CASES = (
    # Read: default deny for everything not on the allow-list.
    ("read", "POST", "/api/services/light/turn_on", "denied"),
    ("read", "POST", "/api/services/homeassistant/restart", "denied"),
    ("read", "POST", "/api/template", "denied"),
    ("read", "POST", "/api/events/my_event", "denied"),
    ("read", "POST", "/api/states/sensor.x", "denied"),
    ("read", "DELETE", "/api/states/sensor.x", "denied"),
    ("read", "POST", "/api/config/core/check_config", "denied"),
    ("read", "POST", "/api/config/config_entries/flow", "denied"),
    ("read", "DELETE", "/api/config/config_entries/entry/0123abcd", "denied"),
    ("read", "GET", "/api/config/config_entries/entry/0123abcd", "denied"),
    ("read", "POST", "/api/intent/handle", "denied"),
    ("read", "POST", "/api/conversation/process", "denied"),
    ("read", "GET", "/api/error_log", "denied"),
    ("read", "GET", "/api/camera_proxy/camera.front_door", "denied"),
    ("read", "GET", "/api/websocket", "denied"),
    ("read", "GET", "/api/webhook/abc", "denied"),
    ("read", "POST", "/api/webhook/abc", "denied"),
    ("read", "GET", "/api/unknown", "denied"),
    ("read", "GET", "/api", "denied"),
    ("read", "GET", "/api/configx", "denied"),
    ("read", "GET", "/api/config/", "denied"),
    ("read", "GET", "/api/states/", "denied"),
    ("read", "GET", "/api/states/sensor.x/attributes", "denied"),
    ("read", "GET", "/api/history/period/a/b", "denied"),
    ("read", "GET", "/api/logbook/a/b", "denied"),
    ("read", "GET", "/api/calendars/", "denied"),
    # The allow-list matches exactly, with case.
    ("read", "GET", "/API/STATES", "denied"),
    ("read", "GET", "/api/States", "denied"),
    ("read", "PUT", "/api/states", "denied"),
    ("read", "PATCH", "/api/states/sensor.x", "denied"),
    ("read", "OPTIONS", "/api/states", "denied"),
    # No grant: nothing.
    ("none", "GET", "/api/", "denied"),
    ("none", "GET", "/api/states", "denied"),
    ("none", "POST", "/api/mcp", "denied"),
    # MCP: the endpoint /api/mcp with every method, nothing else.
    ("mcp", "POST", "/api/mcp", "mcp"),
    ("mcp", "GET", "/api/mcp", "mcp"),
    ("mcp", "DELETE", "/api/mcp", "mcp"),
    ("read+mcp", "POST", "/api/mcp", "mcp"),
    ("full", "POST", "/api/mcp", "mcp"),
    ("read", "POST", "/api/mcp", "denied"),
    ("read", "GET", "/api/mcp", "denied"),
    ("mcp", "GET", "/api/", "denied"),
    ("mcp", "GET", "/api/states", "denied"),
    ("mcp", "POST", "/api/services/light/turn_on", "denied"),
    # The per-API endpoints /api/mcp/<id> need Full (DOCS.md: they would let
    # MCP callers bypass the main URL's settings).
    ("mcp", "POST", "/api/mcp/assist", "denied"),
    ("read+mcp", "POST", "/api/mcp/assist", "denied"),
    ("mcp", "POST", "/api/mcp/", "denied"),
    ("full", "POST", "/api/mcp/assist", "full"),
    # Read and MCP together: each its own requests.
    ("read+mcp", "GET", "/api/states", "read"),
    ("read+mcp", "POST", "/api/services/light/turn_on", "denied"),
    # Full: everything that is not always blocked.
    ("full", "POST", "/api/services/light/turn_on", "full"),
    ("full", "POST", "/api/services/homeassistant/restart", "full"),
    ("full", "POST", "/api/template", "full"),
    ("full", "POST", "/api/events/my_event", "full"),
    ("full", "DELETE", "/api/states/sensor.x", "full"),
    ("full", "GET", "/api/error_log", "full"),
    ("full", "POST", "/api/config/config_entries/flow", "full"),
    ("full", "POST", "/api/webhook/abc", "full"),
    ("full", "GET", "/api/unknown", "full"),
)

# Raw paths through the proxy's two steps: canonical_path(), then
# decide_rest(); "unclear" is the 400 answer for a path that could be read
# in more than one way.
RAW_CASES = (
    ("full", "POST", "/api/services/%68assio/host_reboot", "blocked"),
    ("full", "GET", "/api/%68assio/supervisor/info", "blocked"),
    ("full", "GET", "/api/%62ackup/download/x", "blocked"),
    ("full", "POST", "/api/services/hassio%2Fhost_reboot", "unclear"),
    ("full", "POST", "/api/services%2Fhassio/host_reboot", "unclear"),
    ("full", "GET", "/api/hassio%3f", "unclear"),
    ("full", "GET", "/api/hassio%23", "unclear"),
    ("full", "GET", "/api/%2568assio/x", "unclear"),
    ("full", "GET", "/api/states/../hassio/x", "unclear"),
    ("full", "GET", "/api/x/..%2fhassio", "unclear"),
    ("full", "GET", "/api/%2e%2e/hassio", "unclear"),
    ("full", "GET", "//api/hassio", "unclear"),
    ("full", "GET", "/api//hassio", "unclear"),
    ("mcp", "POST", "/api/mcp%2Fassist", "unclear"),
    ("mcp", "POST", "/api/%6Dcp", "mcp"),
    ("read", "GET", "/api/st%61tes", "read"),
    ("read", "GET", "/api/states%3f", "unclear"),
    ("full", "POST", "/api/services/light/turn_on", "full"),
)


def decide_raw(method: str, raw_path: str, grants: frozenset) -> str:
    path = access_rules.canonical_path(raw_path)
    if path is None:
        return "unclear"
    return access_rules.decide_rest(method, path, grants)[1]


class RestPolicyTest(unittest.TestCase):
    def assert_decision(self, grant: str, method: str, path: str, reason: str) -> None:
        self.assertEqual(
            access_rules.decide_rest(method, path, GRANTS[grant]),
            (reason in ALLOWED_REASONS, reason),
            f"{grant} {method} {path}",
        )

    def test_read_allow_list_is_as_documented(self) -> None:
        self.assertEqual(tuple((method, pattern.pattern) for method, pattern in access_rules.READ_REST), EXPECTED_READ_REST)

    def test_every_read_allow_list_entry(self) -> None:
        for path in READ_PATHS:
            with self.subTest(path=path):
                self.assert_decision("read", "GET", path, "read")
                self.assert_decision("read", "HEAD", path, "read")
                self.assert_decision("read+mcp", "GET", path, "read")
                self.assert_decision("full", "GET", path, "full")
                # Changing requests on the same paths are not reads.
                self.assert_decision("read", "POST", path, "denied")
                self.assert_decision("read", "DELETE", path, "denied")
                # MCP alone, and no grant, give no reads.
                self.assert_decision("mcp", "GET", path, "denied")
                self.assert_decision("none", "GET", path, "denied")

    def test_every_allow_list_entry_has_an_example(self) -> None:
        for method, pattern in access_rules.READ_REST:
            with self.subTest(pattern=pattern.pattern):
                self.assertTrue(any(pattern.fullmatch(path) for path in READ_PATHS))
                self.assertEqual(method, "GET")

    def test_always_blocked_for_every_grant(self) -> None:
        for path in ALWAYS_BLOCKED_PATHS:
            for grant in ALL_GRANTS:
                for method in ("GET", "HEAD", "POST", "DELETE"):
                    with self.subTest(path=path, grant=grant, method=method):
                        self.assert_decision(grant, method, path, "blocked")

    def test_rest_cases(self) -> None:
        for grant, method, path, reason in REST_CASES:
            with self.subTest(grant=grant, method=method, path=path):
                self.assert_decision(grant, method, path, reason)

    def test_raw_paths(self) -> None:
        for grant, method, raw_path, reason in RAW_CASES:
            with self.subTest(grant=grant, method=method, raw_path=raw_path):
                self.assertEqual(decide_raw(method, raw_path, GRANTS[grant]), reason)

    def test_blocked_service_domains(self) -> None:
        self.assertEqual(access_rules.BLOCKED_SERVICE_DOMAINS, frozenset({"hassio", "backup"}))
        cases = (
            ("hassio", True),
            ("HASSIO", True),
            (" Backup\t", True),
            ("light", False),
            ("hassio_x", False),
            ("", False),
            # A domain that is not text cannot be checked: blocked.
            (None, True),
            (["hassio"], True),
            (5, True),
        )
        for domain, blocked in cases:
            with self.subTest(domain=domain):
                self.assertIs(access_rules.blocked_service_domain(domain), blocked)


if __name__ == "__main__":
    unittest.main()
