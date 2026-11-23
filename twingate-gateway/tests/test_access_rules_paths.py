"""Request paths, log masking and the cross-site check (access_rules)."""

import unittest

from support import access_rules

# Raw request paths (as sent, before decoding) and the path the rules check:
# decoded once, as Home Assistant routes it.
ACCEPTED_PATHS = (
    ("/", "/"),
    ("/api/", "/api/"),
    ("/api/states", "/api/states"),
    ("/api/states/sensor.outside_temperature", "/api/states/sensor.outside_temperature"),
    ("/api/history/period/2026-11-23T00:00:00+00:00", "/api/history/period/2026-11-23T00:00:00+00:00"),
    ("/api/webhook/Abc-123_x", "/api/webhook/Abc-123_x"),
    # Decoded once: the rules see the domain Home Assistant sees.
    ("/api/services/%68assio/host_reboot", "/api/services/hassio/host_reboot"),
    ("/api/st%61tes", "/api/states"),
    ("/api/states/sensor.caf%C3%A9", "/api/states/sensor.caf\xe9"),
    ("/api/services/%20hassio/x", "/api/services/ hassio/x"),
    # Dots that are not a whole segment are names.
    ("/api/states/...", "/api/states/..."),
    ("/api/states/.hidden", "/api/states/.hidden"),
    ("/api/" + "a" * 2043, "/api/" + "a" * 2043),
)

# Raw request paths that are refused (400) instead of being matched.
REFUSED_PATHS = (
    # Encoded query and fragment separators (%3f, %23).
    "/api/states%3fx",
    "/api/states%3Fx",
    "/api/services/light%3F/turn_on",
    "/api/states%23x",
    "/api/hassio%23",
    # Encoded slashes and backslashes (%2f, %5c).
    "/api/services/hassio%2Fhost_reboot",
    "/api/services%2fhassio/host_reboot",
    "/api/mcp%2Fassist",
    "/api/states%5cx",
    "/api/states%5Cx",
    # Encoded percent signs (%25): double encoding.
    "/api/%2568assio/x",
    "/api/states%25",
    "/api/%252e%252e/hassio",
    # Encoded dots (%2e), also inside a name.
    "/api/%2e%2e/hassio",
    "/api/states/%2E",
    "/api/states/sensor%2Ex",
    # Encoded NUL and other control characters.
    "/api/states%00",
    "/api/states%0a",
    "/api/states%0D",
    "/api/states%09",
    "/api/states%7f",
    # Dot segments.
    "/api/../hassio",
    "/api/./states",
    "/api/states/..",
    "/api/states/.",
    "/..",
    "/api/x/..%2fhassio",
    # Empty segments.
    "//api/states",
    "/api//states",
    "/api/states//",
    "//",
    # Characters that are not sent unencoded in a path.
    "/api\\states",
    "/api/states?x=1",
    "/api/states#x",
    "/api/sta tes",
    "/api/states/caf\xe9",
    "/api/states\n",
    # Broken escapes and escapes that are not UTF-8.
    "/api/x%",
    "/api/x%4",
    "/api/x%zz",
    "/api/x%%41",
    "/api/states/%ff",
    "/api/states/%c3%28",
    # Not a path.
    "",
    "api/states",
    "*",
    "http://example.com/api/states",
    # Longer than 2048 characters.
    "/api/" + "a" * 2044,
)


class CanonicalPathTest(unittest.TestCase):
    def test_accepted_paths_are_decoded_once(self) -> None:
        for raw, expected in ACCEPTED_PATHS:
            with self.subTest(raw=raw[:80]):
                self.assertEqual(access_rules.canonical_path(raw), expected)

    def test_unclear_paths_are_refused(self) -> None:
        for raw in REFUSED_PATHS:
            with self.subTest(raw=raw[:80]):
                self.assertIsNone(access_rules.canonical_path(raw))

    def test_not_text_is_refused(self) -> None:
        for raw in (None, b"/api/states", 5):
            with self.subTest(raw=raw):
                self.assertIsNone(access_rules.canonical_path(raw))


class MaskPathTest(unittest.TestCase):
    """The webhook ID is masked in logs: anyone who knows it can trigger the webhook."""

    CASES = (
        ("/api/webhook/secret-id", "/api/webhook/***"),
        ("/api/webhook/secret-id/more", "/api/webhook/***"),
        ("/API/Webhook/secret-id", "/API/Webhook/***"),
        ("//api/webhook/secret-id", "//api/webhook/***"),
        ("/api/webhook/", "/api/webhook/***"),
        ("/api/webhook", "/api/webhook"),
        ("/api/states", "/api/states"),
    )

    def test_mask_path(self) -> None:
        for path, expected in self.CASES:
            with self.subTest(path=path):
                self.assertEqual(access_rules.mask_path(path), expected)


# (Origin, Sec-Fetch-Site, Host, whether the request comes from a web page of
# another site)
CROSS_SITE_CASES = (
    # Scripts and agents send neither header.
    (None, None, "ha-api.int", False),
    (None, None, None, False),
    # Sec-Fetch-Site: only same-origin and none (typed or bookmarked) pass.
    (None, "same-origin", "ha-api.int", False),
    (None, "none", "ha-api.int", False),
    (None, " Same-Origin ", "ha-api.int", False),
    (None, "same-site", "ha-api.int", True),
    (None, "cross-site", "ha-api.int", True),
    (None, "", "ha-api.int", True),
    ("http://ha-api.int", "cross-site", "ha-api.int", True),
    # Origin: the address the request was sent to, with case and default
    # ports ignored; the request reached the Gateway over plain HTTP or TLS,
    # so either default port matches.
    ("http://ha-api.int", None, "ha-api.int", False),
    ("https://ha-api.int", "same-origin", "ha-api.int", False),
    ("HTTPS://HA-API.int:443", None, "ha-api.int", False),
    ("http://ha-api.int:80", None, "ha-api.int:80", False),
    ("http://ha-api.int:443", None, "ha-api.int", False),
    ("http://ha-api.int/", None, "ha-api.int", False),
    ("http://ha-api.int:8080", None, "ha-api.int:8080", False),
    ("http://[::1]:8124", None, "[::1]:8124", False),
    ("http://[::1]", None, "[::1]", False),
    # Any other Origin is another site.
    ("http://ha-api.int:8080", None, "ha-api.int", True),
    ("https://evil.example", None, "ha-api.int", True),
    ("http://ha-api.int.evil.example", None, "ha-api.int", True),
    ("http://ha-api.int", None, "evil.example", True),
    ("http://ha-api.int", "same-origin", "evil.example", True),
    ("http://ha-api.int", None, None, True),
    ("http://ha-api.int", None, "", True),
    ("http://user@ha-api.int", None, "ha-api.int", True),
    ("http://ha-api.int:abc", None, "ha-api.int", True),
    ("http://ha-api.int/path", None, "ha-api.int", True),
    ("null", None, "ha-api.int", True),
    ("", None, "ha-api.int", True),
    ("file://", None, "ha-api.int", True),
    ("chrome-extension://abcdef", None, "ha-api.int", True),
    ("ws://ha-api.int", None, "ha-api.int", True),
)


class CrossSiteTest(unittest.TestCase):
    def test_cross_site_browser_request(self) -> None:
        for origin, fetch_site, host, expected in CROSS_SITE_CASES:
            with self.subTest(origin=origin, fetch_site=fetch_site, host=host):
                self.assertIs(access_rules.cross_site_browser_request(origin, fetch_site, host), expected)


if __name__ == "__main__":
    unittest.main()
