"""Summaries of the Gateway's audit log for the Web UI (audit_relay.py).

Only the pure functions are tested: printable(), mask_path() and
summarize(). The relay's file following and sockets are not.
"""

import json
import unittest

from support import audit_relay


def entry(**changes: object) -> dict:
    """A Gateway audit log entry, as Twingate Gateway 2.x writes it."""
    value = {
        "levelname": "info",
        "ts": "2026-01-01T00:00:01.250Z",
        "logger": "audit",
        "message": "API request completed",
        "version": "2.1.0",
        "request_id": "0f0e",
        "requested_at": "2026-01-01T00:00:01.000Z",
        "method": "GET",
        "url": "/api/states?token=secret-query",
        "proto": "HTTP/1.1",
        "remote_addr": "192.0.2.1:54321",
        "user": {"id": "1", "username": "alice@example.com", "groups": ["Admins"]},
        "conn_id": "c",
        "request": {"headers": {"Authorization": ["Bearer secret-header"], "X-Twingate-Gateway-Token": ["secret-gat"]}},
        "response": {"status_code": 200, "headers": {"Set-Cookie": ["secret-cookie"]}},
    }
    value.update(changes)
    return value


def summarize(**changes: object) -> dict | None:
    return audit_relay.summarize(json.dumps(entry(**changes)).encode())


class PrintableTest(unittest.TestCase):
    def test_printable(self) -> None:
        cases = (
            ("alice@example.com", "alice@example.com"),
            ("caf\xe9", "caf\xe9"),
            ("a\nb\rc\td\x00e\x7f", "a?b?c?d?e?"),
            ("a\u202eb\u2028c\u2029d\u0085e\u200bf", "a?b?c?d?e?f"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(audit_relay.printable(value), expected)


class MaskPathTest(unittest.TestCase):
    """The webhook ID is masked, also when the path is percent-encoded."""

    CASES = (
        ("/api/webhook/secret-id", "/api/webhook/***"),
        ("/api/webhook/secret-id/more", "/api/webhook/***"),
        ("/API/WEBHOOK/secret-id", "/API/WEBHOOK/***"),
        ("/api/%77ebhook/secret-id", "/api/webhook/***"),
        ("/API/%57ebhook/secret%2Fid", "/API/Webhook/***"),
        ("/api/webhook/secret%2Fid", "/api/webhook/***"),
        ("//api/webhook/secret-id", "//api/webhook/***"),
        ("/api/webhook", "/api/webhook"),
        ("/api/states", "/api/states"),
        ("/api/states%2Fx", "/api/states%2Fx"),
    )

    def test_mask_path(self) -> None:
        for path, expected in self.CASES:
            with self.subTest(path=path):
                self.assertEqual(audit_relay.mask_path(path), expected)


class SummarizeTest(unittest.TestCase):
    def test_summary_fields(self) -> None:
        self.assertEqual(
            summarize(),
            {
                "id": "0f0e",
                "t": 1767225601.0,
                "user": "alice@example.com",
                "method": "GET",
                "path": "/api/states",
                "q": True,
                "status": 200,
                "ms": 250.0,
                "err": False,
                "v": "2.1.0",
            },
        )

    def test_no_secrets_in_the_summary(self) -> None:
        # Headers, query string, client address and groups are never copied.
        text = json.dumps(summarize())
        for secret in ("secret", "192.0.2.1", "Authorization", "Set-Cookie", "Admins", "token"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, text)

    def test_path(self) -> None:
        cases = (
            # (url, path, query or fragment present)
            ("/api/states", "/api/states", False),
            ("/api/states?x=1", "/api/states", True),
            ("/api/states#frag", "/api/states", True),
            ("https://ha-api.int:8443/api/states?x=1", "/api/states", True),
            ("/api/webhook/secret-id", "/api/webhook/***", False),
            ("/api/webhook/secret-id?x=1", "/api/webhook/***", True),
            ("/API/%77ebhook/secret-id/more", "/API/webhook/***", False),
            # A path that starts with // is a path, not a host name.
            ("//api/webhook/secret%2Fid", "//api/webhook/***", False),
            ("//evil.example/api/states", "//evil.example/api/states", False),
            ("/api/x\u202ey", "/api/x?y", False),
            ("/api/x\u2028y", "/api/x?y", False),
            (5, "", False),
            (None, "", False),
            ("http://[::1/api/states", "", False),
        )
        for url, path, has_query in cases:
            with self.subTest(url=url):
                summary = summarize(url=url)
                self.assertEqual((summary["path"], summary["q"]), (path, has_query))

    def test_long_path_is_shortened_and_marked(self) -> None:
        summary = summarize(url="/api/" + "a" * 600)
        self.assertEqual(len(summary["path"]), audit_relay.MAX_PATH_CHARS)
        self.assertIs(summary["pt"], True)
        self.assertNotIn("pt", summarize())

    def test_user(self) -> None:
        cases = (
            ({"username": "a\u202eb\u2028c\u0085d"}, "a?b?c?d"),
            ({"username": "x" * 300}, "x" * 200),
            ({"username": 5}, ""),
            ({}, ""),
            ("alice", ""),
            (None, ""),
        )
        for user, expected in cases:
            with self.subTest(user=user):
                self.assertEqual(summarize(user=user)["user"], expected)

    def test_method_status_version_and_level(self) -> None:
        self.assertEqual(summarize(method="get")["method"], "?")
        self.assertEqual(summarize(method="GET\nX")["method"], "?")
        self.assertEqual(summarize(method="A" * 17)["method"], "?")
        self.assertEqual(summarize(method="PROPFIND")["method"], "PROPFIND")
        self.assertEqual(summarize(response={"status_code": 1000})["status"], 0)
        self.assertEqual(summarize(response={"status_code": "200"})["status"], 0)
        self.assertEqual(summarize(response=None)["status"], 0)
        self.assertEqual(summarize(response={"status_code": 503})["status"], 503)
        self.assertNotIn("v", summarize(version="2.1.0 <b>"))
        self.assertNotIn("v", summarize(version=5))
        self.assertIs(summarize(levelname="error")["err"], True)

    def test_times(self) -> None:
        # Without a start time the end time is used, without a duration.
        summary = summarize(requested_at=None)
        self.assertEqual((summary["t"], summary["ms"]), (1767225601.25, None))
        summary = summarize(requested_at="2026-01-01T01:00:01+0100", ts="2026-01-01T00:00:00.500Z")
        self.assertEqual((summary["t"], summary["ms"]), (1767225601.0, 0.0))
        self.assertIsNone(summarize(requested_at=None, ts=None))
        self.assertIsNone(summarize(requested_at="yesterday", ts="today"))

    def test_request_id(self) -> None:
        self.assertEqual(summarize(request_id="abc-DEF-123")["id"], "abc-DEF-123")
        for request_id in (None, 5, "", "a/b", "x" * 65, "a b"):
            with self.subTest(request_id=request_id):
                self.assertEqual(summarize(request_id=request_id)["id"], "1767225601.000000-GET-200")

    def test_lines_that_are_not_audit_entries(self) -> None:
        cases = (
            b"",
            b"plain text",
            b'{"logger":"gateway","message":"audit"}',
            json.dumps(entry(logger="access")).encode(),
            b'["audit"]',
            b'{"logger":"audit"',
            b'["audit",' + b"[" * 100_000 + b"]" * 100_001,
        )
        for line in cases:
            with self.subTest(line=line[:40]):
                self.assertIsNone(audit_relay.summarize(line))


if __name__ == "__main__":
    unittest.main()
