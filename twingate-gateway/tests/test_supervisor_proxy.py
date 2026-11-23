"""Pure parts of the API proxy (supervisor_proxy.py); no server is started.

Proxy objects are created only to test their bookkeeping and identify();
creating one imports aiohttp, which these tests therefore need.
"""

import os
import types
import unittest

from support import (
    HOSTNAMES,
    NETWORK,
    NOW,
    OTHER_SIGNER,
    SIGNER,
    FakeClock,
    FakeFetch,
    binding,
    gat,
    gat_claims,
    headers,
    jwks,
    supervisor_proxy,
)

GAT_HEADER = "X-Twingate-Gateway-Token"


class PrintableTest(unittest.TestCase):
    """Values from clients and tokens, made safe for one log line."""

    def test_printable(self) -> None:
        cases = (
            ("alice@example.com", "alice@example.com"),
            ("caf\xe9 \u65e5\u672c", "caf\xe9 \u65e5\u672c"),
            ("a\nb\rc\td", "a?b?c?d"),
            ("\x00\x1b[31mred", "??[31mred"),
            # Bidi overrides, line and paragraph separators, NEL, zero width.
            ("a\u202eb\u2066c", "a?b?c"),
            ("a\u2028b\u2029c\u0085d", "a?b?c?d"),
            ("a\u200bb\ufeffc", "a?b?c"),
            ("", ""),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(supervisor_proxy._printable(value), expected)

    def test_limit(self) -> None:
        self.assertEqual(supervisor_proxy._printable("x" * 300), "x" * 200)
        self.assertEqual(supervisor_proxy._printable("\n" * 20, 5), "?????")
        self.assertEqual(supervisor_proxy._printable("abcdef", 3), "abc")


class HeadersTest(unittest.TestCase):
    """Only the headers the Supervisor passes on reach it."""

    def test_forwarded_request_headers(self) -> None:
        self.assertEqual(
            supervisor_proxy.FORWARD_REQUEST_HEADERS,
            ("Content-Type", "Accept", "Last-Event-ID", "Mcp-Session-Id", "MCP-Protocol-Version", "X-Speech-Content"),
        )
        forwarded = {name.lower() for name in supervisor_proxy.FORWARD_REQUEST_HEADERS}
        never = (
            GAT_HEADER,
            "Authorization",
            "Cookie",
            "Host",
            "Origin",
            "Referer",
            "Forwarded",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Real-IP",
            "X-Hassio-Key",
            "X-Supervisor-Token",
            "Upgrade",
            "Connection",
        )
        for name in never:
            with self.subTest(name=name):
                self.assertNotIn(name.lower(), forwarded)

    def test_forwarded_response_headers(self) -> None:
        self.assertEqual(supervisor_proxy.FORWARD_RESPONSE_HEADERS, ("Content-Type", "Cache-Control", "Mcp-Session-Id", "X-Accel-Buffering"))

    def test_methods(self) -> None:
        self.assertEqual(supervisor_proxy.PROXIED_METHODS, ("GET", "HEAD", "POST", "DELETE"))


class ConfigTest(unittest.TestCase):
    """The proxy's options as /run.sh writes them."""

    def config(self, **raw: object) -> object:
        return supervisor_proxy.Config({"network": NETWORK, **raw})

    def test_network(self) -> None:
        for network in ("examplenet", "net2", "a", "a" * 63):
            with self.subTest(network=network):
                self.assertEqual(self.config(network=network).network, network)
        for network in ("", "Example", "example-net", "example.net", "example net", "a" * 64, None, 5, ["examplenet"]):
            with self.subTest(network=network), self.assertRaises(ValueError):
                self.config(network=network)

    def test_ports(self) -> None:
        cases = (
            ({}, 8124, None),
            ({"port": 8125, "host_port": 18124}, 8125, 18124),
            ({"port": 0, "host_port": 0}, 8124, None),
            ({"port": 65536, "host_port": 65536}, 8124, None),
            ({"port": "8125", "host_port": "18124"}, 8124, None),
            ({"port": True, "host_port": True}, 8124, None),
            ({"port": 8125.0, "host_port": None}, 8124, None),
        )
        for raw, port, host_port in cases:
            with self.subTest(raw=raw):
                config = self.config(**raw)
                self.assertEqual((config.port, config.host_port), (port, host_port))

    def test_hostnames(self) -> None:
        self.assertEqual(self.config(hostnames=[*HOSTNAMES, "", 5, None]).hostnames, HOSTNAMES)
        self.assertEqual(self.config(hostnames="host").hostnames, [])
        self.assertEqual(self.config().hostnames, [])

    def test_groups(self) -> None:
        config = self.config(groups={"read": ["Readers", "", 5, None], "mcp": ["Agents"], "full": ["Admins"]})
        self.assertEqual(config.rules.read_groups, frozenset({"Readers"}))
        self.assertEqual(config.rules.mcp_groups, frozenset({"Agents"}))
        self.assertEqual(config.rules.full_groups, frozenset({"Admins"}))
        self.assertEqual(config.rules.grants(["Other"]), frozenset())
        # No group options: Read for everyone, nobody has MCP or Full.
        empty = self.config(groups={"read": [], "mcp": [], "full": []})
        self.assertEqual(empty.rules.grants(["Admins"]), frozenset({"read"}))


class ReadTokenTest(unittest.TestCase):
    """The Supervisor token arrives on a file descriptor."""

    def read(self, data: bytes) -> str:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, data)
        os.close(write_fd)
        token = supervisor_proxy.read_token(read_fd)
        # read_token() closed the descriptor.
        with self.assertRaises(OSError):
            os.fstat(read_fd)
        return token

    def test_read_token(self) -> None:
        cases = (
            (b"abc.DEF-123_xyz\n", "abc.DEF-123_xyz"),
            (b"  token  \r\n", "token"),
            (b"", ""),
            (b"two words", ""),
            (b"tok\x00en", ""),
            (b"tok\ten", ""),
        )
        for data, expected in cases:
            with self.subTest(data=data):
                self.assertEqual(self.read(data), expected)

    def test_no_descriptor(self) -> None:
        self.assertEqual(supervisor_proxy.read_token(None), "")


def make_proxy(verifier: object = None, journal: object = None) -> object:
    config = supervisor_proxy.Config({"network": NETWORK, "hostnames": HOSTNAMES})
    journal = journal or types.SimpleNamespace(keys={}, changed=False)
    return supervisor_proxy.Proxy(config, "supervisor-token", journal, verifier)


class LimitsTest(unittest.TestCase):
    """Slots per Twingate user and in all: 429 beyond a user's share, 503 beyond the total."""

    def test_limits(self) -> None:
        self.assertEqual(
            (supervisor_proxy.MAX_USER_REQUESTS, supervisor_proxy.MAX_REQUESTS, supervisor_proxy.MAX_USER_WEBSOCKETS, supervisor_proxy.MAX_WEBSOCKETS),
            (16, 64, 16, 64),
        )

    def test_requests(self) -> None:
        self.check_kind("http", supervisor_proxy.MAX_USER_REQUESTS, supervisor_proxy.MAX_REQUESTS)

    def test_websockets(self) -> None:
        self.check_kind("ws", supervisor_proxy.MAX_USER_WEBSOCKETS, supervisor_proxy.MAX_WEBSOCKETS)

    def check_kind(self, kind: str, per_user: int, total: int) -> None:
        proxy = make_proxy()
        users = [f"user{n}@example.com" for n in range(total // per_user)]
        for user in users:
            for _ in range(per_user):
                self.assertEqual(proxy._take(kind, user), 0)
        # A user at its share: 429, also when the total is reached.
        self.assertEqual(proxy._take(kind, users[0]), 429)
        # Another user once the total is reached: 503.
        self.assertEqual(proxy._take(kind, "late@example.com"), 503)
        proxy._release(kind, users[0])
        self.assertEqual(proxy._take(kind, "late@example.com"), 0)
        self.assertEqual(proxy._take(kind, users[0]), 503)
        # The other kind has its own slots.
        other = "ws" if kind == "http" else "http"
        self.assertEqual(proxy._take(other, users[0]), 0)
        proxy._release(other, users[0])
        # Releasing every slot leaves nothing behind.
        proxy._release(kind, "late@example.com")
        for user in users:
            for _ in range(per_user - (1 if user == users[0] else 0)):
                proxy._release(kind, user)
        self.assertEqual((proxy.requests_open, proxy.websockets_open), (0, 0))
        self.assertEqual((proxy.user_requests, proxy.user_websockets), ({}, {}))

    def test_user_names_are_compared_exactly(self) -> None:
        proxy = make_proxy()
        for _ in range(supervisor_proxy.MAX_USER_REQUESTS):
            proxy._take("http", "alice@example.com")
        self.assertEqual(proxy._take("http", "alice@example.com"), 429)
        self.assertEqual(proxy._take("http", "Alice@example.com"), 0)


class IdentifyTest(unittest.IsolatedAsyncioTestCase):
    """The caller from the GAT header (Proxy.identify), with the key set read again on an unknown key ID."""

    def setUp(self) -> None:
        self.key_clock = FakeClock()
        self.fetch = FakeFetch(jwks(SIGNER))
        self.store = gat.KeyStore(NETWORK, fetch=self.fetch, clock=self.key_clock)
        self.store.refresh()
        self.verifier = gat.Verifier(NETWORK, binding(), self.store, clock=FakeClock())
        self.journal = types.SimpleNamespace(keys={}, changed=False)
        self.proxy = make_proxy(self.verifier, self.journal)

    async def identify(self, *pairs: tuple[str, str]) -> tuple:
        return await self.proxy.identify(types.SimpleNamespace(headers=headers(*pairs)))

    async def test_valid_token(self) -> None:
        token = SIGNER.token()
        for value in (token, f" {token} ", f"Bearer {token}", f"bearer   {token}", f"BEARER {token}"):
            with self.subTest(value=value[:12]):
                identity, reason = await self.identify((GAT_HEADER, value))
                self.assertEqual((identity.username, reason), ("alice@example.com", ""))
        identity, _reason = await self.identify((GAT_HEADER.lower(), token))
        self.assertEqual(identity.username, "alice@example.com")

    async def test_no_token(self) -> None:
        # A GAT anywhere but in its own header does not count.
        token = SIGNER.token()
        for pairs in ((), (("Authorization", f"Bearer {token}"),), (("Cookie", f"token={token}"),)):
            with self.subTest(pairs=[name for name, _value in pairs]):
                self.assertEqual(await self.identify(*pairs), (None, "no token"))

    async def test_more_than_one_token_header(self) -> None:
        token = SIGNER.token()
        cases = (
            ((GAT_HEADER, token), (GAT_HEADER, token)),
            ((GAT_HEADER, token), (GAT_HEADER.lower(), token)),
            ((GAT_HEADER.upper(), "x"), (GAT_HEADER, token)),
            ((GAT_HEADER, token), (GAT_HEADER, "")),
        )
        for pairs in cases:
            with self.subTest(names=[name for name, _value in pairs]):
                self.assertEqual(await self.identify(*pairs), (None, "more than one token header"))

    async def test_invalid_token_does_not_read_the_keys_again(self) -> None:
        self.key_clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL)
        cases = (
            ("", "missing or oversized token"),
            ("Bearer", "malformed token"),
            ("not a token", "malformed token"),
            (SIGNER.token(gat_claims(exp=int(NOW) - 1)), "expired"),
            (SIGNER.token(gat_claims(aud=["other"])), "wrong audience"),
        )
        for value, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(await self.identify((GAT_HEADER, value)), (None, reason))
        self.assertEqual(self.fetch.calls, 1)

    async def test_unknown_key_id_reads_the_keys_again(self) -> None:
        # Twingate added a key: read the key set again, then accept.
        self.fetch.result = jwks(SIGNER, OTHER_SIGNER)
        self.key_clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL)
        identity, reason = await self.identify((GAT_HEADER, OTHER_SIGNER.token()))
        self.assertEqual((identity.username, reason), ("alice@example.com", ""))
        self.assertEqual(self.fetch.calls, 2)
        self.assertEqual(self.journal.keys, self.store.state)
        self.assertTrue(self.journal.changed)

    async def test_unknown_key_ids_read_the_keys_at_most_once_a_minute(self) -> None:
        self.key_clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL)
        self.assertEqual(await self.identify((GAT_HEADER, OTHER_SIGNER.token())), (None, "unknown signing key"))
        self.assertEqual(self.fetch.calls, 2)
        self.key_clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL - 1)
        for kid in ("key-3", "key-4", "key-5"):
            with self.subTest(kid=kid):
                self.assertEqual(await self.identify((GAT_HEADER, OTHER_SIGNER.token(kid=kid))), (None, "unknown signing key"))
        self.assertEqual(self.fetch.calls, 2)

    async def test_keys_not_read_yet(self) -> None:
        clock = FakeClock()
        fetch = FakeFetch(OSError("network down"))
        store = gat.KeyStore(NETWORK, fetch=fetch, clock=clock)
        store.refresh()
        proxy = make_proxy(gat.Verifier(NETWORK, binding(), store, clock=FakeClock()))
        request = types.SimpleNamespace(headers=headers((GAT_HEADER, SIGNER.token())))
        self.assertEqual(await proxy.identify(request), (None, "signing keys not available"))
        self.assertEqual(fetch.calls, 1)
        fetch.result = jwks(SIGNER)
        clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL)
        identity, _reason = await proxy.identify(request)
        self.assertEqual(identity.username, "alice@example.com")
        self.assertEqual(fetch.calls, 2)


class ShownPathTest(unittest.TestCase):
    """The path in logs before it was checked: decoded if possible, masked, shortened."""

    def test_shown_path(self) -> None:
        proxy = make_proxy()
        cases = (
            ("/api/states", "/api/states"),
            ("/api/st%61tes", "/api/states"),
            ("/api/webhook/secret-id", "/api/webhook/***"),
            ("/api/%77ebhook/secret-id", "/api/webhook/***"),
            ("//api/webhook/secret-id", "//api/webhook/***"),
            ("/api/states%0a", "/api/states%0a"),
            ("/api/" + "a" * 400, ("/api/" + "a" * 400)[:300]),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(proxy._shown_path(raw), expected)


if __name__ == "__main__":
    unittest.main()
