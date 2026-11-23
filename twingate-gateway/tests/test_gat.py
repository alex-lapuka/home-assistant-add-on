"""Verification of Twingate Gateway Access Tokens (gat.py).

Tokens are signed in the tests with a P-256 key made for each run; the key
set is handed to gat.KeyStore through an injected fetcher, and every clock is
a FakeClock. Nothing is fetched from Twingate.
"""

import hashlib
import hmac
import json
import unittest
import urllib.error
import urllib.request
from typing import Self
from unittest import mock

from support import (
    DROP,
    HOSTNAME,
    NETWORK,
    NOW,
    OTHER_SIGNER,
    PROXY_PORT,
    SIGNER,
    FakeClock,
    FakeFetch,
    Signer,
    b64url,
    binding,
    gat,
    gat_claims,
    json_segment,
    jwks,
    resource,
    verifier,
)


def rejection(check: object, token: str) -> str | None:
    """The reason a token is refused, or None if it is accepted."""
    try:
        check.verify(token)
    except gat.TokenError as error:
        return str(error)
    return None


def with_user(**changes: object) -> dict:
    user = {"id": "user-1", "username": "alice@example.com", "groups": ["Everyone"]}
    user.update(changes)
    return {name: value for name, value in user.items() if value is not DROP}


def with_resource(**changes: object) -> dict:
    value = resource()
    value.update(changes)
    return {name: item for name, item in value.items() if item is not DROP}


class TokenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = verifier(SIGNER, OTHER_SIGNER)

    def assert_refused(self, token: str, reason: str) -> None:
        self.assertEqual(rejection(self.verifier, token), reason)

    def test_valid_token_gives_the_caller(self) -> None:
        identity = self.verifier.verify(SIGNER.token(gat_claims(user=with_user(groups=["Home Admins", "Family"]))))
        self.assertEqual(identity.username, "alice@example.com")
        self.assertEqual(identity.user_id, "user-1")
        self.assertEqual(identity.resource_id, "resource-1")
        self.assertEqual(identity.expires_at, NOW + 600)
        # The access level is the same for every caller: the groups are not kept.
        self.assertFalse(hasattr(identity, "groups"))

    def test_any_list_of_groups_is_accepted(self) -> None:
        # Missing, null, empty, or with entries that are not text: the token
        # is valid all the same (a groups claim that is not a list is not;
        # see CLAIM_CASES).
        for groups in (DROP, None, [], ["Everyone"], ["Home Admins", 5, None, {"x": 1}]):
            with self.subTest(groups=groups):
                identity = self.verifier.verify(SIGNER.token(gat_claims(user=with_user(groups=groups))))
                self.assertEqual(identity.username, "alice@example.com")

    def test_only_es256_is_accepted(self) -> None:
        payload = json_segment(gat_claims())
        cases = (
            # (header, signature segment, reason)
            ({"alg": "none", "kid": "key-1"}, "", "algorithm 'none' not accepted"),
            ({"alg": "None", "kid": "key-1"}, "", "algorithm 'None' not accepted"),
            ({"alg": "RS256", "kid": "key-1"}, b64url(b"x" * 256), "algorithm 'RS256' not accepted"),
            ({"alg": "ES384", "kid": "key-1"}, b64url(b"x" * 96), "algorithm 'ES384' not accepted"),
            ({"alg": "ES512", "kid": "key-1"}, b64url(b"x" * 132), "algorithm 'ES512' not accepted"),
            ({"alg": "EdDSA", "kid": "key-1"}, b64url(b"x" * 64), "algorithm 'EdDSA' not accepted"),
            ({"alg": "es256", "kid": "key-1"}, b64url(b"x" * 64), "algorithm 'es256' not accepted"),
            ({"alg": "ES256 ", "kid": "key-1"}, b64url(b"x" * 64), "algorithm 'ES256 ' not accepted"),
            ({"kid": "key-1"}, b64url(b"x" * 64), "algorithm '' not accepted"),
            ({"alg": ["ES256"], "kid": "key-1"}, b64url(b"x" * 64), "algorithm '' not accepted"),
            ({"alg": None, "kid": "key-1"}, b64url(b"x" * 64), "algorithm '' not accepted"),
        )
        for header, signature, reason in cases:
            with self.subTest(header=header):
                self.assert_refused(f"{json_segment(header)}.{payload}.{signature}", reason)

    def test_hs256_is_refused_with_any_secret(self) -> None:
        # Algorithm confusion: an HMAC "signed" with the public key.
        public_key = json.dumps(SIGNER.jwk()).encode()
        for secret in (b"secret", public_key):
            with self.subTest(secret=secret[:10]):
                signing_input = f"{json_segment({'alg': 'HS256', 'kid': 'key-1'})}.{json_segment(gat_claims())}"
                signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
                self.assert_refused(f"{signing_input}.{b64url(signature)}", "algorithm 'HS256' not accepted")

    def test_es384_signature_is_refused(self) -> None:
        # A real P-384 signature under alg ES384, and the same under alg ES256;
        # a P-384 key is not even read into the key set.
        p384 = Signer("key-384", curve="P-384")
        self.assertEqual(gat.parse_jwks({"keys": [p384.jwk()]}), {})
        self.assert_refused(p384.token(), "algorithm 'ES384' not accepted")
        self.assert_refused(p384.token(alg="ES256"), "bad signature")
        self.assert_refused(p384.token(alg="ES256", kid="key-1"), "bad signature")

    def test_critical_header_is_refused(self) -> None:
        for crit in (["exp"], [], "exp", None):
            with self.subTest(crit=crit):
                self.assert_refused(SIGNER.token(crit=crit), "unsupported critical header")

    def test_key_id(self) -> None:
        # A key ID that is not text.
        for kid in (5, ["key-1"], {"kid": "key-1"}, True):
            with self.subTest(kid=kid):
                self.assert_refused(SIGNER.token(kid=kid), "malformed token")
        # A key ID that is not in the key set.
        self.assert_refused(SIGNER.token(kid="key-3"), "unknown signing key")
        # The key ID names another key of the set than the one that signed.
        self.assert_refused(SIGNER.token(kid="key-2"), "bad signature")
        # Without a key ID every key of the set is tried.
        self.assertEqual(self.verifier.verify(OTHER_SIGNER.token(kid=DROP)).username, "alice@example.com")

    def test_signature_format(self) -> None:
        token = SIGNER.token()
        header, payload, signature = token.split(".")
        raw = gat._b64url(signature)
        der = SIGNER.der_signature(f"{header}.{payload}".encode())
        cases = (
            # Not r and s of 32 bytes each.
            (b64url(raw[:63]), "bad signature"),
            (b64url(raw + b"\x00"), "bad signature"),
            (b64url(der), "bad signature"),
            # r and s swapped, all zero, or of another message.
            (b64url(raw[32:] + raw[:32]), "bad signature"),
            (b64url(b"\x00" * 64), "bad signature"),
            (SIGNER.token(gat_claims(exp=int(NOW) + 601)).split(".")[2], "bad signature"),
            # Unpadded base64url only.
            (signature + "=", "malformed token"),
            (signature + "==", "malformed token"),
            (signature.replace("-", "+").replace("_", "/") + "+/", "malformed token"),
            (signature[:20] + " " + signature[20:], "malformed token"),
            (signature[:20] + "." + signature[20:], "malformed token"),
            ("", "malformed token"),
        )
        for value, reason in cases:
            with self.subTest(signature=value[:24]):
                self.assert_refused(f"{header}.{payload}.{value}", reason)

    def test_tampered_token(self) -> None:
        header, payload, signature = SIGNER.token().split(".")
        other_payload = json_segment(gat_claims(user=with_user(username="mallory@example.com")))
        other_header = json_segment({"alg": "ES256", "kid": "key-1", "typ": "GAT"})
        self.assert_refused(f"{header}.{other_payload}.{signature}", "bad signature")
        self.assert_refused(f"{other_header}.{payload}.{signature}", "bad signature")
        # Signed by a key that is not in the set, under a known key ID.
        self.assert_refused(Signer("key-1").sign_segments(header, payload), "bad signature")

    def test_token_structure(self) -> None:
        good = SIGNER.token()
        header, payload, signature = good.split(".")
        cases = (
            ("", "missing or oversized token"),
            ("x" * (32 * 1024 + 1), "missing or oversized token"),
            (f"{header}.{payload}", "malformed token"),
            (f"{good}.{signature}", "malformed token"),
            (f"{header}..{signature}", "bad signature"),
            (f" {good}", "malformed token"),
            (f"!!!.{payload}.{signature}", "malformed token"),
            (f"{b64url(b'not json')}.{payload}.{signature}", "malformed token"),
            (f"{json_segment(['ES256'])}.{payload}.{signature}", "malformed token"),
            (f"{header}.{payload}\xe9.{signature}", "malformed token"),
        )
        for token, reason in cases:
            with self.subTest(token=token[:40]):
                self.assert_refused(token, reason)

    def test_signed_payload_must_be_a_json_object(self) -> None:
        header = json_segment({"alg": "ES256", "kid": "key-1"})
        for payload in (json_segment([1, 2]), json_segment("claims"), b64url(b"{"), "A", b64url(b"\xff")):
            with self.subTest(payload=payload):
                self.assert_refused(SIGNER.sign_segments(header, payload), "malformed token")


# (changes to the claims, reason the token is refused, or None if accepted)
CLAIM_CASES = (
    ({}, None),
    # Issuer.
    ({"iss": "Twingate"}, "wrong issuer"),
    ({"iss": "twingate-dev"}, "wrong issuer"),
    ({"iss": DROP}, "wrong issuer"),
    ({"iss": None}, "wrong issuer"),
    # Audience: the network name, as text or in a list.
    ({"aud": NETWORK}, None),
    ({"aud": ["other", NETWORK]}, None),
    ({"aud": "other"}, "wrong audience"),
    ({"aud": ["other"]}, "wrong audience"),
    ({"aud": [NETWORK.upper()]}, "wrong audience"),
    ({"aud": []}, "wrong audience"),
    ({"aud": DROP}, "wrong audience"),
    ({"aud": [5]}, "wrong audience"),
    ({"aud": {NETWORK: True}}, "wrong audience"),
    # Expiry: a number in the future.
    ({"exp": NOW + 0.5}, None),
    ({"exp": int(NOW)}, "expired"),
    ({"exp": int(NOW) - 1}, "expired"),
    ({"exp": DROP}, "no expiry"),
    ({"exp": None}, "no expiry"),
    ({"exp": str(int(NOW) + 600)}, "no expiry"),
    ({"exp": True}, "no expiry"),
    # Issued at and not before: numbers not in the future, when present.
    ({"iat": int(NOW)}, None),
    ({"nbf": int(NOW)}, None),
    ({"iat": DROP, "nbf": DROP}, None),
    ({"iat": int(NOW) + 1}, "iat in the future or invalid"),
    ({"iat": "0"}, "iat in the future or invalid"),
    ({"iat": True}, "iat in the future or invalid"),
    ({"iat": None}, "iat in the future or invalid"),
    ({"nbf": int(NOW) + 1}, "nbf in the future or invalid"),
    ({"nbf": "0"}, "nbf in the future or invalid"),
    # Type and version of a Gateway Access Token.
    ({"typ": DROP}, "claim typ missing"),
    ({"typ": ""}, "claim typ missing"),
    ({"typ": "JWT"}, "not a Gateway Access Token"),
    ({"typ": "gat"}, "not a Gateway Access Token"),
    ({"ver": DROP}, "claim ver missing"),
    ({"ver": 1}, "claim ver missing"),
    ({"ver": "2"}, "unsupported token version"),
    # Other required claims.
    ({"cpk": DROP}, "claim cpk missing"),
    ({"cpk": ""}, "claim cpk missing"),
    ({"rnw": DROP}, "claim rnw missing"),
    ({"rnw": "1900000300"}, "claim rnw missing"),
    ({"rnw": False}, "claim rnw missing"),
    ({"user": DROP}, "user missing"),
    ({"user": "alice"}, "user missing"),
    ({"user": with_user(id=DROP)}, "user missing"),
    ({"user": with_user(id="")}, "user missing"),
    ({"user": with_user(id=5)}, "user missing"),
    ({"user": with_user(username=DROP)}, "user missing"),
    ({"user": with_user(username="")}, "user missing"),
    ({"user": with_user(groups="Home Admins")}, "invalid groups"),
    ({"user": with_user(groups={"Home Admins": True})}, "invalid groups"),
    ({"resource": DROP}, "resource missing"),
    ({"resource": "resource-1"}, "resource missing"),
    ({"resource": with_resource(id=DROP)}, "resource missing"),
    ({"resource": with_resource(address="")}, "resource missing"),
    ({"resource": with_resource(gateway_metadata=DROP)}, "invalid port"),
    # Ports: integers from 1 to 65535.
    ({"resource": resource(downstream_port=1)}, None),
    ({"resource": resource(downstream_port=65535)}, None),
    ({"resource": resource(downstream_port=0)}, "invalid port"),
    ({"resource": resource(downstream_port=65536)}, "invalid port"),
    ({"resource": resource(downstream_port="443")}, "invalid port"),
    ({"resource": resource(downstream_port=443.0)}, "invalid port"),
    ({"resource": resource(downstream_port=True)}, "invalid port"),
    ({"resource": resource(downstream_port=None)}, "invalid port"),
    ({"resource": resource(upstream_port="8124")}, "invalid port"),
    ({"resource": resource(upstream_port=8124.0)}, "invalid port"),
    ({"resource": resource(upstream_port=-8124)}, "invalid port"),
    # TLS modes of a Web App Resource.
    ({"resource": resource(downstream_tls="NONE")}, None),
    ({"resource": resource(downstream_tls="TLS12")}, "invalid TLS mode"),
    ({"resource": resource(downstream_tls=None)}, "invalid TLS mode"),
    ({"resource": resource(upstream_tls="VERIFY_NONE")}, "invalid TLS mode"),
    ({"resource": resource(upstream_tls="none")}, "invalid TLS mode"),
)

# (changes to the claims, reason) for tokens refused because they are not
# for this proxy (Binding), after the claims were checked.
BINDING_CLAIM_CASES = (
    ({"resource": resource(upstream_tls="VERIFY_FULL")}, "the token's Resource uses upstream TLS mode VERIFY_FULL, not NONE"),
    ({"resource": resource(upstream_tls="INSECURE")}, "the token's Resource uses upstream TLS mode INSECURE, not NONE"),
    ({"resource": resource(kind="SSH")}, "the token is for a SSH Resource"),
    ({"resource": resource(kind=None)}, "the token is for a non-Web App Resource"),
    ({"resource": resource(upstream_port=8123)}, f"the token is for Resource address '{HOSTNAME}' with upstream port 8123, not this proxy"),
    ({"resource": resource(address="homeassistant")}, "the token is for Resource address 'homeassistant' with upstream port 8124, not this proxy"),
)


class ClaimsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = verifier()

    def test_claims(self) -> None:
        for changes, reason in CLAIM_CASES:
            with self.subTest(changes=changes):
                self.assertEqual(rejection(self.verifier, SIGNER.token(gat_claims(**changes))), reason)

    def test_binding_after_claims(self) -> None:
        for changes, reason in BINDING_CLAIM_CASES:
            with self.subTest(changes=changes):
                self.assertEqual(rejection(self.verifier, SIGNER.token(gat_claims(**changes))), reason)


class BindingTest(unittest.TestCase):
    """Which Resources' tokens are for this proxy."""

    # (address, upstream port, accepted without a published port, accepted
    # with the proxy port published on host port 18124)
    CASES = (
        # The add-on's host name, with or without .local.hass.io, and port 8124.
        (HOSTNAME, PROXY_PORT, True, True),
        (f"{HOSTNAME}.local.hass.io", PROXY_PORT, True, True),
        (f"{HOSTNAME.upper()}.LOCAL.HASS.IO.", PROXY_PORT, True, True),
        (HOSTNAME, 8123, False, False),
        (HOSTNAME, 18124, False, False),
        (f"{HOSTNAME}.evil.example", PROXY_PORT, False, False),
        (f"x{HOSTNAME}", PROXY_PORT, False, False),
        ("homeassistant", PROXY_PORT, False, False),
        ("homeassistant.local.hass.io", PROXY_PORT, False, False),
        ("", PROXY_PORT, False, False),
        # Published port: any IPv4 address but loopback and 0.0.0.0, with
        # the host port.
        ("192.0.2.10", 18124, False, True),
        ("10.1.2.3", 18124, False, True),
        ("192.0.2.10", PROXY_PORT, False, False),
        ("127.0.0.1", 18124, False, False),
        ("127.1.2.3", 18124, False, False),
        ("0.0.0.0", 18124, False, False),
        ("::1", 18124, False, False),
        ("2001:db8::1", 18124, False, False),
        ("192.0.2.10.nip.io", 18124, False, False),
        ("192.000.2.10", 18124, False, False),
        ("3221226000", 18124, False, False),
        (HOSTNAME, "8124", False, False),
    )

    def test_addresses_and_ports(self) -> None:
        for address, port, without, published in self.CASES:
            for host_port, expected in ((None, without), (18124, published)):
                with self.subTest(address=address, port=port, host_port=host_port):
                    claim = resource(address=address, upstream_port=port)
                    if expected:
                        binding(host_port).check(claim)
                    else:
                        with self.assertRaises(gat.TokenError):
                            binding(host_port).check(claim)

    def test_web_app_with_upstream_tls_none_only(self) -> None:
        cases = (
            {"kind": "SSH"},
            {"kind": "KUBERNETES"},
            {"kind": "web_app"},
            {"kind": None},
            {"upstream_tls": "VERIFY_FULL"},
            {"upstream_tls": "VERIFY_CA"},
            {"upstream_tls": "INSECURE"},
            {"upstream_tls": None},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(gat.TokenError):
                    binding(18124).check(resource(**changes))
                with self.assertRaises(gat.TokenError):
                    binding(18124).check(resource(address="192.0.2.10", upstream_port=18124, **changes))

    def test_configured_names_are_normalized(self) -> None:
        check = gat.Binding(["A0B1C2D3-Twingate-Gateway.", ""], PROXY_PORT, None)
        self.assertEqual(check.hostnames, frozenset({HOSTNAME}))
        check.check(resource())


class VerifierCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.key_clock = FakeClock()
        self.fetch = FakeFetch(jwks(SIGNER))
        self.store = gat.KeyStore(NETWORK, fetch=self.fetch, clock=self.key_clock)
        self.store.refresh()
        self.verifier = gat.Verifier(NETWORK, binding(), self.store, clock=self.clock)

    def test_verified_token_is_kept_until_it_expires(self) -> None:
        token = SIGNER.token()
        identity = self.verifier.verify(token)
        # The key set changes: the token is not verified again.
        self.fetch.result = jwks(OTHER_SIGNER)
        self.key_clock.advance(gat.JWKS_REFRESH_INTERVAL)
        self.assertTrue(self.store.refresh())
        self.assertIs(self.verifier.verify(token), identity)
        self.assertEqual(rejection(self.verifier, SIGNER.token(gat_claims(rnw=int(NOW) + 301))), "unknown signing key")
        # At its expiry it is dropped, and checked again.
        self.clock.advance(599)
        self.assertIs(self.verifier.cached(token), identity)
        self.clock.advance(1)
        self.assertIsNone(self.verifier.cached(token))
        self.fetch.result = jwks(SIGNER)
        self.key_clock.advance(gat.JWKS_REFRESH_INTERVAL)
        self.store.refresh()
        self.assertEqual(rejection(self.verifier, token), "expired")

    def test_refused_tokens_are_not_kept(self) -> None:
        token = SIGNER.token(gat_claims(iss="other"))
        self.assertEqual(rejection(self.verifier, token), "wrong issuer")
        self.assertIsNone(self.verifier.cached(token))

    def test_least_recently_used_token_is_dropped(self) -> None:
        first, second, third = (SIGNER.token(gat_claims(rnw=int(NOW) + n)) for n in (1, 2, 3))
        with mock.patch.object(gat, "MAX_CACHED_TOKENS", 2):
            self.verifier.verify(first)
            self.verifier.verify(second)
            self.assertIsNotNone(self.verifier.cached(first))
            self.verifier.verify(third)
        self.assertIsNotNone(self.verifier.cached(first))
        self.assertIsNone(self.verifier.cached(second))
        self.assertIsNotNone(self.verifier.cached(third))

    def test_needs_keys(self) -> None:
        cases = (
            (SIGNER.token(), False),
            (OTHER_SIGNER.token(), True),
            (SIGNER.token(kid=DROP), False),
            (SIGNER.token(kid=5), False),
            (SIGNER.token(alg="none", kid="key-9"), True),
            ("not a token", False),
            ("", False),
        )
        for token, expected in cases:
            with self.subTest(token=token[:30]):
                self.assertIs(self.verifier.needs_keys(token), expected)


class KeyStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.fetch = FakeFetch(jwks(SIGNER))
        self.store = gat.KeyStore(NETWORK, fetch=self.fetch, clock=self.clock)

    def assert_state(self, ok: bool, keys: int, error: str | None) -> None:
        state = self.store.state
        self.assertEqual((state["ok"], state["keys"], state["error"]), (ok, keys, error))

    def test_before_the_first_read(self) -> None:
        self.assertEqual(self.store.state, {"ok": False, "keys": 0, "checked_at": None, "error": "not read yet"})
        self.assertEqual(self.store.keys_for("key-1"), [])
        self.assertEqual(self.store.keys_for(None), [])
        self.assertTrue(self.store.has_kid(None))
        self.assertFalse(self.store.has_kid("key-1"))
        self.assertEqual(self.fetch.calls, 0)

    def test_read_every_hour(self) -> None:
        self.assertTrue(self.store.refresh())
        self.assert_state(True, 1, None)
        self.assertIsInstance(self.store.state["checked_at"], float)
        self.assertEqual(len(self.store.keys_for("key-1")), 1)
        self.clock.advance(gat.JWKS_REFRESH_INTERVAL - 1)
        self.assertFalse(self.store.refresh())
        self.assertEqual(self.fetch.calls, 1)
        self.clock.advance(1)
        self.assertTrue(self.store.refresh())
        self.assertEqual(self.fetch.calls, 2)

    def test_new_key_set_replaces_the_old_one(self) -> None:
        self.store.refresh()
        self.fetch.result = jwks(OTHER_SIGNER)
        self.clock.advance(gat.JWKS_REFRESH_INTERVAL)
        self.assertTrue(self.store.refresh())
        self.assertFalse(self.store.has_kid("key-1"))
        self.assertTrue(self.store.has_kid("key-2"))
        self.assertEqual(len(self.store.keys_for(None)), 1)

    def test_failure_keeps_the_previous_keys_and_retries_every_minute(self) -> None:
        self.store.refresh()
        self.clock.advance(gat.JWKS_REFRESH_INTERVAL)
        self.fetch.result = urllib.error.URLError(TimeoutError("timed out"))
        self.assertFalse(self.store.refresh())
        self.assert_state(True, 1, "TimeoutError")
        self.assertEqual(len(self.store.keys_for("key-1")), 1)
        self.clock.advance(gat.JWKS_RETRY_INTERVAL - 1)
        self.assertFalse(self.store.refresh())
        self.assertEqual(self.fetch.calls, 2)
        self.clock.advance(1)
        self.fetch.result = jwks(SIGNER)
        self.assertTrue(self.store.refresh())
        self.assertEqual(self.fetch.calls, 3)
        self.assert_state(True, 1, None)

    def test_errors_without_keys(self) -> None:
        not_found = urllib.error.HTTPError("https://x", 404, "Not Found", {}, None)
        self.addCleanup(not_found.close)
        cases = (
            (not_found, "HTTP 404"),
            (urllib.error.URLError("no such host"), "URLError"),
            (urllib.error.URLError(ConnectionRefusedError()), "ConnectionRefusedError"),
            (ValueError("no P-256 keys"), "ValueError"),
            (TypeError("not a key set"), "TypeError"),
        )
        for error, text in cases:
            with self.subTest(error=text):
                store = gat.KeyStore(NETWORK, fetch=FakeFetch(error), clock=FakeClock())
                self.assertFalse(store.refresh())
                self.assertEqual((store.state["ok"], store.state["keys"], store.state["error"]), (False, 0, text))
                self.assertEqual(store.keys_for(None), [])

    def test_forced_read_at_most_once_a_minute(self) -> None:
        # Forced (unknown key ID): at once if never read, then not within a
        # minute of the last read, whether it worked or not.
        self.assertTrue(self.store.refresh(force=True))
        self.clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL - 1)
        self.assertFalse(self.store.refresh(force=True))
        self.assertEqual(self.fetch.calls, 1)
        self.clock.advance(1)
        self.assertTrue(self.store.refresh(force=True))
        self.assertEqual(self.fetch.calls, 2)
        self.fetch.result = ValueError("broken")
        self.clock.advance(gat.JWKS_UNKNOWN_KID_INTERVAL)
        self.assertFalse(self.store.refresh(force=True))
        self.assertFalse(self.store.refresh(force=True))
        self.assertEqual(self.fetch.calls, 3)

    def test_intervals(self) -> None:
        self.assertEqual((gat.JWKS_REFRESH_INTERVAL, gat.JWKS_RETRY_INTERVAL, gat.JWKS_UNKNOWN_KID_INTERVAL), (3600.0, 60.0, 60.0))


class ParseJwksTest(unittest.TestCase):
    def numbers(self, keys: dict) -> dict:
        return {kid: key.public_numbers() for kid, key in keys.items()}

    def test_valid_keys(self) -> None:
        keys = gat.parse_jwks(jwks(SIGNER, OTHER_SIGNER))
        self.assertEqual(
            self.numbers(keys),
            {"key-1": SIGNER.key.public_key().public_numbers(), "key-2": OTHER_SIGNER.key.public_key().public_numbers()},
        )

    def test_entries_that_are_skipped(self) -> None:
        cases = (
            SIGNER.jwk(kty="RSA"),
            SIGNER.jwk(kty=DROP),
            SIGNER.jwk(crv="P-384"),
            SIGNER.jwk(crv="secp256k1"),
            SIGNER.jwk(alg="ES384"),
            SIGNER.jwk(alg="HS256"),
            SIGNER.jwk(use="enc"),
            SIGNER.jwk(x=b64url(b"\x01" * 31)),
            SIGNER.jwk(y=b64url(b"\x01" * 33)),
            SIGNER.jwk(x=SIGNER.jwk()["x"] + "="),
            SIGNER.jwk(x=DROP),
            SIGNER.jwk(x=5),
            # A point that is not on the curve.
            SIGNER.jwk(x=b64url((1).to_bytes(32, "big")), y=b64url((1).to_bytes(32, "big"))),
            "key",
            None,
        )
        for entry in cases:
            with self.subTest(entry=entry):
                self.assertEqual(gat.parse_jwks({"keys": [entry, OTHER_SIGNER.jwk()]}).keys(), {"key-2"})

    def test_optional_members(self) -> None:
        keys = gat.parse_jwks({"keys": [SIGNER.jwk(alg=DROP, use=DROP)]})
        self.assertEqual(set(keys), {"key-1"})
        # A key ID that is not text: the key has none.
        self.assertEqual(set(gat.parse_jwks({"keys": [SIGNER.jwk(kid=5)]})), {None})
        self.assertEqual(set(gat.parse_jwks({"keys": [SIGNER.jwk(kid=DROP)]})), {None})

    def test_at_most_32_keys_are_read(self) -> None:
        entries = [SIGNER.jwk(kid=f"key-{n}") for n in range(40)]
        self.assertEqual(set(gat.parse_jwks({"keys": entries})), {f"key-{n}" for n in range(32)})

    def test_not_a_key_set(self) -> None:
        for document in ({}, {"keys": {}}, {"keys": "x"}, [], None, "keys"):
            with self.subTest(document=document), self.assertRaises(TypeError):
                gat.parse_jwks(document)


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.sizes: list[int] = []

    def read(self, size: int) -> bytes:
        self.sizes.append(size)
        return self.body[:size]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class FakeOpener:
    def __init__(self, body: bytes) -> None:
        self.response = FakeResponse(body)
        self.handlers: tuple = ()
        self.requests: list = []

    def build(self, *handlers: object) -> Self:
        self.handlers = handlers
        return self

    def open(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        return self.response


class FetchJwksTest(unittest.TestCase):
    """fetch_jwks with urllib's opener replaced: no request leaves the test."""

    def fetch(self, body: bytes) -> tuple:
        opener = FakeOpener(body)
        with mock.patch.object(gat.urllib.request, "build_opener", opener.build):
            try:
                return gat.fetch_jwks(NETWORK), opener
            except (ValueError, TypeError) as error:
                return error, opener

    def test_request(self) -> None:
        keys, opener = self.fetch(json.dumps(jwks(SIGNER)).encode())
        self.assertEqual(set(keys), {"key-1"})
        ((request, timeout),) = opener.requests
        self.assertEqual(request.full_url, f"https://{NETWORK}.twingate.com/api/v1/jwk/ec")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(timeout, 10.0)
        # No proxy from the environment, and the redirect check.
        self.assertIs(opener.handlers[0], gat._NO_PROXY)
        self.assertEqual(gat._NO_PROXY.proxies, {})
        self.assertIsInstance(opener.handlers[1], gat._TwingateRedirects)
        self.assertEqual(opener.response.sizes, [gat.MAX_JWKS_BYTES + 1])

    def test_failures(self) -> None:
        cases = (
            (b" " * (gat.MAX_JWKS_BYTES + 1), ValueError, "key set too large"),
            (b"<html>", ValueError, "not JSON"),
            (b"[" * 100_000, ValueError, "not JSON"),
            (json.dumps({"keys": []}).encode(), ValueError, "no P-256 keys"),
            (json.dumps({"keys": [SIGNER.jwk(crv="P-384")]}).encode(), ValueError, "no P-256 keys"),
            (b'{"keys": 5}', TypeError, "not a key set"),
        )
        for body, error_type, text in cases:
            with self.subTest(text=text, body=body[:20]):
                error, _opener = self.fetch(body)
                self.assertIsInstance(error, error_type)
                self.assertEqual(str(error), text)


class RedirectTest(unittest.TestCase):
    """Redirects of the key set request: only to HTTPS addresses on twingate.com."""

    def redirect(self, url: str) -> object:
        request = urllib.request.Request(f"https://{NETWORK}.twingate.com/api/v1/jwk/ec")
        return gat._TwingateRedirects().redirect_request(request, None, 302, "Found", {}, url)

    def test_allowed(self) -> None:
        for url in ("https://twingate.com/api/v1/jwk/ec", "https://eu.twingate.com/api/v1/jwk/ec", "https://EXAMPLENET.TWINGATE.COM/x"):
            with self.subTest(url=url):
                self.assertEqual(self.redirect(url).full_url, url)

    def test_refused(self) -> None:
        cases = (
            "http://examplenet.twingate.com/api/v1/jwk/ec",
            "https://eviltwingate.com/x",
            "https://twingate.com.evil.example/x",
            "https://examplenet.twingate.com.evil.example/x",
            "https://evil.example/twingate.com",
            "https://evil.example/?.twingate.com",
            "https://twingate.com@evil.example/x",
            "ftp://twingate.com/x",
            "https://",
        )
        for url in cases:
            with self.subTest(url=url):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.redirect(url)
                caught.exception.close()

    def test_at_most_three_redirects(self) -> None:
        self.assertEqual(gat._TwingateRedirects.max_redirections, 3)


class Base64UrlTest(unittest.TestCase):
    def test_strict_unpadded_base64url(self) -> None:
        self.assertEqual(gat._b64url("Zm9v"), b"foo")
        self.assertEqual(gat._b64url("Zm8"), b"fo")
        self.assertEqual(gat._b64url("-_-_"), b"\xfb\xff\xbf")
        for segment in ("", "Zm8=", "Zm9v\n", "Zm 9v", "Zm+v", "Zm/v", "A", "Zm9v.", "\xe9", None, b"Zm9v"):
            with self.subTest(segment=segment), self.assertRaises(gat.TokenError):
                gat._b64url(segment)


if __name__ == "__main__":
    unittest.main()
