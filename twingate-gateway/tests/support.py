"""Shared helpers of the unit tests.

Puts the add-on's Python directories on sys.path and imports the modules
under test from there, and makes Twingate Gateway Access Tokens (GATs)
signed with a P-256 key that is created for each test run. Nothing here
opens a network connection, starts a server or reads the real time: tests
pass a FakeClock wherever the code takes a clock.
"""

from __future__ import annotations

import base64
import importlib
import json
import sys
import types
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from multidict import CIMultiDict, CIMultiDictProxy

ADDON_DIR = Path(__file__).resolve().parent.parent
LIB_DIR = ADDON_DIR / "rootfs" / "usr" / "lib"
PROXY_DIR = LIB_DIR / "twingate-gateway-proxy"
UI_DIR = LIB_DIR / "twingate-gateway-ui"

# The modules are imported from the add-on's own tree, as the image runs
# them; no __pycache__ is written into that tree.
sys.dont_write_bytecode = True
for _directory in (UI_DIR, PROXY_DIR):
    if str(_directory) not in sys.path:
        sys.path.insert(0, str(_directory))


def _stub_posix_modules() -> None:
    """Lets audit_relay be imported where grp and pwd do not exist (Windows).

    The add-on runs on Linux, where they exist and are used unchanged. Only
    audit_relay.copy_ids() uses them, which no test calls; the stubs know no
    user or group.
    """
    for name, function in (("grp", "getgrnam"), ("pwd", "getpwnam")):
        try:
            importlib.import_module(name)
        except ModuleNotFoundError:
            module = types.ModuleType(name)

            def unknown(entry: str) -> None:
                raise KeyError(entry)

            setattr(module, function, unknown)
            sys.modules[name] = module


access_rules = importlib.import_module("access_rules")
gat = importlib.import_module("gat")
supervisor_proxy = importlib.import_module("supervisor_proxy")
_stub_posix_modules()
audit_relay = importlib.import_module("audit_relay")

# ----------------------------------------------------------------------------
# Grants
# ----------------------------------------------------------------------------

GRANTS = {
    "none": frozenset(),
    "read": frozenset({access_rules.READ}),
    "mcp": frozenset({access_rules.MCP}),
    "read+mcp": frozenset({access_rules.READ, access_rules.MCP}),
    "full": frozenset({access_rules.READ, access_rules.MCP, access_rules.FULL}),
}

# ----------------------------------------------------------------------------
# Time
# ----------------------------------------------------------------------------

# A fixed "now" for every token test (2030-03-17), never the real time.
NOW = 1_900_000_000.0


class FakeClock:
    """A clock for KeyStore and Verifier that moves only when a test says so."""

    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ----------------------------------------------------------------------------
# Tokens
# ----------------------------------------------------------------------------

NETWORK = "examplenet"
# The add-on's host name on the Supervisor's network, as /run.sh writes it to
# the proxy's configuration (with and without the .local.hass.io suffix).
HOSTNAME = "a0b1c2d3-twingate-gateway"
HOSTNAMES = [HOSTNAME, f"{HOSTNAME}.local.hass.io"]
PROXY_PORT = 8124

# Leaves a header field or claim out of a token.
DROP = object()


def b64url(data: bytes) -> str:
    """Unpadded base64url, as in a JWT."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_segment(value: object) -> str:
    return b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def resource(
    *,
    address: str = HOSTNAME,
    upstream_port: object = PROXY_PORT,
    upstream_tls: object = "NONE",
    downstream_port: object = 443,
    downstream_tls: object = "TLS13",
    kind: object = "WEB_APP",
) -> dict:
    """The resource claim of a GAT for a Web App Resource."""
    return {
        "id": "resource-1",
        "type": kind,
        "address": address,
        "gateway_metadata": {
            "downstream": {"port": downstream_port, "tls_mode": downstream_tls},
            "upstream": {"port": upstream_port, "tls_mode": upstream_tls},
        },
    }


def gat_claims(**changes: object) -> dict:
    """The claims of a valid GAT for this proxy at NOW; DROP removes a claim."""
    claims = {
        "iss": "twingate",
        "aud": [NETWORK],
        "iat": int(NOW) - 5,
        "nbf": int(NOW) - 5,
        "exp": int(NOW) + 600,
        "typ": "GAT",
        "ver": "1",
        "rnw": int(NOW) + 300,
        "cpk": "Y2xpZW50LWtleQ",
        "user": {"id": "user-1", "username": "alice@example.com", "groups": ["Everyone", "Home Admins"]},
        "device": {"id": "device-1"},
        "resource": resource(),
    }
    claims.update(changes)
    return {name: value for name, value in claims.items() if value is not DROP}


_CURVES = {
    "P-256": (ec.SECP256R1, hashes.SHA256, "ES256"),
    "P-384": (ec.SECP384R1, hashes.SHA384, "ES384"),
}


class Signer:
    """An ECDSA signing key of a made-up Twingate network (P-256: ES256)."""

    def __init__(self, kid: str, curve: str = "P-256") -> None:
        curve_class, self._digest, self.alg = _CURVES[curve]
        self.kid = kid
        self.curve = curve
        self.key = ec.generate_private_key(curve_class())
        self.size = (self.key.curve.key_size + 7) // 8

    def jwk(self, **changes: object) -> dict:
        """The public key as an entry of a JWK set; DROP removes a member."""
        numbers = self.key.public_key().public_numbers()
        entry = {
            "kty": "EC",
            "crv": self.curve,
            "kid": self.kid,
            "alg": self.alg,
            "use": "sig",
            "x": b64url(numbers.x.to_bytes(self.size, "big")),
            "y": b64url(numbers.y.to_bytes(self.size, "big")),
        }
        entry.update(changes)
        return {name: value for name, value in entry.items() if value is not DROP}

    def der_signature(self, signing_input: bytes) -> bytes:
        """The signature as cryptography makes it: DER, not JWS."""
        return self.key.sign(signing_input, ec.ECDSA(self._digest()))

    def raw_signature(self, signing_input: bytes) -> bytes:
        """The JWS form of the signature: r and s, 32 bytes each for P-256."""
        r, s = decode_dss_signature(self.der_signature(signing_input))
        return r.to_bytes(self.size, "big") + s.to_bytes(self.size, "big")

    def sign_segments(self, header_segment: str, payload_segment: str) -> str:
        signing_input = f"{header_segment}.{payload_segment}"
        return f"{signing_input}.{b64url(self.raw_signature(signing_input.encode('ascii')))}"

    def token(self, claims: dict | None = None, **header: object) -> str:
        """A signed GAT; header fields override alg ES256 and this key's kid."""
        fields = {"alg": self.alg, "kid": self.kid, "typ": "JWT"}
        fields.update(header)
        fields = {name: value for name, value in fields.items() if value is not DROP}
        return self.sign_segments(json_segment(fields), json_segment(gat_claims() if claims is None else claims))


# Created once per test run, never stored anywhere.
SIGNER = Signer("key-1")
OTHER_SIGNER = Signer("key-2")


class FakeFetch:
    """Stands in for gat.fetch_jwks: the keys of a JWK set document, or an error."""

    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0

    def __call__(self, _network: str) -> dict:
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return gat.parse_jwks(self.result)


def jwks(*signers: Signer) -> dict:
    return {"keys": [signer.jwk() for signer in signers]}


def binding(host_port: int | None = None) -> object:
    return gat.Binding(HOSTNAMES, PROXY_PORT, host_port)


def verifier(*signers: Signer, clock: FakeClock | None = None, host_port: int | None = None) -> object:
    """A Verifier whose key set (by default SIGNER's key) was read once."""
    store = gat.KeyStore(NETWORK, fetch=FakeFetch(jwks(*(signers or (SIGNER,)))), clock=FakeClock())
    store.refresh()
    return gat.Verifier(NETWORK, binding(host_port), store, clock=clock or FakeClock())


# ----------------------------------------------------------------------------
# Requests
# ----------------------------------------------------------------------------


def headers(*pairs: tuple[str, str]) -> CIMultiDictProxy:
    """Request headers as aiohttp gives them: case-insensitive, repeatable."""
    return CIMultiDictProxy(CIMultiDict(pairs))
