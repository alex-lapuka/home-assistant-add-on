"""Verification of Twingate Gateway Access Tokens (GATs) for the API proxy.

The Gateway in this add-on verifies the GAT of every client connection and
passes it on to the proxy in a request header ({{jwt}}). The proxy cannot
trust that header by itself, because anything that reaches its port can set
it, so it verifies the token again, as the Gateway does
(internal/token/parser.go and gat_claims.go of Twingate Gateway 2.1.0):

- signed with ES256 (the only algorithm accepted) by a key of the network's
  key set at https://<network>.twingate.com/api/v1/jwk/ec;
- iss "twingate", aud containing the network name, exp in the future, iat
  and nbf (when present) not in the future;
- typ "GAT", ver "1", and rnw, cpk, user.id, user.username, resource.id and
  resource.address present; ports and TLS modes valid.

Then it checks that the token was issued for a Resource whose upstream is
this proxy (see Binding). It cannot check the token's client-key binding
(the Gateway checks it against the TLS session of the client connection),
so a valid token for this Resource is accepted from anyone who holds it
until it expires.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ISSUER = "twingate"
GAT_TYPE = "GAT"
GAT_VERSION = "1"
RESOURCE_TYPE_WEB_APP = "WEB_APP"
TLS_SERVER_MODES = ("TLS13", "NONE")
TLS_CLIENT_MODES = ("VERIFY_FULL", "VERIFY_CA", "INSECURE", "NONE")

MAX_TOKEN_BYTES = 32 * 1024
MAX_JWKS_BYTES = 256 * 1024
MAX_KEYS = 32
MAX_CACHED_TOKENS = 1024
JWKS_REFRESH_INTERVAL = 3600.0
JWKS_RETRY_INTERVAL = 60.0
# A token with a key ID that is not in the key set makes the proxy read the
# key set again, at most this often, so that unknown key IDs cannot make it
# flood Twingate with requests.
JWKS_UNKNOWN_KID_INTERVAL = 60.0

_NO_PROXY = urllib.request.ProxyHandler({})
_B64URL = re.compile(r"[A-Za-z0-9_-]+")


class TokenError(Exception):
    """A token that is not accepted, with the reason for the add-on log."""


def _b64url(segment: str) -> bytes:
    # Unpadded base64url only: Python's decoder would otherwise skip
    # characters outside the alphabet.
    if not isinstance(segment, str) or not _B64URL.fullmatch(segment):
        raise TokenError("malformed token")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError):
        raise TokenError("malformed token") from None


def _json_object(data: bytes) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        raise TokenError("malformed token") from None
    if not isinstance(value, dict):
        raise TokenError("malformed token")
    return value


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


# ----------------------------------------------------------------------------
# Signing keys
# ----------------------------------------------------------------------------


class _TwingateRedirects(urllib.request.HTTPRedirectHandler):
    """Follows at most 3 redirects, and only to HTTPS addresses on twingate.com."""

    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        parts = urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not (host == "twingate.com" or host.endswith(".twingate.com")):
            raise urllib.error.HTTPError(newurl, code, "redirect outside twingate.com", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_jwks(document: object) -> dict[str | None, ec.EllipticCurvePublicKey]:
    """The P-256 keys of a JWK set by key ID (None for a key without one)."""
    keys: dict[str | None, ec.EllipticCurvePublicKey] = {}
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise TypeError("not a key set")
    for entry in entries[:MAX_KEYS]:
        if not isinstance(entry, dict) or entry.get("kty") != "EC" or entry.get("crv") != "P-256":
            continue
        if entry.get("alg") not in (None, "ES256") or entry.get("use") not in (None, "sig"):
            continue
        try:
            x = _b64url(_text(entry.get("x")))
            y = _b64url(_text(entry.get("y")))
            if len(x) != 32 or len(y) != 32:
                continue
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        except (TokenError, ValueError):
            continue
        kid = entry.get("kid")
        keys[kid if isinstance(kid, str) else None] = key
    return keys


def fetch_jwks(network: str, timeout: float = 10.0) -> dict[str | None, ec.EllipticCurvePublicKey]:
    """Reads the network's signing keys; raises on any failure."""
    url = f"https://{network}.twingate.com/api/v1/jwk/ec"
    opener = urllib.request.build_opener(_NO_PROXY, _TwingateRedirects())
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "twingate-gateway-addon"})
    with opener.open(request, timeout=timeout) as response:
        body = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("key set too large")
    try:
        document = json.loads(body)
    except (ValueError, RecursionError):
        raise ValueError("not JSON") from None
    keys = parse_jwks(document)
    if not keys:
        raise ValueError("no P-256 keys")
    return keys


class KeyStore:
    """The network's signing keys, read again every hour and on an unknown key ID.

    Reading happens in the caller's thread (the proxy calls it in a worker
    thread); one read at a time.
    """

    def __init__(self, network: str, fetch=fetch_jwks, clock=time.monotonic) -> None:
        self._network = network
        self._fetch = fetch
        self._clock = clock
        # _fetch_lock: one read of the key set at a time; _lock: the keys
        # themselves, never held during a read, so that verifying tokens
        # does not wait for Twingate.
        self._fetch_lock = threading.Lock()
        self._lock = threading.Lock()
        self._keys: dict[str | None, ec.EllipticCurvePublicKey] = {}
        self._loaded_at: float | None = None
        self._attempt_at: float | None = None
        self.state: dict = {"ok": False, "keys": 0, "checked_at": None, "error": "not read yet"}

    def refresh(self, force: bool = False) -> bool:
        """Reads the key set if due (or when forced and not read within the last minute).

        Returns whether new keys were loaded.
        """
        with self._fetch_lock:
            now = self._clock()
            if self._attempt_at is not None:
                since = now - self._attempt_at
                if force and since < JWKS_UNKNOWN_KID_INTERVAL:
                    return False
                if not force:
                    due = JWKS_REFRESH_INTERVAL if self._loaded_at == self._attempt_at else JWKS_RETRY_INTERVAL
                    if since < due:
                        return False
            self._attempt_at = now
            error_text = None
            keys: dict = {}
            try:
                keys = self._fetch(self._network)
            except urllib.error.HTTPError as error:
                error_text = f"HTTP {error.code}"
            except Exception as error:  # noqa: BLE001 - any failure keeps the previous keys
                reason = getattr(error, "reason", None)
                error_text = type(reason).__name__ if isinstance(reason, BaseException) else type(error).__name__
            with self._lock:
                if error_text is not None:
                    self.state = {"ok": bool(self._keys), "keys": len(self._keys), "checked_at": round(time.time(), 3), "error": error_text}
                    return False
                self._keys = keys
                self._loaded_at = now
                self.state = {"ok": True, "keys": len(keys), "checked_at": round(time.time(), 3), "error": None}
                return True

    def keys_for(self, kid: str | None) -> list[ec.EllipticCurvePublicKey]:
        with self._lock:
            if kid is not None:
                key = self._keys.get(kid)
                return [key] if key is not None else []
            return list(self._keys.values())

    def has_kid(self, kid: str | None) -> bool:
        with self._lock:
            return kid is None or kid in self._keys


# ----------------------------------------------------------------------------
# Binding
# ----------------------------------------------------------------------------


class Binding:
    """Which Resources' tokens are for this proxy.

    The Gateway forwards a request to the Resource address and the upstream
    port in the token, so a token reaches the proxy through the Gateway only
    if the Resource points at it. Accepted are Web App Resources with
    upstream TLS mode NONE (the proxy speaks plain HTTP) and either
    - the address of this add-on on the Supervisor's network (its host name,
      also with .local.hass.io) and upstream port PORT, the container port
      the Gateway reaches without a published port; or
    - when PORT is published on the host as HOST_PORT: an IPv4 address and
      upstream port HOST_PORT. The add-on cannot learn the host's LAN
      address without wider Supervisor API access, so any IPv4 address other
      than loopback and 0.0.0.0 is accepted then.
    """

    def __init__(self, hostnames: list[str], port: int, host_port: int | None) -> None:
        self.hostnames = frozenset(name.lower().rstrip(".") for name in hostnames if name)
        self.port = port
        self.host_port = host_port

    def check(self, resource: dict) -> None:
        if resource.get("type") != RESOURCE_TYPE_WEB_APP:
            raise TokenError(f"the token is for a {_text(resource.get('type')) or 'non-Web App'} Resource")
        metadata = resource.get("gateway_metadata") if isinstance(resource.get("gateway_metadata"), dict) else {}
        upstream = metadata.get("upstream") if isinstance(metadata.get("upstream"), dict) else {}
        address = _text(resource.get("address")).lower().rstrip(".")
        port = upstream.get("port")
        if upstream.get("tls_mode") != "NONE":
            raise TokenError(f"the token's Resource uses upstream TLS mode {_text(upstream.get('tls_mode'))}, not NONE")
        if address in self.hostnames and port == self.port:
            return
        if self.host_port is not None and port == self.host_port and _plain_ipv4(address):
            return
        raise TokenError(f"the token is for Resource address {address!r} with upstream port {port}, not this proxy")


def _plain_ipv4(address: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


# ----------------------------------------------------------------------------
# Tokens
# ----------------------------------------------------------------------------


class Identity:
    """The caller of a verified token.

    The groups in the token are not kept: the access level is the same for
    every caller (see access_rules.py).
    """

    __slots__ = ("expires_at", "resource_id", "user_id", "username")

    def __init__(self, username: str, user_id: str, resource_id: str, expires_at: float) -> None:
        self.username = username
        self.user_id = user_id
        self.resource_id = resource_id
        self.expires_at = expires_at


def _valid_port(value: object) -> bool:
    return type(value) is int and 1 <= value <= 65535


def check_claims(claims: dict, network: str, now: float) -> None:
    """The checks of the Gateway's token parser and of GATClaims.Validate."""
    if claims.get("iss") != ISSUER:
        raise TokenError("wrong issuer")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
    if network not in [item for item in audiences if isinstance(item, str)]:
        raise TokenError("wrong audience")
    expires = _number(claims.get("exp"))
    if expires is None:
        raise TokenError("no expiry")
    if now >= expires:
        raise TokenError("expired")
    for name in ("iat", "nbf"):
        if name in claims:
            value = _number(claims.get(name))
            if value is None or value > now:
                raise TokenError(f"{name} in the future or invalid")
    for name in ("typ", "ver", "cpk"):
        if not _text(claims.get(name)):
            raise TokenError(f"claim {name} missing")
    if _number(claims.get("rnw")) is None:
        raise TokenError("claim rnw missing")
    if claims.get("typ") != GAT_TYPE:
        raise TokenError("not a Gateway Access Token")
    if claims.get("ver") != GAT_VERSION:
        raise TokenError("unsupported token version")
    user = claims.get("user")
    resource = claims.get("resource")
    if not isinstance(user, dict) or not _text(user.get("id")) or not _text(user.get("username")):
        raise TokenError("user missing")
    if not isinstance(resource, dict) or not _text(resource.get("id")) or not _text(resource.get("address")):
        raise TokenError("resource missing")
    metadata = resource.get("gateway_metadata") if isinstance(resource.get("gateway_metadata"), dict) else {}
    downstream = metadata.get("downstream") if isinstance(metadata.get("downstream"), dict) else {}
    upstream = metadata.get("upstream") if isinstance(metadata.get("upstream"), dict) else {}
    if not _valid_port(downstream.get("port")) or not _valid_port(upstream.get("port")):
        raise TokenError("invalid port")
    if resource.get("type") == RESOURCE_TYPE_WEB_APP and (
        downstream.get("tls_mode") not in TLS_SERVER_MODES or upstream.get("tls_mode") not in TLS_CLIENT_MODES
    ):
        raise TokenError("invalid TLS mode")
    # The proxy does not use the groups, but the Gateway refuses a token whose
    # groups are not a list, and so does the proxy.
    groups = user.get("groups", [])
    if groups is not None and not isinstance(groups, list):
        raise TokenError("invalid groups")


class Verifier:
    """Verifies tokens and keeps verified ones until they expire."""

    def __init__(self, network: str, binding: Binding, keys: KeyStore, clock=time.time) -> None:
        self.network = network
        self.binding = binding
        self.keys = keys
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: OrderedDict[bytes, Identity] = OrderedDict()

    def cached(self, token: str) -> Identity | None:
        digest = hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()
        now = self._clock()
        with self._lock:
            identity = self._cache.get(digest)
            if identity is None:
                return None
            if now >= identity.expires_at:
                del self._cache[digest]
                return None
            self._cache.move_to_end(digest)
            return identity

    def needs_keys(self, token: str) -> bool:
        """Whether the token names a key ID that is not in the key set."""
        try:
            header = _json_object(_b64url(token.split(".", 1)[0]))
        except TokenError:
            return False
        kid = header.get("kid")
        return isinstance(kid, str) and not self.keys.has_kid(kid)

    def verify(self, token: str) -> Identity:
        """Returns the caller of a valid token for this proxy, or raises TokenError."""
        if not token or len(token) > MAX_TOKEN_BYTES:
            raise TokenError("missing or oversized token")
        cached = self.cached(token)
        if cached is not None:
            return cached
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("malformed token")
        header = _json_object(_b64url(parts[0]))
        if header.get("alg") != "ES256":
            raise TokenError(f"algorithm {_text(header.get('alg'))!r} not accepted")
        if "crit" in header:
            raise TokenError("unsupported critical header")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise TokenError("malformed token")
        signature = _b64url(parts[2])
        if len(signature) != 64:
            raise TokenError("bad signature")
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        signed = f"{parts[0]}.{parts[1]}".encode("ascii", "strict") if parts[0].isascii() and parts[1].isascii() else None
        if signed is None:
            raise TokenError("malformed token")
        candidates = self.keys.keys_for(kid)
        if not candidates:
            raise TokenError("unknown signing key" if self.keys.state.get("ok") else "signing keys not available")
        for key in candidates:
            try:
                key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
                break
            except InvalidSignature:
                continue
        else:
            raise TokenError("bad signature")
        claims = _json_object(_b64url(parts[1]))
        now = self._clock()
        check_claims(claims, self.network, now)
        resource = claims["resource"]
        self.binding.check(resource)
        user = claims["user"]
        identity = Identity(user["username"], user["id"], resource["id"], float(claims["exp"]))
        digest = hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()
        with self._lock:
            self._cache[digest] = identity
            while len(self._cache) > MAX_CACHED_TOKENS:
                self._cache.popitem(last=False)
        return identity
