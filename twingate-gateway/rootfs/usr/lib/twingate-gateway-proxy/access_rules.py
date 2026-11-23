"""Access rules of the Home Assistant API proxy in the Twingate Gateway add-on.

Every caller acts as the same Home Assistant user (the Supervisor's system
user, an administrator), so the proxy decides what each caller may do, from
the Twingate groups in its verified Gateway Access Token:

- Read (option read_groups): reads over REST and WebSocket, no actions. An
  allow-list: only the REST requests and WebSocket command types listed
  below; everything else is denied. With read_groups empty, every verified
  caller has Read.
- MCP (option mcp_groups): the Model Context Protocol endpoint /api/mcp,
  every method. Nobody when empty.
- Full (option full_groups): everything that is not always blocked;
  includes Read and MCP. Nobody when empty.

A caller holds the union of the grants of all its groups. Read and MCP are
independent. Some requests are blocked for everyone, Full included, because
they lead from Home Assistant into the Supervisor or the host, or manage
accounts and credentials (see ALWAYS_BLOCKED_*). Full is a block-list on an
administrator API: indirect routes to a blocked action remain (for example a
script or automation that calls it), so it is not a security boundary.

The lists were checked against Home Assistant Core 2026.11.2. Python
standard library only, so that the rules can be tested anywhere.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

if TYPE_CHECKING:
    from collections.abc import Iterable

READ = "read"
MCP = "mcp"
FULL = "full"
GRANT_ORDER = (FULL, READ, MCP)

# ----------------------------------------------------------------------------
# Grants
# ----------------------------------------------------------------------------


class Rules:
    """The three group lists of the add-on options."""

    def __init__(self, read_groups: Iterable[str], mcp_groups: Iterable[str], full_groups: Iterable[str]) -> None:
        self.read_groups = frozenset(read_groups)
        self.mcp_groups = frozenset(mcp_groups)
        self.full_groups = frozenset(full_groups)

    def grants(self, groups: Iterable[str]) -> frozenset[str]:
        """The union of the grants of all the caller's groups."""
        member = {group for group in groups if isinstance(group, str)}
        grants: set[str] = set()
        if not self.read_groups or member & self.read_groups:
            grants.add(READ)
        if member & self.mcp_groups:
            grants.add(MCP)
        if member & self.full_groups:
            grants.update((READ, MCP, FULL))
        return frozenset(grants)

    def describe(self) -> list[str]:
        """One line per grant, for the add-on log."""

        def names(groups: frozenset[str]) -> str:
            return ", ".join(f'"{group}"' for group in sorted(groups))

        read = f"members of {names(self.read_groups)}" if self.read_groups else "everyone with access to the Resource"
        mcp = f"members of {names(self.mcp_groups)}" if self.mcp_groups else "nobody"
        full = f"members of {names(self.full_groups)}" if self.full_groups else "nobody"
        return [f"Read: {read}", f"MCP: {mcp}", f"Full (includes Read and MCP): {full}"]


def grant_label(grants: frozenset[str]) -> str:
    """A short label of a caller's grants for logs: full, read+mcp, read, mcp or none."""
    if FULL in grants:
        return FULL
    return "+".join(grant for grant in (READ, MCP) if grant in grants) or "none"


# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------

# Characters a request path may contain as sent. Percent signs must start an
# escape of two hex digits.
_RAW_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
# Escapes that would let a path mean something else after another decoding
# or path normalization: slash, backslash, NUL, percent, dot, and the query
# and fragment separators.
_AMBIGUOUS_ESCAPES = ("%2f", "%5c", "%00", "%25", "%2e", "%3f", "%23")

WEBHOOK_PREFIX = "/api/webhook/"


def canonical_path(raw_path: str) -> str | None:
    """Decodes a request path once, as Home Assistant routes it, or None if unclear.

    The Supervisor forwards the path byte for byte and Home Assistant decodes
    it once. Paths that could decode to something else in another component
    (encoded slashes, dots, percent signs, question marks or hashes, dot
    segments, empty segments, control characters) are refused instead of
    being matched.
    """
    if not isinstance(raw_path, str) or len(raw_path) > 2048 or not _RAW_PATH.fullmatch(raw_path):
        return None
    if _BAD_ESCAPE.search(raw_path):
        return None
    lowered = raw_path.lower()
    if any(escape in lowered for escape in _AMBIGUOUS_ESCAPES):
        return None
    try:
        path = unquote(raw_path, errors="strict")
    except UnicodeDecodeError:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        return None
    if "//" in path or "\\" in path or "?" in path or "#" in path:
        return None
    if any(segment in (".", "..") for segment in path.split("/")):
        return None
    return path


def _authority(scheme: str, host_port: str) -> str | None:
    """host:port in lower case, with the scheme's default port added."""
    if not host_port or any(char in host_port for char in "/@ \t"):
        return None
    host_port = host_port.lower()
    if host_port.startswith("["):
        host, _, rest = host_port.partition("]")
        host += "]"
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = host_port.partition(":")
    port = port or {"http": "80", "https": "443", "ws": "80", "wss": "443"}.get(scheme, "")
    if not host or not port.isdigit():
        return None
    return f"{host}:{int(port)}"


def cross_site_browser_request(origin: str | None, fetch_site: str | None, host: str | None) -> bool:
    """Whether a request comes from a web page of another site, in a browser.

    The Twingate Client adds the caller's identity to every connection to the
    Resource, including those a browser on the same device opens for any
    website. Such a page could send actions, or open the WebSocket API,
    whose authentication accepts any placeholder here. Browsers mark these
    requests: Sec-Fetch-Site other than same-origin or none, or an Origin
    that is not the address the request was sent to. Scripts and agents send
    neither header, or an Origin of the address itself.
    """
    if fetch_site is not None and fetch_site.strip().lower() not in ("same-origin", "none"):
        return True
    if origin is None:
        return False
    scheme, separator, rest = origin.strip().partition("://")
    if not separator or scheme.lower() not in ("http", "https"):
        return True
    origin_authority = _authority(scheme.lower(), rest.rstrip("/"))
    # The Gateway passes on the Host the client used; the request reached
    # the Gateway over plain HTTP or TLS, so either default port matches.
    host_value = (host or "").strip()
    candidates = {_authority("http", host_value), _authority("https", host_value)}
    return origin_authority is None or origin_authority not in candidates


def mask_path(path: str) -> str:
    """Masks the webhook ID in /api/webhook/<id>: anyone who knows it can trigger the webhook."""
    start = path.lower().find(WEBHOOK_PREFIX)
    if start < 0:
        return path
    return path[: start + len(WEBHOOK_PREFIX)] + "***"


# ----------------------------------------------------------------------------
# REST
# ----------------------------------------------------------------------------

MCP_PATH = "/api/mcp"
WEBSOCKET_PATH = "/api/websocket"


def is_mcp_path(path: str) -> bool:
    """/api/mcp and the per-API endpoints /api/mcp/<id>."""
    return path == MCP_PATH or path.startswith(MCP_PATH + "/")

# Service domains whose actions are always blocked: the Supervisor
# integration (apps, host reboot and shutdown, backups and restores) and the
# backup integration, which creates backups through the Supervisor.
BLOCKED_SERVICE_DOMAINS = frozenset({"hassio", "backup"})

# REST paths that are always blocked (compared without regard to case):
# - /api/hassio..., /api/hassio_ingress/..., /api/hassio_auth...,
#   /api/hassio_push/...: Core's own proxies into the Supervisor, its add-on
#   ingress proxy and its Supervisor login endpoints (the Supervisor also
#   refuses /core/api/hassio/ and /core/api/hassio_).
# - /api/backup/...: download (every secret of the installation) and upload
#   of backups.
# - /api/onboarding...: creates the owner account and restores backups
#   during onboarding.
# - /api/repairs/issues/fix...: repair flows; those of the Supervisor
#   integration reboot the host or repair the system, and a running flow
#   cannot be told apart by its ID.
ALWAYS_BLOCKED_REST = re.compile(
    r"/api/(?:hassio.*|backup(?:/.*)?|onboarding(?:/.*)?|repairs/issues/fix(?:/.*)?)",
    re.IGNORECASE | re.DOTALL,
)
# /api/services/<domain>/<service>, and anything below it.
_SERVICE_PATH = re.compile(r"/api/services/([^/]*)(?:/.*)?", re.IGNORECASE | re.DOTALL)

# The REST requests that are reads, checked against the views of Home
# Assistant Core 2026.11.2. HEAD is allowed wherever GET is.
READ_REST: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (method, re.compile(pattern))
    for method, pattern in (
        ("GET", r"/api/"),  # API status
        ("GET", r"/api/config"),  # core configuration
        ("GET", r"/api/core/state"),  # run state
        ("GET", r"/api/components"),  # loaded integrations
        ("GET", r"/api/states"),  # all states
        ("GET", r"/api/states/[^/]+"),  # one state (POST and DELETE change it)
        ("GET", r"/api/services"),  # available actions
        ("GET", r"/api/events"),  # event listener counts (POST fires an event)
        ("GET", r"/api/history/period(?:/[^/]+)?"),  # history
        ("GET", r"/api/logbook(?:/[^/]+)?"),  # logbook
        ("GET", r"/api/calendars"),  # calendar entities
        ("GET", r"/api/calendars/[^/]+"),  # calendar events in a time range
        ("GET", r"/api/config/config_entries/entry"),  # integration entries (no credentials)
        # Not POST /api/template: a template cannot act, but an expensive one
        # can keep Home Assistant busy.
    )
)


def blocked_service_domain(domain: object) -> bool:
    """Whether an action domain is always blocked; Home Assistant lower-cases it."""
    if not isinstance(domain, str):
        return True
    return domain.strip().lower() in BLOCKED_SERVICE_DOMAINS


def rest_always_blocked(path: str) -> bool:
    if ALWAYS_BLOCKED_REST.fullmatch(path):
        return True
    service = _SERVICE_PATH.fullmatch(path)
    return bool(service and blocked_service_domain(service.group(1)))


def rest_is_read(method: str, path: str) -> bool:
    check = "GET" if method == "HEAD" else method
    return any(check == allowed and pattern.fullmatch(path) for allowed, pattern in READ_REST)


def decide_rest(method: str, path: str, grants: frozenset[str]) -> tuple[bool, str]:
    """Whether a REST request is allowed, and why: blocked, mcp, full, read or denied."""
    if rest_always_blocked(path):
        return False, "blocked"
    if path == MCP_PATH:
        return (MCP in grants), ("mcp" if MCP in grants else "denied")
    if FULL in grants:
        return True, "full"
    if READ in grants and rest_is_read(method, path):
        return True, "read"
    return False, "denied"


# ----------------------------------------------------------------------------
# MCP
# ----------------------------------------------------------------------------

# Tools of the Supervisor integration (for example hassio__get_logs, which
# reads the logs of the host, the Supervisor and every app through the
# Supervisor). Home Assistant names an LLM tool after its integration.
BLOCKED_MCP_TOOL_PREFIX = "hassio__"
# Tools that call any action, given as "action" in their arguments:
# homeassistant__call_action of the Home Assistant LLM API, which the MCP
# Server integration offers by default. Any API's tool with this name ending
# is checked.
CALL_ACTION_TOOL_SUFFIX = "call_action"
MAX_MCP_BODY_BYTES = 4 * 1024 * 1024


def mcp_content_type_ok(content_type: str | None) -> bool:
    """application/json, with no parameter or only charset=utf-8.

    Home Assistant decodes the body with the charset it is given; with only
    UTF-8 allowed, it reads the same JSON as the proxy checked.
    """
    if not isinstance(content_type, str):
        return False
    media, *parameters = (part.strip() for part in content_type.split(";"))
    if media.lower() != "application/json":
        return False
    for parameter in parameters:
        name, _, value = parameter.partition("=")
        if name.strip().lower() != "charset" or value.strip().strip('"').lower() not in ("utf-8", "utf8"):
            return False
    return True


def _blocked_action(arguments: object) -> bool:
    """Whether call_action arguments name a blocked action, or none that can be checked."""
    action = arguments.get("action") if isinstance(arguments, dict) else None
    if not isinstance(action, str):
        return True
    match = _PLAIN_ACTION.fullmatch(action.strip().lower())
    return match is None or match.group(1) in BLOCKED_SERVICE_DOMAINS


def inspect_mcp_body(body: bytes) -> tuple[str, object]:
    """Checks an MCP request body: ("ok", None), ("invalid", None) or ("blocked", id).

    The body must be UTF-8 JSON: one object, or an array of objects (Home
    Assistant accepts single messages only; arrays are checked all the same).
    Refused for every caller: calls to the Supervisor integration's tools,
    and calls to a call_action tool whose action is in a blocked domain or is
    not plain text "domain.action" (Home Assistant accepts it only in that
    form). A body the proxy cannot read is never passed on.
    """
    if len(body) > MAX_MCP_BODY_BYTES:
        return "invalid", None
    try:
        message = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "invalid", None
    items = message if isinstance(message, list) else [message]
    if not items or not all(isinstance(item, dict) for item in items):
        return "invalid", None
    for item in items:
        if item.get("method") != "tools/call":
            continue
        params = item.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            return "blocked", item.get("id")
        lowered = name.strip().lower()
        if lowered.startswith(BLOCKED_MCP_TOOL_PREFIX):
            return "blocked", item.get("id")
        if lowered.endswith(CALL_ACTION_TOOL_SUFFIX) and _blocked_action(params.get("arguments")):
            return "blocked", item.get("id")
    return "ok", None


# ----------------------------------------------------------------------------
# WebSocket
# ----------------------------------------------------------------------------

# Command types blocked for everyone: a type equal to one of these or below
# it ("auth" and "auth/..."), compared without regard to case.
# - supervisor/...: supervisor/api reaches the whole Supervisor API with Home
#   Assistant's own Supervisor token; also supervisor/subscribe, /event and
#   the ingress session commands (the Supervisor refuses supervisor/ too).
# - hassio/...: app and Core updates through the Supervisor and their
#   backup settings.
# - auth/...: long-lived access tokens, signed paths, refresh tokens, MFA.
# - config/auth/... and config/auth_provider/...: users, passwords, usernames.
# - backup/...: creating, restoring, deleting and configuring backups (in
#   Home Assistant OS through the Supervisor), and their encryption keys.
# - debug_console/...: runs Python inside Home Assistant, which can call the
#   Supervisor with Home Assistant's own token.
ALWAYS_BLOCKED_WS_PREFIXES = (
    "supervisor",
    "hassio",
    "auth",
    "config/auth",
    "config/auth_provider",
    "backup",
    "debug_console",
)

# Command types that only read or subscribe, checked against Home Assistant
# Core 2026.11.2. subscribe_events is limited further below.
READ_WS = frozenset(
    {
        # Connection
        "ping",
        "supported_features",
        "unsubscribe_events",
        # States, configuration, actions available
        "get_states",
        "get_config",
        "get_services",
        "subscribe_entities",
        "subscribe_events",
        "entity/source",
        "manifest/list",
        "manifest/get",
        "extract_from_target",
        "get_services_for_target",
        # Not render_template: see READ_REST. The connection's own user,
        # which client libraries such as Node-RED's ask for right after
        # connecting.
        "auth/current_user",
        # Registries
        "config/entity_registry/list",
        "config/entity_registry/list_for_display",
        "config/entity_registry/get",
        "config/entity_registry/get_entries",
        "config/device_registry/list",
        "config/area_registry/list",
        "config/floor_registry/list",
        "config/label_registry/list",
        "config/category_registry/list",
        "config_entries/get",
        # History, logbook, statistics, energy
        "history/history_during_period",
        "history/stream",
        "logbook/get_events",
        "logbook/event_stream",
        "recorder/statistics_during_period",
        "recorder/statistic_during_period",
        "recorder/list_statistic_ids",
        "recorder/get_statistics_metadata",
        "energy/get_prefs",
        "energy/info",
        # Other reads
        "search/related",
        "todo/item/list",
        "todo/item/subscribe",
        "calendar/event/subscribe",
        "weather/subscribe_forecast",
        "persistent_notification/get",
        "persistent_notification/subscribe",
        "repairs/list_issues",
        "lovelace/config",
        "lovelace/dashboards/list",
        "lovelace/info",
    }
)

# The events Home Assistant lets a non-administrator subscribe to
# (homeassistant/auth/permissions/events.py, SUBSCRIBE_ALLOWLIST): they hold
# no sensitive data. Others, such as call_service, can carry codes and
# passwords given to actions.
READ_EVENT_TYPES = frozenset(
    {
        "area_registry_updated",
        "category_registry_updated",
        "component_loaded",
        "core_config_updated",
        "device_registry_updated",
        "entity_registry_updated",
        "floor_registry_updated",
        "label_registry_updated",
        "labs_updated",
        "lovelace_updated",
        "panels_updated",
        "recorder_5min_statistics_generated",
        "recorder_hourly_statistics_generated",
        "repairs_issue_registry_updated",
        "service_registered",
        "service_removed",
        "shopping_list_updated",
        "state_changed",
        "themes_updated",
    }
)

_PLAIN_ACTION = re.compile(r"([a-z0-9_]+)\.[a-z0-9_]+")
# Keys of a script step whose values are data, not steps.
_SCRIPT_DATA_KEYS = frozenset({"data", "data_template", "target", "metadata", "variables", "event_data", "event_data_template", "response_variable"})


# Below a blocked prefix, but only reads the connection's own user.
ALLOWED_AUTH_COMMANDS = frozenset({"auth/current_user"})


def ws_always_blocked_type(command_type: str) -> bool:
    if command_type in ALLOWED_AUTH_COMMANDS:
        return False
    lowered = command_type.strip().lower()
    return any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in ALWAYS_BLOCKED_WS_PREFIXES)


def script_blocked(sequence: Any, depth: int = 0) -> bool:
    """Whether a script sequence calls a blocked action, or one that cannot be checked.

    Every step and nested step (choose, if, parallel, repeat, sequence) is
    checked. An action given as a template, or under the old key
    service_template, could name any domain and is refused as well.
    """
    if depth > 64:
        return True
    if isinstance(sequence, list):
        return any(script_blocked(item, depth + 1) for item in sequence)
    if not isinstance(sequence, dict):
        return False
    for key in ("service_template", "action_template"):
        if key in sequence:
            return True
    for key in ("action", "service"):
        if key in sequence:
            value = sequence[key]
            match = _PLAIN_ACTION.fullmatch(value.strip().lower()) if isinstance(value, str) else None
            if match is None or match.group(1) in BLOCKED_SERVICE_DOMAINS:
                return True
    return any(script_blocked(value, depth + 1) for key, value in sequence.items() if key not in _SCRIPT_DATA_KEYS)


def decide_ws_command(command: dict, grants: frozenset[str]) -> tuple[bool, str]:
    """Whether a well-formed WebSocket command may be forwarded, and why.

    A command whose fields cannot be checked is refused, never forwarded.
    """
    try:
        return _decide_ws_command(command, grants)
    except (TypeError, ValueError, AttributeError, RecursionError):
        return False, "denied"


def _decide_ws_command(command: dict, grants: frozenset[str]) -> tuple[bool, str]:
    command_type = command["type"]
    if ws_always_blocked_type(command_type):
        return False, "blocked"
    if command_type == "call_service" and blocked_service_domain(command.get("domain")):
        return False, "blocked"
    if command_type == "execute_script" and script_blocked(command.get("sequence")):
        return False, "blocked"
    if FULL in grants:
        return True, "full"
    if READ in grants and command_type in READ_WS:
        event_type = command.get("event_type")
        if command_type == "subscribe_events" and not (isinstance(event_type, str) and event_type in READ_EVENT_TYPES):
            return False, "denied"
        return True, "read"
    return False, "denied"


def well_formed(command: object) -> bool:
    """As Home Assistant checks a command: an object with a positive integer id and a type."""
    if type(command) is not dict:
        return False
    command_id = command.get("id")
    command_type = command.get("type")
    return type(command_id) is int and command_id > 0 and type(command_type) is str and bool(command_type)


def error_result(command_id: object, code: str, message: str) -> dict:
    """A result message in Home Assistant's shape (websocket_api/messages.py)."""
    return {"id": command_id, "type": "result", "success": False, "error": {"code": code, "message": message}}


def denial_message(reason: str, command_type: str) -> str:
    if reason == "blocked":
        return f"Unauthorized: {command_type} is blocked by the Twingate Gateway add-on for every caller."
    return f"Unauthorized: {command_type} needs another grant in the Twingate Gateway add-on."


class FrameDecision:
    """What to do with one TEXT frame from the client."""

    __slots__ = ("close", "commands", "forward", "replies")

    def __init__(self) -> None:
        # The text to send to Home Assistant, or None.
        self.forward: str | None = None
        # Results to send back to the client for refused commands.
        self.replies: list[dict] = []
        # (id, type, allowed, reason) for the log.
        self.commands: list[tuple[object, str, bool, str]] = []
        # Invalid JSON: Home Assistant closes the connection.
        self.close = False


def decide_ws_frame(text: str, grants: frozenset[str]) -> FrameDecision:
    """Applies the rules to a TEXT frame: one command, or an array of commands.

    Home Assistant handles each element of an array as its own command, so
    the allowed elements are passed on (the frame unchanged when all are) and
    each refused one gets its own error result. Malformed commands are
    answered here as Home Assistant answers them.
    """
    decision = FrameDecision()
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        decision.close = True
        return decision
    is_array = type(parsed) is list
    items = parsed if is_array else [parsed]
    kept = []
    for item in items:
        if not well_formed(item):
            item_id = item.get("id") if type(item) is dict else 0
            decision.replies.append(error_result(item_id if type(item_id) is int else 0, "invalid_format", "Message incorrectly formatted."))
            decision.commands.append((item_id if type(item_id) is int else None, "?", False, "invalid"))
            continue
        allowed, reason = decide_ws_command(item, grants)
        decision.commands.append((item["id"], item["type"], allowed, reason))
        if allowed:
            kept.append(item)
        else:
            decision.replies.append(error_result(item["id"], "unauthorized", denial_message(reason, item["type"])))
    if kept:
        if len(kept) == len(items):
            decision.forward = text
        elif is_array:
            decision.forward = json.dumps(kept, separators=(",", ":"), ensure_ascii=False)
        else:
            decision.forward = text
    return decision


# ----------------------------------------------------------------------------
# WebSocket authentication phase
# ----------------------------------------------------------------------------

MAX_AUTH_MESSAGE_BYTES = 64 * 1024  # Home Assistant's MAX_UNAUTHENTICATED_BODY_SIZE


def check_client_auth(text: str) -> tuple[str, str | None]:
    """Checks the client's auth message as Home Assistant's schema does.

    Returns ("ok", None), ("invalid", message) for an auth_invalid answer, or
    ("close", None) when Home Assistant closes without an answer. Any
    non-empty access_token is accepted: the caller was identified by its
    Twingate token when the WebSocket was opened.
    """
    if len(text.encode("utf-8", "surrogatepass")) > MAX_AUTH_MESSAGE_BYTES:
        return "close", None
    try:
        message = json.loads(text)
    except (ValueError, RecursionError):
        return "close", None
    if type(message) is not dict or message.get("type") != "auth":
        return "invalid", "Auth message incorrectly formatted: expected type auth"
    extra = sorted(str(key) for key in message if key not in ("type", "access_token", "api_password"))
    if extra:
        return "invalid", f"Auth message incorrectly formatted: extra keys not allowed @ data['{extra[0]}']"
    if "access_token" in message and "api_password" in message:
        return "invalid", "Auth message incorrectly formatted: two or more values in the same group of exclusion 'auth'"
    for key in ("access_token", "api_password"):
        if key in message and type(message[key]) is not str:
            return "invalid", f"Auth message incorrectly formatted: expected str for dictionary value @ data['{key}']"
    token = message.get("access_token")
    if isinstance(token, str) and token.strip():
        return "ok", None
    return "invalid", "Invalid access token or password"
