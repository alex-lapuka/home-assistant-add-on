"""WebSocket decisions per grant: commands, frames and the authentication phase.

The tables below are the WebSocket access policy: a change to what a grant
allows must change them.
"""

import json
import unittest

from support import GRANTS, access_rules

ALL_GRANTS = tuple(GRANTS)
ALLOWED_REASONS = ("read", "full")

# The command types Read allows (subscribe_events only for the event types
# below).
EXPECTED_READ_WS = frozenset(
    {
        "ping",
        "supported_features",
        "unsubscribe_events",
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
        "auth/current_user",
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

# The events Read may subscribe to: Home Assistant's SUBSCRIBE_ALLOWLIST for
# non-administrators.
EXPECTED_READ_EVENT_TYPES = frozenset(
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

# Command types blocked for every caller: each prefix and everything below it.
EXPECTED_BLOCKED_PREFIXES = ("supervisor", "hassio", "auth", "config/auth", "config/auth_provider", "backup", "debug_console")


def script(*steps: object) -> dict:
    return {"type": "execute_script", "sequence": list(steps)}


def nested(step: dict, levels: int) -> dict:
    for _ in range(levels):
        step = {"sequence": [step]}
    return step


# Commands blocked for every grant, Full included.
ALWAYS_BLOCKED_COMMANDS = (
    # The Supervisor API with Home Assistant's own Supervisor token.
    {"type": "supervisor"},
    {"type": "supervisor/api", "endpoint": "/host/reboot", "method": "post"},
    {"type": "supervisor/api", "endpoint": "/core/info", "method": "get"},
    {"type": "supervisor/subscribe"},
    {"type": "supervisor/event", "data": {}},
    # Updates and backup settings through the Supervisor.
    {"type": "hassio"},
    {"type": "hassio/update/addon", "addon": "core_ssh"},
    {"type": "hassio/update/core"},
    # Tokens, signed paths, refresh tokens, MFA.
    {"type": "auth"},
    {"type": "auth/long_lived_access_token", "client_name": "x", "lifespan": 3650},
    {"type": "auth/sign_path", "path": "/api/camera_proxy/camera.x"},
    {"type": "auth/refresh_tokens"},
    {"type": "auth/delete_refresh_token", "refresh_token_id": "x"},
    {"type": "auth/setup_mfa"},
    # Users, passwords and user names.
    {"type": "config/auth"},
    {"type": "config/auth/list"},
    {"type": "config/auth/create", "name": "x"},
    {"type": "config/auth/delete", "user_id": "x"},
    {"type": "config/auth_provider/homeassistant/create", "user_id": "x", "username": "x", "password": "x"},
    {"type": "config/auth_provider/homeassistant/admin_change_password", "user_id": "x", "password": "x"},
    # Backups and their encryption keys.
    {"type": "backup"},
    {"type": "backup/generate"},
    {"type": "backup/restore", "backup_id": "x"},
    {"type": "backup/config/info"},
    {"type": "backup/config/update"},
    {"type": "backup/info"},
    # Python inside Home Assistant.
    {"type": "debug_console"},
    {"type": "debug_console/run"},
    # Compared without regard to case and surrounding spaces.
    {"type": "Supervisor/API", "endpoint": "/host/reboot", "method": "post"},
    {"type": " supervisor/api"},
    {"type": "AUTH/sign_path", "path": "/x"},
    {"type": "Backup/Generate"},
    # The one allowed command below auth/ is matched exactly.
    {"type": "Auth/Current_User"},
    {"type": "auth/current_user/x"},
    # Actions of the hassio and backup domains.
    {"type": "call_service", "domain": "hassio", "service": "host_reboot"},
    {"type": "call_service", "domain": "hassio", "service": "addon_stop", "service_data": {"addon": "core_ssh"}},
    {"type": "call_service", "domain": "backup", "service": "create"},
    {"type": "call_service", "domain": "HASSIO", "service": "host_shutdown"},
    {"type": "call_service", "domain": " Backup ", "service": "create_automatic"},
    # A domain that cannot be checked.
    {"type": "call_service", "service": "host_reboot"},
    {"type": "call_service", "domain": None, "service": "x"},
    {"type": "call_service", "domain": ["hassio"], "service": "host_reboot"},
    {"type": "call_service", "domain": 5, "service": "x"},
    # Scripts that call such an action, in any step.
    script({"action": "hassio.host_reboot"}),
    script({"service": "hassio.host_reboot"}),
    script({"action": "backup.create"}),
    script({"action": " Hassio.Host_Reboot "}),
    script({"action": "light.turn_on"}, {"action": "hassio.addon_stop", "data": {"addon": "core_ssh"}}),
    {"type": "execute_script", "sequence": {"action": "hassio.host_reboot"}},
    script({"choose": [{"conditions": [], "sequence": [{"action": "hassio.addon_stop"}]}]}),
    script({"choose": [], "default": [{"action": "backup.create"}]}),
    script(
        {
            "if": [{"condition": "state", "entity_id": "light.x", "state": "on"}],
            "then": [{"action": "light.turn_on"}],
            "else": [{"action": "hassio.host_shutdown"}],
        }
    ),
    script({"parallel": [{"action": "light.turn_on"}, {"sequence": [{"action": "hassio.host_reboot"}]}]}),
    script({"repeat": {"count": 2, "sequence": [{"action": "hassio.host_reboot"}]}}),
    script({"sequence": [{"service": "backup.create_automatic"}]}),
    script(nested({"action": "hassio.host_reboot"}, 10)),
    # ... or names its action in a way that cannot be checked.
    script({"action": "{{ 'hassio' }}.host_reboot"}),
    script({"action": "{{ action }}"}),
    script({"service_template": "light.turn_on"}),
    script({"action_template": "light.turn_on"}),
    script({"action": ["hassio.host_reboot"]}),
    script({"action": None}),
    script({"action": 5}),
    script({"action": "light"}),
    script({"action": "light.turn_on.x"}),
    script({"action": "light.turn_on hassio.host_reboot"}),
    # ... or nests deeper than the check follows.
    script(nested({"action": "light.turn_on"}, 40)),
)

# (grant, command, expected reason) for commands that are not always blocked.
WS_CASES = (
    # Read: the allow-list only.
    ("read", {"type": "get_states"}, "read"),
    ("read", {"type": "auth/current_user"}, "read"),
    ("read", {"type": "subscribe_events", "event_type": "state_changed"}, "read"),
    # subscribe_events: only the event types of the list, as text.
    ("read", {"type": "subscribe_events"}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": "call_service"}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": "*"}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": ""}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": "State_Changed"}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": " state_changed"}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": ["state_changed"]}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": None}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": 5}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": {"state_changed": True}}, "denied"),
    ("read", {"type": "subscribe_events", "event_type": True}, "denied"),
    # Read: default deny for actions and every unknown command.
    ("read", {"type": "call_service", "domain": "light", "service": "turn_on"}, "denied"),
    ("read", script({"action": "light.turn_on"}), "denied"),
    ("read", {"type": "render_template", "template": "{{ 1 }}"}, "denied"),
    ("read", {"type": "fire_event", "event_type": "x"}, "denied"),
    ("read", {"type": "subscribe_trigger", "trigger": {"platform": "state", "entity_id": "light.x"}}, "denied"),
    ("read", {"type": "config/entity_registry/update", "entity_id": "light.x"}, "denied"),
    ("read", {"type": "lovelace/config/save", "config": {}}, "denied"),
    ("read", {"type": "conversation/process", "text": "turn on the light"}, "denied"),
    ("read", {"type": "assist_pipeline/run"}, "denied"),
    ("read", {"type": "unknown/command"}, "denied"),
    ("read", {"type": "GET_STATES"}, "denied"),
    ("read", {"type": "get_states "}, "denied"),
    # No grant, and MCP alone: no WebSocket commands.
    ("none", {"type": "get_states"}, "denied"),
    ("none", {"type": "ping"}, "denied"),
    ("mcp", {"type": "get_states"}, "denied"),
    ("mcp", {"type": "auth/current_user"}, "denied"),
    ("read+mcp", {"type": "get_states"}, "read"),
    # Full: everything that is not always blocked.
    ("full", {"type": "get_states"}, "full"),
    ("full", {"type": "auth/current_user"}, "full"),
    ("full", {"type": "subscribe_events"}, "full"),
    ("full", {"type": "subscribe_events", "event_type": "call_service"}, "full"),
    ("full", {"type": "call_service", "domain": "light", "service": "turn_on", "target": {"entity_id": "light.x"}}, "full"),
    ("full", {"type": "call_service", "domain": "homeassistant", "service": "restart"}, "full"),
    ("full", {"type": "render_template", "template": "{{ 1 }}"}, "full"),
    ("full", {"type": "fire_event", "event_type": "x"}, "full"),
    ("full", {"type": "config/entity_registry/update", "entity_id": "light.x"}, "full"),
    ("full", {"type": "unknown/command"}, "full"),
    ("full", script({"action": "light.turn_on", "target": {"entity_id": "light.x"}}), "full"),
    ("full", script({"service": "script.morning"}), "full"),
    ("full", script({"delay": "00:00:01"}, {"wait_template": "{{ true }}"}), "full"),
    ("full", script(nested({"action": "light.turn_on"}, 10)), "full"),
    # "action" keys inside data are data, not steps.
    (
        "full",
        script({"action": "notify.mobile_app_phone", "data": {"message": "x", "data": {"actions": [{"action": "URI", "title": "Open"}]}}}),
        "full",
    ),
    ("full", script({"event": "my_event", "event_data": {"action": "hassio.host_reboot"}}), "full"),
    ("full", script({"variables": {"action": "hassio.host_reboot"}}), "full"),
    ("full", script({"action": "script.turn_on", "target": {"entity_id": "script.x"}, "data": {"variables": {"service": "hassio.x"}}}), "full"),
    # execute_script without a sequence has nothing to check; Home Assistant
    # refuses it.
    ("full", {"type": "execute_script"}, "full"),
)


def command(fields: dict, command_id: int = 1) -> dict:
    return {"id": command_id, **fields}


class CommandPolicyTest(unittest.TestCase):
    def assert_decision(self, grant: str, fields: dict, reason: str) -> None:
        self.assertEqual(
            access_rules.decide_ws_command(command(fields), GRANTS[grant]),
            (reason in ALLOWED_REASONS, reason),
            f"{grant} {fields}",
        )

    def test_lists_are_as_documented(self) -> None:
        self.assertEqual(access_rules.READ_WS, EXPECTED_READ_WS)
        self.assertEqual(access_rules.READ_EVENT_TYPES, EXPECTED_READ_EVENT_TYPES)
        self.assertEqual(access_rules.ALWAYS_BLOCKED_WS_PREFIXES, EXPECTED_BLOCKED_PREFIXES)
        self.assertEqual(access_rules.ALLOWED_AUTH_COMMANDS, frozenset({"auth/current_user"}))

    def test_every_read_command(self) -> None:
        for command_type in sorted(EXPECTED_READ_WS - {"subscribe_events"}):
            with self.subTest(command_type=command_type):
                self.assert_decision("read", {"type": command_type}, "read")
                self.assert_decision("read+mcp", {"type": command_type}, "read")
                self.assert_decision("full", {"type": command_type}, "full")
                self.assert_decision("mcp", {"type": command_type}, "denied")
                self.assert_decision("none", {"type": command_type}, "denied")

    def test_every_read_event_type(self) -> None:
        for event_type in sorted(EXPECTED_READ_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                self.assert_decision("read", {"type": "subscribe_events", "event_type": event_type}, "read")
                self.assert_decision("none", {"type": "subscribe_events", "event_type": event_type}, "denied")

    def test_always_blocked_for_every_grant(self) -> None:
        for fields in ALWAYS_BLOCKED_COMMANDS:
            for grant in ALL_GRANTS:
                with self.subTest(command=fields, grant=grant):
                    self.assert_decision(grant, fields, "blocked")

    def test_ws_cases(self) -> None:
        for grant, fields, reason in WS_CASES:
            with self.subTest(grant=grant, command=fields):
                self.assert_decision(grant, fields, reason)

    def test_command_that_cannot_be_checked_is_refused(self) -> None:
        # Not reachable through decide_ws_frame(), which checks the type
        # first; refused rather than raising.
        self.assertEqual(access_rules.decide_ws_command({"id": 1, "type": 5}, GRANTS["full"]), (False, "denied"))
        self.assertEqual(access_rules.decide_ws_command({"id": 1, "type": None}, GRANTS["read"]), (False, "denied"))


def frame(text: str, grant: str) -> object:
    return access_rules.decide_ws_frame(text, GRANTS[grant])


def unauthorized(command_id: int, message: str) -> dict:
    return {"id": command_id, "type": "result", "success": False, "error": {"code": "unauthorized", "message": message}}


def invalid(command_id: int) -> dict:
    return {"id": command_id, "type": "result", "success": False, "error": {"code": "invalid_format", "message": "Message incorrectly formatted."}}


BLOCKED_MESSAGE = "Unauthorized: {} is blocked by the Twingate Gateway add-on for every caller."
DENIED_MESSAGE = "Unauthorized: {} needs another grant in the Twingate Gateway add-on."


class FrameTest(unittest.TestCase):
    def test_allowed_command_is_forwarded_unchanged(self) -> None:
        text = '{ "id": 1, "type": "get_states" }'
        decision = frame(text, "read")
        self.assertIs(decision.forward, text)
        self.assertEqual(decision.replies, [])
        self.assertEqual(decision.commands, [(1, "get_states", True, "read")])
        self.assertFalse(decision.close)

    def test_denied_command_gets_an_error_result(self) -> None:
        decision = frame('{"id":7,"type":"render_template","template":"x"}', "read")
        self.assertIsNone(decision.forward)
        self.assertEqual(decision.replies, [unauthorized(7, DENIED_MESSAGE.format("render_template"))])
        self.assertEqual(decision.commands, [(7, "render_template", False, "denied")])

    def test_blocked_command_gets_an_error_result(self) -> None:
        decision = frame('{"id":8,"type":"supervisor/api","endpoint":"/host/reboot","method":"post"}', "full")
        self.assertIsNone(decision.forward)
        self.assertEqual(decision.replies, [unauthorized(8, BLOCKED_MESSAGE.format("supervisor/api"))])
        self.assertEqual(decision.commands, [(8, "supervisor/api", False, "blocked")])

    def test_array_with_mixed_outcomes(self) -> None:
        # Home Assistant handles each element as its own command: the allowed
        # ones are passed on, each refused one is answered here.
        items = [
            {"id": 1, "type": "get_states"},
            {"id": 2, "type": "call_service", "domain": "hassio", "service": "host_reboot"},
            {"id": 3, "type": "render_template", "template": "x"},
            {"id": 4, "type": "subscribe_events", "event_type": "state_changed", "note": "caf\xe9"},
            {"id": 5, "type": "subscribe_events", "event_type": ["state_changed"]},
            {"id": 0, "type": "get_states"},
        ]
        decision = frame(json.dumps(items), "read")
        self.assertEqual(json.loads(decision.forward), [items[0], items[3]])
        self.assertEqual(decision.forward, json.dumps([items[0], items[3]], separators=(",", ":"), ensure_ascii=False))
        self.assertEqual(
            decision.replies,
            [
                unauthorized(2, BLOCKED_MESSAGE.format("call_service")),
                unauthorized(3, DENIED_MESSAGE.format("render_template")),
                unauthorized(5, DENIED_MESSAGE.format("subscribe_events")),
                invalid(0),
            ],
        )
        self.assertEqual(
            decision.commands,
            [
                (1, "get_states", True, "read"),
                (2, "call_service", False, "blocked"),
                (3, "render_template", False, "denied"),
                (4, "subscribe_events", True, "read"),
                (5, "subscribe_events", False, "denied"),
                (0, "?", False, "invalid"),
            ],
        )

    def test_array_of_allowed_commands_is_forwarded_unchanged(self) -> None:
        text = '[ {"id": 1, "type": "get_states"}, {"id": 2, "type": "ping"} ]'
        decision = frame(text, "read")
        self.assertIs(decision.forward, text)
        self.assertEqual(decision.replies, [])

    def test_array_of_refused_commands_forwards_nothing(self) -> None:
        decision = frame('[{"id":1,"type":"supervisor/api"},{"id":2,"type":"auth/sign_path"}]', "full")
        self.assertIsNone(decision.forward)
        self.assertEqual([reply["id"] for reply in decision.replies], [1, 2])

    def test_empty_array(self) -> None:
        decision = frame("[]", "full")
        self.assertIsNone(decision.forward)
        self.assertEqual((decision.replies, decision.commands, decision.close), ([], [], False))

    def test_malformed_commands_are_answered_as_home_assistant_does(self) -> None:
        # (message, id in the answer, id in the log)
        cases = (
            ('{"type":"get_states"}', 0, None),
            ('{"id":0,"type":"get_states"}', 0, 0),
            ('{"id":-1,"type":"get_states"}', -1, -1),
            ('{"id":true,"type":"get_states"}', 0, None),
            ('{"id":1.0,"type":"get_states"}', 0, None),
            ('{"id":"1","type":"get_states"}', 0, None),
            ('{"id":1}', 1, 1),
            ('{"id":1,"type":""}', 1, 1),
            ('{"id":1,"type":5}', 1, 1),
            ('{"id":1,"type":null}', 1, 1),
            ('{"id":1,"type":["get_states"]}', 1, 1),
            ("5", 0, 0),
            ('"get_states"', 0, 0),
            ("null", 0, 0),
            ('[[{"id":1,"type":"get_states"}]]', 0, 0),
        )
        for text, reply_id, logged_id in cases:
            with self.subTest(text=text):
                decision = frame(text, "full")
                self.assertIsNone(decision.forward)
                self.assertEqual(decision.replies, [invalid(reply_id)])
                self.assertEqual(decision.commands, [(logged_id, "?", False, "invalid")])
                self.assertFalse(decision.close)

    def test_invalid_json_closes_the_connection(self) -> None:
        for text in ("{", "", "not json", '{"id":1,"type":"get_states"', "[" * 100_000 + "]" * 100_000):
            with self.subTest(text=text[:20]):
                decision = frame(text, "full")
                self.assertTrue(decision.close)
                self.assertIsNone(decision.forward)
                self.assertEqual(decision.replies, [])

    def test_duplicate_keys_are_read_as_home_assistant_reads_them(self) -> None:
        # Python's json and Home Assistant's parser both keep the last value
        # of a repeated key, so the proxy decides on what Home Assistant runs.
        cases = (
            ('{"id":1,"type":"get_states","type":"supervisor/api"}', "full", "blocked"),
            ('{"id":1,"type":"supervisor/api","type":"get_states"}', "read", "read"),
            ('{"id":1,"type":"call_service","domain":"light","service":"turn_on","domain":"hassio"}', "full", "blocked"),
            ('{"id":1,"type":"call_service","domain":"hassio","service":"host_reboot","domain":"light"}', "full", "full"),
            ('{"id":1,"type":"subscribe_events","event_type":"state_changed","event_type":"call_service"}', "read", "denied"),
            ('{"id":1,"type":"subscribe_events","event_type":"call_service","event_type":"state_changed"}', "read", "read"),
            ('{"id":1,"type":"execute_script","sequence":[{"action":"light.turn_on","action":"hassio.host_reboot"}]}', "full", "blocked"),
        )
        for text, grant, reason in cases:
            with self.subTest(text=text):
                decision = frame(text, grant)
                self.assertEqual(decision.commands[0][3], reason)
                if reason in ALLOWED_REASONS:
                    self.assertIs(decision.forward, text)
                else:
                    self.assertIsNone(decision.forward)

    def test_escaped_characters_are_decoded_before_the_rules(self) -> None:
        cases = (
            r'{"id":1,"type":"call_service","domain":"\u0068assio","service":"host_reboot"}',
            r'{"id":1,"type":"supervisor\/api"}',
            r'{"id":1,"type":"\u0061uth/sign_path","path":"/x"}',
            r'{"id":1,"type":"execute_script","sequence":[{"action":"hass\u0069o.host_reboot"}]}',
        )
        for text in cases:
            with self.subTest(text=text):
                decision = frame(text, "full")
                self.assertIsNone(decision.forward)
                self.assertEqual(decision.commands[0][2:], (False, "blocked"))


class ClientAuthTest(unittest.TestCase):
    """The client's auth message, answered as Home Assistant's schema answers it."""

    CASES = (
        # Any non-empty access_token: the caller was identified by its GAT.
        ('{"type":"auth","access_token":"placeholder"}', ("ok", None)),
        ('{"access_token":"x","type":"auth"}', ("ok", None)),
        ('{"type":"auth","access_token":""}', ("invalid", "Invalid access token or password")),
        ('{"type":"auth","access_token":"  "}', ("invalid", "Invalid access token or password")),
        ('{"type":"auth"}', ("invalid", "Invalid access token or password")),
        ('{"type":"auth","api_password":"x"}', ("invalid", "Invalid access token or password")),
        ('{"type":"auth","access_token":5}', ("invalid", "Auth message incorrectly formatted: expected str for dictionary value @ data['access_token']")),
        ('{"type":"auth","access_token":null}', ("invalid", "Auth message incorrectly formatted: expected str for dictionary value @ data['access_token']")),
        (
            '{"type":"auth","access_token":"x","api_password":"y"}',
            ("invalid", "Auth message incorrectly formatted: two or more values in the same group of exclusion 'auth'"),
        ),
        ('{"type":"auth","access_token":"x","id":1}', ("invalid", "Auth message incorrectly formatted: extra keys not allowed @ data['id']")),
        ('{"type":"auth_x","access_token":"x"}', ("invalid", "Auth message incorrectly formatted: expected type auth")),
        ('{"access_token":"x"}', ("invalid", "Auth message incorrectly formatted: expected type auth")),
        ('[{"type":"auth","access_token":"x"}]', ("invalid", "Auth message incorrectly formatted: expected type auth")),
        ('"auth"', ("invalid", "Auth message incorrectly formatted: expected type auth")),
        # Not JSON: Home Assistant closes without an answer.
        ("{", ("close", None)),
        ("", ("close", None)),
    )

    def test_client_auth(self) -> None:
        for text, expected in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(access_rules.check_client_auth(text), expected)

    def test_oversized_auth_message_closes(self) -> None:
        limit = access_rules.MAX_AUTH_MESSAGE_BYTES
        message = '{"type":"auth","access_token":"' + "x" * limit + '"}'
        self.assertEqual(access_rules.check_client_auth(message), ("close", None))
        fits = '{"type":"auth","access_token":"' + "x" * (limit - 33) + '"}'
        self.assertEqual(len(fits), limit)
        self.assertEqual(access_rules.check_client_auth(fits), ("ok", None))


if __name__ == "__main__":
    unittest.main()
