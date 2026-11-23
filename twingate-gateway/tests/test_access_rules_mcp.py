"""MCP requests: the endpoint paths, the Content-Type rule and the body check."""

import json
import unittest

from support import access_rules

inspect = access_rules.inspect_mcp_body


def tool_call(name: object, arguments: object = None, message_id: object = 1) -> dict:
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": message_id, "method": "tools/call", "params": params}


def call_action(action: object, name: str = "homeassistant__call_action") -> dict:
    return tool_call(name, {"action": action})


def body(message: object) -> bytes:
    return json.dumps(message).encode("utf-8")


OK = ("ok", None)
INVALID = ("invalid", None)
BLOCKED = ("blocked", 1)

# (message, expected outcome of inspect_mcp_body)
MESSAGE_CASES = (
    # Tools of the Supervisor integration, with any case and spaces.
    (tool_call("hassio__get_logs"), BLOCKED),
    (tool_call("HASSIO__get_logs"), BLOCKED),
    (tool_call(" Hassio__addon_info "), BLOCKED),
    (tool_call("hassio__"), BLOCKED),
    # call_action tools: the action is checked.
    (call_action("hassio.host_reboot"), BLOCKED),
    (call_action("hassio.addon_stop"), BLOCKED),
    (call_action("Hassio.Host_Reboot"), BLOCKED),
    (call_action(" backup.create "), BLOCKED),
    (call_action("BACKUP.create_automatic"), BLOCKED),
    (call_action("light.turn_on"), OK),
    (call_action("script.morning"), OK),
    (call_action("homeassistant.restart"), OK),
    # Any API's tool whose name ends with call_action, with any case.
    (call_action("hassio.host_reboot", name="other_api__call_action"), BLOCKED),
    (call_action("backup.create", name="HomeAssistant__CALL_ACTION"), BLOCKED),
    (call_action("hassio.host_reboot", name="call_action"), BLOCKED),
    (call_action("light.turn_on", name="other_api__call_action"), OK),
    # An action that is missing or not plain text "domain.action".
    (tool_call("homeassistant__call_action", {}), BLOCKED),
    (tool_call("homeassistant__call_action"), BLOCKED),
    (tool_call("homeassistant__call_action", ["hassio.host_reboot"]), BLOCKED),
    (tool_call("homeassistant__call_action", "hassio.host_reboot"), BLOCKED),
    (call_action(None), BLOCKED),
    (call_action(["hassio.host_reboot"]), BLOCKED),
    (call_action(5), BLOCKED),
    (call_action({"domain": "hassio", "service": "host_reboot"}), BLOCKED),
    (call_action("{{ 'hassio' }}.host_reboot"), BLOCKED),
    (call_action("{{ action }}"), BLOCKED),
    (call_action("light"), BLOCKED),
    (call_action("light.turn_on.x"), BLOCKED),
    (call_action("light.turn_on hassio.host_reboot"), BLOCKED),
    (call_action("+AGg-assio.host_reboot"), BLOCKED),
    # A tools/call whose tool cannot be checked.
    (tool_call(None), BLOCKED),
    (tool_call(5), BLOCKED),
    (tool_call(["hassio__get_logs"]), BLOCKED),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}, BLOCKED),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["hassio__get_logs"]}, BLOCKED),
    # The answer carries the id of the refused message.
    (tool_call("hassio__get_logs", message_id="abc"), ("blocked", "abc")),
    (tool_call("hassio__get_logs", message_id=None), ("blocked", None)),
    ({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "hassio__get_logs"}}, ("blocked", None)),
    # Other tools and other methods are not looked into, whatever their
    # arguments.
    (tool_call("GetLiveContext"), OK),
    (tool_call("HassTurnOn", {"name": "kitchen light"}), OK),
    (tool_call("HassTurnOn", {"action": "hassio.host_reboot"}), OK),
    ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, OK),
    ({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, OK),
    ({"jsonrpc": "2.0", "method": "notifications/initialized"}, OK),
    ({"jsonrpc": "2.0", "id": 3, "result": {}}, OK),
    ({}, OK),
    # Arrays (Home Assistant accepts single messages only) are checked all
    # the same; the first refused message gives the id.
    ([{"jsonrpc": "2.0", "id": 1, "method": "initialize"}, tool_call("hassio__get_logs", message_id=2)], ("blocked", 2)),
    ([tool_call("GetLiveContext"), call_action("light.turn_on")], OK),
    (
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            tool_call("homeassistant__call_action", {"action": "backup.create"}, message_id=3),
            tool_call("hassio__get_logs", message_id=4),
        ],
        ("blocked", 3),
    ),
    ([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, tool_call("GetLiveContext", message_id=2)], OK),
    # Only JSON-RPC objects, or arrays of them.
    ([], INVALID),
    ([1], INVALID),
    ([{}, 5], INVALID),
    ([[tool_call("hassio__get_logs")]], INVALID),
    (5, INVALID),
    ("tools/call", INVALID),
    (None, INVALID),
    (True, INVALID),
)


class McpBodyTest(unittest.TestCase):
    def test_messages(self) -> None:
        for message, expected in MESSAGE_CASES:
            with self.subTest(message=message):
                self.assertEqual(inspect(body(message)), expected)

    def test_escaped_names_are_decoded_before_the_check(self) -> None:
        cases = (
            rb'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\u0068assio__get_logs"}}',
            rb'{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"hassio__get_logs"}}',
            rb'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"homeassistant__call_action","arguments":{"action":"h\u0061ssio.host_reboot"}}}',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(inspect(raw), BLOCKED)

    def test_duplicate_keys_are_read_as_home_assistant_reads_them(self) -> None:
        # Python's json and Home Assistant's parser both keep the last value
        # of a repeated key, so the proxy checks the call Home Assistant runs.
        cases = (
            (b'{"id":1,"method":"tools/call","params":{"name":"homeassistant__call_action","arguments":{"action":"light.turn_on","action":"hassio.host_reboot"}}}', BLOCKED),
            (b'{"id":1,"method":"tools/call","params":{"name":"homeassistant__call_action","arguments":{"action":"hassio.host_reboot","action":"light.turn_on"}}}', OK),
            (b'{"id":1,"method":"tools/call","params":{"name":"GetLiveContext","name":"hassio__get_logs"}}', BLOCKED),
            (b'{"id":1,"method":"tools/call","params":{"name":"hassio__get_logs","name":"GetLiveContext"}}', OK),
            (b'{"id":1,"method":"tools/list","method":"tools/call","params":{"name":"hassio__get_logs"}}', BLOCKED),
            (b'{"id":1,"method":"tools/call","method":"tools/list","params":{"name":"hassio__get_logs"}}', OK),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(inspect(raw), expected)

    def test_body_must_be_utf8_json(self) -> None:
        cases = (
            b"",
            b"{",
            b"not json",
            b"\xef\xbb\xbf" + body(tool_call("GetLiveContext")),
            json.dumps(tool_call("GetLiveContext")).encode("utf-16"),
            json.dumps(tool_call("GetLiveContext")).encode("utf-32"),
            # Latin-1: \xe9 is not UTF-8.
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"caf\xe9"}}'.encode("latin-1"),
            b'{"method":"tools/call","x":"\xff"}',
            b"[" * 100_000 + b"]" * 100_000,
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(inspect(raw), INVALID)

    def test_body_size_limit(self) -> None:
        limit = access_rules.MAX_MCP_BODY_BYTES
        self.assertEqual(limit, 4 * 1024 * 1024)
        message = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        fits = message + b" " * (limit - len(message))
        self.assertEqual(inspect(fits), OK)
        self.assertEqual(inspect(fits + b" "), INVALID)

    def test_utf7_body_is_stopped_by_the_content_type_rule(self) -> None:
        # Read as UTF-8 this body calls a harmless tool name; read as UTF-7,
        # as Home Assistant would with charset=utf-7, it calls
        # hassio__get_logs. The Content-Type rule stops it.
        raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"+AGg-assio__get_logs"}}'
        self.assertEqual(json.loads(raw.decode("utf-7"))["params"]["name"], "hassio__get_logs")
        self.assertEqual(inspect(raw), OK)
        self.assertFalse(access_rules.mcp_content_type_ok("application/json; charset=utf-7"))


class McpContentTypeTest(unittest.TestCase):
    ACCEPTED = (
        "application/json",
        "APPLICATION/JSON",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        'application/json; charset="utf-8"',
        "application/json; charset=utf8",
        " application/json ; charset = utf-8 ",
    )
    REFUSED = (
        None,
        "",
        "text/plain",
        "application/json-rpc",
        "application/jsonx",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "application/json, text/plain",
        "application/json; charset=utf-7",
        "application/json; charset=UTF-7",
        "application/json; charset=iso-8859-1",
        "application/json; charset=latin-1",
        "application/json; charset=utf-16",
        "application/json; charset=",
        "application/json; charset=utf-8; charset=utf-7",
        "application/json; boundary=x",
        "application/json;",
    )

    def test_content_types(self) -> None:
        for content_type in self.ACCEPTED:
            with self.subTest(content_type=content_type):
                self.assertTrue(access_rules.mcp_content_type_ok(content_type))
        for content_type in self.REFUSED:
            with self.subTest(content_type=content_type):
                self.assertFalse(access_rules.mcp_content_type_ok(content_type))


class McpPathTest(unittest.TestCase):
    """Bodies are inspected on /api/mcp and on the per-API endpoints /api/mcp/<id>."""

    def test_is_mcp_path(self) -> None:
        cases = (
            ("/api/mcp", True),
            ("/api/mcp/", True),
            ("/api/mcp/assist", True),
            ("/api/mcp/assist/x", True),
            ("/api/mcpx", False),
            ("/api/mcp_x", False),
            ("/api/mc", False),
            ("/api/states", False),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertIs(access_rules.is_mcp_path(path), expected)


if __name__ == "__main__":
    unittest.main()
