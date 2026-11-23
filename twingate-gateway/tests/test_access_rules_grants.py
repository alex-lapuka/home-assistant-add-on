"""The access level from the three toggles (access_rules.grants_from_options).

One access level applies to every caller whose Twingate token the proxy
verified: allow_read, allow_mcp and allow_write of the add-on options. The
groups in the token play no part.
"""

import itertools
import unittest

from support import GRANTS, access_rules

READ, MCP, WRITE = access_rules.READ, access_rules.MCP, access_rules.WRITE

# (allow_read, allow_mcp, allow_write, label of the expected grants in
# support.GRANTS): every combination.
TOGGLE_CASES = (
    (False, False, False, "none"),
    (True, False, False, "read"),
    (False, True, False, "mcp"),
    (True, True, False, "read+mcp"),
    # Write includes reading and MCP: the other two make no difference.
    (False, False, True, "write"),
    (True, False, True, "write"),
    (False, True, True, "write"),
    (True, True, True, "write"),
)

# Values that are not the boolean True: each counts as off.
NOT_TRUE = (None, False, 0, 1, 1.0, "true", "True", "on", "yes", "1", "", [], [True], {}, {"on": True})

# A sample of requests of every kind, none of them always blocked.
SAMPLE_REST = (
    ("GET", "/api/"),
    ("GET", "/api/states"),
    ("HEAD", "/api/states/sensor.x"),
    ("GET", "/api/mcp"),
    ("POST", "/api/mcp"),
    ("POST", "/api/mcp/assist"),
    ("POST", "/api/services/light/turn_on"),
    ("POST", "/api/template"),
    ("GET", "/api/error_log"),
    ("GET", "/api/websocket"),
    ("POST", "/api/webhook/abc"),
)
SAMPLE_WS = (
    {"id": 1, "type": "ping"},
    {"id": 2, "type": "get_states"},
    {"id": 3, "type": "auth/current_user"},
    {"id": 4, "type": "subscribe_events", "event_type": "state_changed"},
    {"id": 5, "type": "subscribe_events"},
    {"id": 6, "type": "call_service", "domain": "light", "service": "turn_on"},
    {"id": 7, "type": "render_template", "template": "{{ 1 }}"},
    {"id": 8, "type": "execute_script", "sequence": [{"action": "light.turn_on"}]},
)


class TogglesTest(unittest.TestCase):
    def test_every_combination(self) -> None:
        self.assertEqual(len({case[:3] for case in TOGGLE_CASES}), 8)
        for allow_read, allow_mcp, allow_write, label in TOGGLE_CASES:
            with self.subTest(read=allow_read, mcp=allow_mcp, write=allow_write):
                grants = access_rules.grants_from_options(allow_read, allow_mcp, allow_write)
                self.assertEqual(grants, GRANTS[label])
                self.assertEqual(access_rules.grant_label(grants), label)

    def test_only_true_turns_a_toggle_on(self) -> None:
        # A missing (None) or malformed value fails closed: off, never on.
        for value in NOT_TRUE:
            with self.subTest(value=value):
                self.assertEqual(access_rules.grants_from_options(value, value, value), frozenset())
                self.assertEqual(access_rules.grants_from_options(True, value, value), GRANTS["read"])
                self.assertEqual(access_rules.grants_from_options(value, True, value), GRANTS["mcp"])
                self.assertEqual(access_rules.grants_from_options(value, value, True), GRANTS["write"])

    def test_grants_are_immutable(self) -> None:
        for allow_read, allow_mcp, allow_write, _label in TOGGLE_CASES:
            self.assertIsInstance(access_rules.grants_from_options(allow_read, allow_mcp, allow_write), frozenset)

    def test_toggle_names(self) -> None:
        self.assertEqual(access_rules.TOGGLE_NAMES, {READ: "Allow reading", MCP: "Allow MCP", WRITE: "Allow changes (write)"})


class AccessLevelTest(unittest.TestCase):
    def test_all_off_refuses_every_request(self) -> None:
        none = access_rules.grants_from_options(False, False, False)
        for method, path in SAMPLE_REST:
            with self.subTest(method=method, path=path):
                self.assertEqual(access_rules.decide_rest(method, path, none), (False, "denied"))
        for command in SAMPLE_WS:
            with self.subTest(command=command):
                self.assertEqual(access_rules.decide_ws_command(command, none), (False, "denied"))

    def test_write_allows_whatever_any_combination_allows(self) -> None:
        write = access_rules.grants_from_options(False, False, True)
        for allow_read, allow_mcp, allow_write, _label in TOGGLE_CASES:
            grants = access_rules.grants_from_options(allow_read, allow_mcp, allow_write)
            self.assertLessEqual(grants, write)
            for method, path in SAMPLE_REST:
                with self.subTest(toggles=(allow_read, allow_mcp, allow_write), method=method, path=path):
                    if access_rules.decide_rest(method, path, grants)[0]:
                        self.assertTrue(access_rules.decide_rest(method, path, write)[0])
            for command in SAMPLE_WS:
                with self.subTest(toggles=(allow_read, allow_mcp, allow_write), command=command):
                    if access_rules.decide_ws_command(command, grants)[0]:
                        self.assertTrue(access_rules.decide_ws_command(command, write)[0])

    def test_write_allows_every_sample_request(self) -> None:
        write = access_rules.grants_from_options(False, False, True)
        for method, path in SAMPLE_REST:
            with self.subTest(method=method, path=path):
                self.assertTrue(access_rules.decide_rest(method, path, write)[0])
        for command in SAMPLE_WS:
            with self.subTest(command=command):
                self.assertEqual(access_rules.decide_ws_command(command, write), (True, "write"))

    def test_read_and_mcp_are_independent(self) -> None:
        for allow_read, allow_mcp in itertools.product((False, True), repeat=2):
            grants = access_rules.grants_from_options(allow_read, allow_mcp, False)
            with self.subTest(read=allow_read, mcp=allow_mcp):
                self.assertIs(access_rules.decide_rest("GET", "/api/states", grants)[0], allow_read)
                self.assertIs(access_rules.decide_rest("POST", "/api/mcp", grants)[0], allow_mcp)
                self.assertFalse(access_rules.decide_rest("POST", "/api/services/light/turn_on", grants)[0])


class LabelTest(unittest.TestCase):
    def test_grant_label(self) -> None:
        cases = (
            (set(), "none"),
            ({READ}, "read"),
            ({MCP}, "mcp"),
            ({READ, MCP}, "read+mcp"),
            ({READ, MCP, WRITE}, "write"),
            ({WRITE}, "write"),
        )
        for grants, label in cases:
            with self.subTest(grants=grants):
                self.assertEqual(access_rules.grant_label(frozenset(grants)), label)

    def test_describe_for_the_add_on_log(self) -> None:
        cases = (
            ("none", "none (every request is refused)"),
            ("read", "read"),
            ("mcp", "MCP"),
            ("read+mcp", "read, MCP"),
            ("write", "write (everything that is not always blocked, including read and MCP)"),
        )
        for label, text in cases:
            with self.subTest(label=label):
                self.assertEqual(access_rules.describe_grants(GRANTS[label]), text)


if __name__ == "__main__":
    unittest.main()
