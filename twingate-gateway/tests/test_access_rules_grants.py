"""Grants from the caller's Twingate groups (access_rules.Rules)."""

import unittest

from support import access_rules

READ, MCP, FULL = access_rules.READ, access_rules.MCP, access_rules.FULL

# (read_groups, mcp_groups, full_groups, the caller's groups, expected grants)
GRANT_CASES = (
    # read_groups empty: every caller with a valid token has Read.
    ((), (), (), (), {READ}),
    ((), (), (), ("Anyone",), {READ}),
    ((), ("Agents",), ("Admins",), ("Other",), {READ}),
    ((), ("Agents",), (), ("Agents",), {READ, MCP}),
    # read_groups not empty: a caller in none of the lists has nothing.
    (("Readers",), (), (), (), set()),
    (("Readers",), (), (), ("Other",), set()),
    (("Readers",), ("Agents",), ("Admins",), ("Other",), set()),
    (("Readers",), (), (), ("Readers",), {READ}),
    (("Readers", "Family"), (), (), ("Family",), {READ}),
    # MCP does not include Read, and Read does not include MCP.
    (("Readers",), ("Agents",), (), ("Agents",), {MCP}),
    # The union of the grants of all the caller's groups.
    (("Readers",), ("Agents",), (), ("Readers", "Agents"), {READ, MCP}),
    (("Team",), ("Team",), (), ("Team",), {READ, MCP}),
    # Full includes Read and MCP, also for a caller in neither list.
    (("Readers",), ("Agents",), ("Admins",), ("Admins",), {READ, MCP, FULL}),
    ((), (), ("Admins",), ("Admins",), {READ, MCP, FULL}),
    # mcp_groups and full_groups empty: nobody has MCP or Full.
    ((), (), (), ("Agents", "Admins"), {READ}),
    # Group names match exactly: with case, spaces and Unicode form.
    (("Readers",), ("Agents",), ("Admins",), ("readers", "AGENTS", "admins"), set()),
    (("Readers",), (), ("Admins",), ("Admins ", " Readers"), set()),
    (("Caf\xe9",), (), (), ("Cafe\u0301",), set()),
    # Groups in the token that are not text are ignored.
    (("Readers",), (), ("Admins",), (None, 5, ["Admins"], {"Admins": 1}), set()),
)


class GrantsTest(unittest.TestCase):
    def test_grants_from_groups(self) -> None:
        for read_groups, mcp_groups, full_groups, caller, expected in GRANT_CASES:
            with self.subTest(read=read_groups, mcp=mcp_groups, full=full_groups, caller=caller):
                rules = access_rules.Rules(read_groups, mcp_groups, full_groups)
                self.assertEqual(rules.grants(caller), frozenset(expected))

    def test_grants_are_immutable(self) -> None:
        self.assertIsInstance(access_rules.Rules([], [], []).grants([]), frozenset)

    def test_describe_for_the_add_on_log(self) -> None:
        self.assertEqual(
            access_rules.Rules([], [], []).describe(),
            ["Read: everyone with access to the Resource", "MCP: nobody", "Full (includes Read and MCP): nobody"],
        )
        self.assertEqual(
            access_rules.Rules(["B", "A"], ["Agents"], ["Admins"]).describe(),
            ['Read: members of "A", "B"', 'MCP: members of "Agents"', 'Full (includes Read and MCP): members of "Admins"'],
        )

    def test_grant_label(self) -> None:
        cases = (
            (set(), "none"),
            ({READ}, "read"),
            ({MCP}, "mcp"),
            ({READ, MCP}, "read+mcp"),
            ({READ, MCP, FULL}, "full"),
            ({FULL}, "full"),
        )
        for grants, label in cases:
            with self.subTest(grants=grants):
                self.assertEqual(access_rules.grant_label(frozenset(grants)), label)


if __name__ == "__main__":
    unittest.main()
