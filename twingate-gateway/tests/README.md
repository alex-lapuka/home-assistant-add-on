# Unit tests of the Twingate Gateway add-on

Fast unit tests of the add-on's security-critical Python: the access rules
of the Home Assistant API proxy, the verification of Twingate Gateway Access
Tokens (GATs), the proxy's helpers and the audit log summaries of the Web UI.
They run in CI on every change to the add-on (`.github/workflows/tests.yaml`)
and are not part of the add-on image (`.dockerignore`).

## Running them

Python 3.11 or newer (the image has 3.14), with the two packages the
add-on's modules import:

```sh
python -m pip install -r twingate-gateway/tests/requirements.txt
python -m unittest discover -s twingate-gateway/tests
```

One file: add `-p test_gat.py`. The suite takes well under a second. It
needs no network, no Docker and no Home Assistant: no server is started,
signing keys are made for each run, and every clock the code takes is a fake
one, so the results do not depend on the time of day. The modules are
imported from `rootfs/` as the image runs them, without writing
`__pycache__` there. On Windows, `audit_relay.py` is imported with
stand-ins for the Linux-only modules `grp` and `pwd`, which the tested
functions do not use.

## What is covered

- `test_access_rules_grants.py`: the access level from the three toggles
  `allow_read`, `allow_mcp` and `allow_write` (every combination, Write
  includes Read and MCP, only the value `true` turns a toggle on, all off
  refuses everything), and its labels in the log.
- `test_access_rules_paths.py`: decoding request paths once and refusing
  ambiguous ones (`%2f`, `%3f`, `%23`, `%25`, `%2e`, dot and empty
  segments, control characters), webhook masking, the cross-site check of
  `Origin` and `Sec-Fetch-Site`.
- `test_access_rules_rest.py`: REST decisions per grant, the Read
  allow-list entry by entry, every always-blocked path for every grant, and
  the toggle a `403` names.
- `test_access_rules_websocket.py`: WebSocket decisions per grant, the Read
  allow-list and event types, always-blocked command types, `call_service`
  and `execute_script` to the `hassio` and `backup` domains, arrays of
  commands with mixed outcomes, malformed commands, repeated JSON keys, the
  toggle an error result names, and the client's authentication phase.
- `test_access_rules_mcp.py`: the MCP body check (`hassio__...` tools,
  `call_action` with blocked, missing or templated actions, arrays, repeated
  keys), the UTF-8 and `Content-Type` rules, and the `/api/mcp/<id>` paths.
- `test_gat.py`: ES256 only, signature format, key IDs, every claim, the
  binding to this proxy's Resource (host name with and without
  `.local.hass.io` and port 8124, or a published host port), the cache of
  verified tokens, reading and re-reading the key set (with an injected
  fetcher), redirects of the key set request.
- `test_supervisor_proxy.py`: the forwarded header lists, `_printable()`,
  the options file (missing or malformed toggles count as off), the
  Supervisor token on a file descriptor, the limits per user and in all,
  `Proxy.identify()` (one token header only, key set read again at most once
  a minute for an unknown key ID), and `Proxy.handle()` up to the request to
  the Supervisor (`401` without a valid token, the `403` messages per toggle,
  the same access for every caller whatever groups its token lists).
- `test_audit_relay.py`: `printable()`, webhook masking (also
  percent-encoded) and the audit log summaries, which never carry headers,
  query strings or client addresses.

The tables in `test_access_rules_*.py` spell out the access policy: a change
to what a toggle allows, or to what is always blocked, has to change them as
well.

Not covered: forwarding to the Supervisor and the WebSocket relay of
`supervisor_proxy.py` (they need a running server and the Supervisor), the
relay's file following and sockets, `run.sh`, and the Web UI.

## What they check against

These tests check the code against the add-on's reading of Home Assistant
and Twingate behaviour, not against real services: which REST paths,
WebSocket commands and MCP tools Home Assistant has, that it decodes a path
once and keeps the last value of a repeated JSON key, what a Gateway Access
Token contains and how the Gateway checks it. When Home Assistant or the
Twingate Gateway change, the tables have to be checked against them again.
