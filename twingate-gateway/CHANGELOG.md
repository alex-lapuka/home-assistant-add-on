# CHANGELOG

## 0.1.0

- Initial release, based on Twingate Gateway 2.1.0 in Web App mode.
- Inject configurable HTTP request headers (static values or Gateway
  placeholders such as `{{username}}`) into proxied Web App requests.
- Create a CA on first start and print its certificate to the log for
  registration in Twingate; the Gateway issues TLS certificates on demand
  with it.
- Optionally use your own CA certificate and key from the `ssl` folder.
- Optionally issue a static certificate for Resources reached by IPv4
  address.
- Optionally write the Gateway audit log to a file in the add-on
  configuration folder instead of the add-on log.
- Check at startup that the Twingate network exists.
- Warn at startup that request headers are sent to every Web App Resource
  that uses the Gateway.
- Container health check against the Gateway's `/healthz` endpoint.

## 0.1.1

- Add the add-on icon and logo.
- Align the add-on description with the Twingate Connector add-on.

## 0.2.0

- Add a read-only Web UI, opened with **Open Web UI** or from the sidebar
  through Home Assistant ingress: the CA certificate with a copy button and
  the Gateway address for setup, Gateway health, signing-key status,
  configuration summary (header names only), traffic from the Gateway's
  metrics and the newest 100 requests (without headers or query strings,
  webhook IDs masked).
- With `audit_log: addon_log`, the audit log reaches the add-on log through
  `s6-log`, unchanged, which also keeps a small copy of the newest entries
  in memory (`/dev/shm`) for the relay that feeds the Web UI. The Gateway
  does not wait for `s6-log`'s copy, the relay or the Web UI; when the relay
  stops responding or the copy cannot be kept (for example because
  `/dev/shm` is full), the Web UI warns that its request list may be out of
  date. `s6-log` uses at most 64 MiB of memory: if entries waiting for a
  full `/dev/shm` reach this limit, it stops keeping the copy until the
  add-on restarts, and the entries it had just read (about 8 KB) are lost.
- Warn at startup when the private key of a custom CA is readable by its
  group or by others.
- Follow the newest Twingate Gateway 2.x release (image tag `2`) instead of a
  fixed version. The Gateway is taken when the add-on is built, so it changes
  on an add-on update or **Rebuild**. Its version is recorded when the add-on
  is built and shown in the log at startup and in the Web UI, before the
  first request.
- Check once a day on Docker Hub which release the tag `2` points to. When a
  rebuild would install a newer 2.x release, the Web UI shows a notice with
  the steps to rebuild the add-on, the log says so (at most once a day), and
  the Web UI's `api/status` reports it under `gateway_update`. Otherwise the
  Web UI shows the Gateway as up to date, with the time of the last check.
  The request carries nothing about the installation; a failed check changes
  nothing else. A new major version still comes with an add-on release.
- The Gateway now runs as an s6-overlay service. The add-on still stops when
  the Gateway exits, with its exit code.
- The add-on's own startup messages and the CA certificate are written to
  standard error instead of standard output; the **Log** tab shows both.

## 0.3.0

- Add a Home Assistant API proxy: point the Twingate Web App Resource at the
  add-on's own address (shown in the Web UI and the log) and upstream port
  `8124`, and the add-on reaches Home Assistant through the Supervisor with
  its own Supervisor token. No long-lived token is created or stored. It
  covers REST, MCP (`/api/mcp`, including streamed responses) and the
  WebSocket API, which clients use with any non-empty placeholder token.
  The add-on now asks for Home Assistant API access (`homeassistant_api`).
- The Gateway adds the client's Twingate token to every Web App request
  (`X-Twingate-Gateway-Token`); the proxy verifies it (signature with the
  network's signing keys, issuer, audience, expiry, and that it was issued
  for this Resource) and takes the caller's username from it. Requests
  without a valid token get `401`.
- New options `allow_read` (on by default), `allow_mcp` and `allow_write`
  (off by default), shown as the toggles **Allow reading**, **Allow MCP**
  and **Allow changes (write)**, set one access level for everyone who has
  access to the Resource in Twingate: reads over REST and WebSocket (an
  allow-list, without templates), the MCP endpoint `/api/mcp` (what it can
  do is set in Home Assistant's MCP Server settings, by default any action
  on any entity), and everything not always blocked, which includes reading
  and MCP. Direct routes into the Supervisor and the host, account and
  token management, backups, the Supervisor integration's MCP tools and MCP
  `call_action` calls for `hassio` and `backup` actions are blocked for
  everyone; with write they remain reachable indirectly. A request outside
  the access level gets `403` with the name of the toggle that would allow
  it; with all three off, every request does. The add-on logs the access
  level at start, and warns when all three are off. Requests that browsers
  mark as coming from a web page of another site are refused, so that a
  website opened on an authorised device cannot use the API or the
  WebSocket.
- The proxy logs every request and WebSocket command with the Twingate
  username, the access level and the decision, and the Web UI shows the
  proxy's state, the access level and the newest proxied requests.
- The Web UI shows a summary at the top and the details in sections that
  open and close, each summed up in one line in its header; a section with
  an error or a warning opens by itself, the browser remembers which
  sections you opened, long lists show the newest 10 entries with a
  "Show all" button, and the setup steps are shown until the first Twingate
  client connects.
- The Web UI's Setup section, its next steps and the startup log give the
  Gateway address with the add-on's host name
  (`<host name>.local.hass.io:8443`), which the Twingate Connector add-on on
  the same Home Assistant resolves; the host's LAN IP address remains the
  alternative for a Connector elsewhere.
- The proxy runs as its own unprivileged user (`api-proxy`), the only
  process besides root with the Supervisor token; s6 restarts it when it
  stops, and the Gateway, its logger and the Web UI do not depend on it.
  It keeps at most 16 WebSocket connections and 16 requests in progress per
  Twingate user (64 of each in all).
- New network port `8124/tcp`, not published by default; publish it only
  for a Resource that uses the host's IP address.
- `request_headers` keeps working for a Resource on Home Assistant's own
  port; nothing needs to change in an existing setup. One difference: the
  Gateway now also sends the caller's Twingate token
  (`X-Twingate-Gateway-Token`) to every Web App upstream on this Gateway,
  including Home Assistant on port 8123, which ignores it. The name
  `X-Twingate-Gateway-Token` is reserved.
