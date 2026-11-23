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
