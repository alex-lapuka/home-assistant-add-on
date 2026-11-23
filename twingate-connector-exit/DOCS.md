# Home Assistant Add-on: Twingate Connector (Exit) add-on

## What this add-on is for

This add-on runs a second Twingate Connector on the same Home Assistant,
next to the Twingate Connector add-on: for an exit network, or for any other
second Remote Network. A Connector belongs to exactly one Remote Network, and
Home Assistant installs each add-on only once, so a second Remote Network
needs this second add-on.

- In the Twingate Admin Console, add a new Connector to the other Remote
  Network and generate its own `access token` and `refresh token` (see
  [How to use](#how-to-use)). Do not reuse the tokens of the Connector in
  the Twingate Connector add-on.
- `network` is the same Twingate network name as in the Twingate Connector
  add-on. The tokens decide which Remote Network the Connector belongs to.
- For an exit network, follow Twingate's
  [exit network documentation](https://www.twingate.com/docs/exit-networks).

Otherwise this add-on is identical to the Twingate Connector add-on, and the
rest of this documentation applies to it as well. It has its own
configuration, log and Web UI.

## How to use

1. Install the add on.
2. Navigate to your Twingate network dashboard.
3. Setup a new connector and use the "Manual" setup.
4. Generate an `access token` and a `refresh token`.
5. Enter the `access token`, `refresh token` and remote network name into the add on configuration.
6. Click `start`.

For a more in depth walkthrough, check out the official [Getting Started Guide](https://www.twingate.com/docs/home-assistant-getting-started)

If you need any support, create an issue on the official [Twingate Community Github](https://github.com/Twingate-Community/home-assistant-add-on/issues)

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `access_token` | | The Connector's access token from the Admin Console. Required. |
| `refresh_token` | | The Connector's refresh token from the Admin Console. Required. |
| `network` | | Your Twingate network name, the `<name>` in `<name>.twingate.com`. Required. |
| `connector_log_level` | `info` | How much the Connector logs: `error`, `warn`, `info` or `debug`. |
| `connection_logs` | `false` | Log every connection and list recent ones on the Web UI. See [Connection logs](#connection-logs). |

The log levels are Twingate's numeric levels: `error` is level 3 (errors
only, the Connector's own default), `warn` is level 4 (also warnings),
`info` is level 5 (also information) and `debug` is level 7 (everything; very
verbose, for troubleshooting).

Up to version 1.1.0, the add-on started the Connector with level 3 (errors
only) also when `connector_log_level` was `info`. Since 1.2.0, `info` is
really level 5: if you used `info` (the default), the add-on log now has more
lines, with the Connector's warnings and information. To log errors only, as
before, set `connector_log_level` to `error`.

The add-on installs the latest Twingate Connector from Twingate's package
repository every time it starts, so it needs internet access at start.

Since 1.2.0, Home Assistant builds the add-on on your device from this
repository instead of downloading a ready-made image. Installing and updating
the add-on therefore take longer (a few minutes on slow devices) and need
internet access, and Home Assistant backups of the add-on include the
built image, so they are larger.

The add-on also sends the Connector two labels that the Admin Console shows
in the Connector's details: `hostname` (the add-on container's host name,
for example `local-twingate-connector-exit`) and `deployed_by`
(`home_assistant`).

## Web UI

Select **Open Web UI** on the add-on page (or turn on **Show in sidebar**) to
see a read-only status page. It refreshes every 5 seconds.

The top of the page always shows the Connector's state, whether its process
runs and its version, the number of Resources available to it and of relay
regions it is connected to, its uptime, and any problem that needs action
(for example when the Connector does not come online). Everything else is in
sections that you open and close. The header of each section sums it up in
one line, so a closed section still tells the essential fact:

- **Recent connections** (for example `12 connections, 1 open, 3 users`):
  open when `connection_logs` is on, see [Connection logs](#connection-logs).
- **Warnings and errors** from the Connector's log, grouped by message
  (for example `1 error and 4 warnings since the add-on started`). IP
  addresses (with their port) and email addresses in these messages are
  shown as `[IP]` and `[email]`, whether `connection_logs` is on or off; the
  add-on log keeps the lines unchanged.
- **Traffic**, from the Connector's metrics (for example `2.3 MiB received,
  145 KiB sent, 81% direct`): bytes received from and sent to Resources,
  split into direct (peer-to-peer) and relayed traffic, and the current rate.
  The counters start at zero when the Connector starts.
- **Status details**: the Connector's latest state as it prints it in its
  log (`Online`, `Authentication`, `Offline` or `Error`), since when, when it
  was last online, the recent state changes, and the Connector and add-on
  versions.
- **Configuration** (for example `Network mynetwork, log level info,
  connection logs off`): also the hostname and deployed-by labels and the
  metrics port.

Recent connections is open when `connection_logs` is on; the other sections
start closed. A section that shows an error or a warning opens by itself
and has a badge in its header, for example `1 error`; it never closes by
itself. The lists of connections and of warnings and errors show the newest
10 entries; **Show all** lists the rest. The
browser remembers which sections you opened or closed and your **Show all**
choices.

The page shows the Connector's own view. Whether Twingate sees the Connector
as online, and which Resources and users it serves, is shown in the Twingate
Admin Console (`https://<network>.twingate.com`), in the Remote Network the
Connector belongs to; the page links to it. When the Connector keeps cycling
through `Offline`, `Authentication` and `Error`, the tokens or the network
name are usually wrong, or the tokens were revoked: generate new tokens in
the Admin Console and enter them in the add-on configuration.

The page never shows the access token, the refresh token or the Supervisor
token. The Web UI and the log relay that feeds it run as two different
unprivileged users without these tokens in their environment, and they
cannot read the add-on options. The Web UI cannot read the relay's files or
signal or trace the relay. Warnings, errors and connection summaries are
kept in memory only and are gone when the add-on restarts; the full
Connector log stays in the add-on's **Log** tab.

### How the Connector's log reaches the page

The Connector writes its log to `s6-log`, which copies every line unchanged
(without adding a timestamp) to the add-on log. `s6-log` also keeps a copy
of the latest lines in memory (`/dev/shm/twingate-connector-log`, at most
about 1 MiB; older lines are deleted), which only the log relay can read; the
relay summarizes it for the page. No Python program is in the path of the
Connector's log: when the log relay or the Web UI stops, hangs, fails to
start or cannot find Python, the Connector keeps running and its log keeps
reaching the add-on log. While the relay is not working, the page says that
its data may be out of date. With `connection_logs` on, the copy contains
the connection lines with their personal data, until it is overwritten or
the add-on stops.

Lines longer than 64 KiB are split into several lines of the add-on log
(nothing is lost). If the copy cannot be kept (for example because
`/dev/shm` is full), the lines still reach the add-on log, and the page
shows fewer of them or says that it cannot read the Connector's log.

While `/dev/shm` is full, `s6-log` keeps the lines it cannot write to the
copy in memory, up to its limit of 16 MiB (about 15 MB of lines). When it
reaches the limit, it logs
`s6-log: fatal: unable to stralloc_catb: Out of memory` and from then on
copies the Connector's log to the add-on log only, until the add-on
restarts; the page then says that it cannot read the Connector's log. The
lines `s6-log` had just read when it stopped (about 8 KB) are lost; all
other lines are in the add-on log, and the Connector is not affected.

## Connection logs

When `connection_logs` is on, the add-on starts the Connector with
`TWINGATE_LOG_ANALYTICS=v3`. The Connector then writes one line starting with
`ANALYTICS` to the add-on log for every connection that opens, closes, fails
or is denied ([Twingate's description of the format](https://www.twingate.com/docs/connector-real-time-logs)).

These lines contain personal data: the email address of the user, the
Resource and port they connect to, the public IP address of their device, its
approximate location (city, region, country and coordinates) and the bytes
transferred. They are kept wherever Home Assistant keeps the add-on log.
Turn the option on only if you want this record, and tell the people who use
your Twingate network.

The Web UI then lists the newest 100 connections since the add-on started:
when each one started, the user, the Resource (its address, port, protocol
and the Resource's IP address), whether it went direct or through a relay,
the bytes received and sent, the duration, the approximate location (city,
region and country) and the result (open, closed, failed or denied, with the
Connector's error message). It does not show the device's public IP address,
the device ID or the coordinates, and it keeps the list in memory only.

Twingate may not offer connection logs on every plan. If your plan does not
include them, the Connector logs the warning `Network analytics is not
supported in your Twingate product tier` and ignores the option; the Web UI
says so. With the log level `error`, the Connector does not log this warning,
so the Web UI cannot tell; choose `warn` or `info` to see it.

## What listens where

| Port | Inside the add-on container | Reachable from |
| --- | --- | --- |
| 8102/tcp | The Web UI | Only the Home Assistant ingress proxy (172.30.32.2). Other connections are closed without an answer. Not published on the host. |
| 9999/tcp | The Connector's Prometheus metrics (`/metrics`), all container addresses | Home Assistant and other add-ons on the internal add-on network. Not published on the host or your LAN. |
| Unix socket `/var/run/twingate/connector.sock` | The Connector's local API (`twingate-connectorctl health`) | Root inside the container only. |

The metrics contain only byte counters, the uptime and the numbers of
Resources and relay regions. The Connector itself only makes outgoing
connections to Twingate; no port needs to be opened on your router.
