# Home Assistant Add-on: Twingate Gateway

This add-on lets scripts and AI agents use the Home Assistant API through
Twingate without ever holding a Home Assistant credential.

It runs the [Twingate Gateway](https://github.com/Twingate/gateway) in Web App
mode. The Gateway adds an `Authorization: Bearer <long-lived-token>` header to
every request it forwards to Home Assistant, so the client never sees the
token. This covers the REST API (`/api/...`) and the Model Context Protocol
endpoint (`/api/mcp`). Who may use the API is decided in Twingate, per user,
group or service account, and access is revoked there.

The add-on is experimental.

## How it works

1. A script or agent sends a plain HTTP request to the Twingate Resource
   alias, for example `http://ha-api.int/api/states`. It sends no
   `Authorization` header.
2. The Twingate Client on that machine tunnels the request to the Twingate
   Connector add-on.
3. The Connector sees that the Resource uses a Gateway and forwards the
   connection to this add-on at `<home-assistant-ip>:8443`.
4. The Twingate Client opens a TLS connection to the Gateway and presents a
   Twingate access token for the user or service account. The Gateway checks
   the token against Twingate's public signing keys.
5. The Gateway forwards the request to the Resource address and upstream port
   (for example `<home-assistant-ip>:8123`), adds the headers configured in
   this add-on, and writes an audit log entry with the Twingate identity.
6. Home Assistant authenticates the request with the injected token.

Use this add-on for programmatic access: scripts, automations running
elsewhere, and MCP clients. Do not use it for opening the Home Assistant
frontend in a browser; keep browser access on an ordinary Twingate Resource
(see [Security considerations](#security-considerations)).

## Prerequisites

- Home Assistant OS, or another installation type with the Supervisor
  (add-ons need the Supervisor).
- The Twingate Connector add-on from this repository, installed, running and
  shown as online in the Twingate Admin Console. Note the Remote Network it
  belongs to: the Gateway and the Resource go into the same Remote Network.
- Administrator access to your Twingate network. The Gateway is part of
  Twingate's Identity Firewall (Privileged Access) features; check
  [Twingate's documentation](https://www.twingate.com/docs/identity-firewall)
  for availability on your plan.
- A current Twingate Client and Connector. Twingate does not document a
  minimum version for Web App Resources.
- A fixed LAN IP address for the Home Assistant host (a DHCP reservation or a
  static address). Both the Gateway address and the Resource address use it.
- One of the following, to create the Twingate objects in step 3:
  - [Terraform](https://developer.hashicorp.com/terraform/install) 1.11 or
    later with the [Twingate provider](https://registry.terraform.io/providers/Twingate/twingate/latest/docs)
    5.0.0 or later, or
  - `curl` and `jq` in a POSIX shell.
- A Twingate API key, created in the Admin Console under **Settings** >
  **API**. Twingate's sources differ on the permission level: the
  [API overview](https://www.twingate.com/docs/api-overview) says
  **Read & Write** allows creating, updating and deleting objects, and the
  Gateway wiki's standalone (SSH) installation guide uses **Read & Write**,
  while the Gateway wiki's Web App quick start uses
  **Read, Write & Provision** (which adds generating Connector tokens and
  Service Keys). Start with **Read & Write**; if a request is rejected for
  lack of permission, create a key with **Read, Write & Provision**.
- For MCP clients: Home Assistant 2025.11 or later, which serves the
  Model Context Protocol endpoint at `/api/mcp`.

## Setup

### Step 1: Install and configure the add-on

1. Add this repository to Home Assistant (see the repository README) and
   install the **Twingate Gateway** add-on.
2. On the **Configuration** tab, set `network` to your Twingate network name:
   the `<network>` part of `https://<network>.twingate.com`. This is the same
   value you entered in the Connector add-on.
3. Leave the other options at their defaults for now.
4. In the **Network** section, container port `8443/tcp` is published on host
   port `8443`. Keep it. If you change the host port, use that port in the
   Gateway address in step 3.
5. Start the add-on.

### Step 2: Copy the CA certificate from the Web UI

On its first start the add-on creates a certificate authority (CA) and keeps
it in the add-on's data folder. The Gateway uses this CA to sign the TLS
certificates it presents to Twingate Clients. Twingate Clients trust the
Gateway only after the CA certificate is registered in Twingate.

1. On the add-on's **Info** tab, select **Open Web UI**.
2. In the **Setup** section, select **Copy** next to the CA certificate and
   paste it into a file named `ca.pem` on the machine where you will run
   Terraform or `curl`.

The same section shows the certificate's subject, SHA-256 fingerprint and
expiry date, and the Gateway address you need in step 3. This is the public
certificate only; the CA private key never leaves the add-on. If **Copy**
does not work in your browser, select the certificate text and copy it.

The add-on also prints the CA certificate on every start, so you can copy it
from the **Log** tab instead. It looks like this:

```text
[12:00:00] INFO: The Gateway signs its TLS certificates with this CA. Twingate Clients trust the Gateway only if this CA certificate is registered in Twingate as the X.509 certificate authority of the Gateway.
[12:00:00] INFO: CA subject: CN=Twingate Gateway add-on CA 1a2b3c4d
[12:00:00] INFO: CA expires: Nov 20 12:00:00 2036 GMT
[12:00:00] INFO: CA SHA-256 fingerprint: 3F:A1:...:9C
[12:00:00] INFO: CA certificate (PEM, certificate only):
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
```

Copy everything from `-----BEGIN CERTIFICATE-----` to
`-----END CERTIFICATE-----`, including those two lines, into a file named
`ca.pem` on the machine where you will run Terraform or `curl`. This is the
public certificate only; the CA private key never leaves the add-on.

### Step 3: Register the CA, the Gateway and the Resource in Twingate

Twingate documents these objects through its
[GraphQL API](https://www.twingate.com/docs/api) and the
[Terraform provider](https://registry.terraform.io/providers/Twingate/twingate/latest/docs).
Use either option below. Both create three objects:

1. **X.509 certificate authority**: the contents of `ca.pem`.
2. **Gateway**: the address where the Connector reaches this add-on,
   `<home-assistant-ip>:8443` (shown as **Gateway address** in the Web UI),
   in the Remote Network of the Connector add-on, using the CA from 1.
3. **Web App Resource** for the Home Assistant API, bound to the Gateway:
   - **Address**: `<home-assistant-ip>`. The Gateway sends requests to this
     address, so it must be reachable from the add-on container. Use the
     Home Assistant host's LAN IP address.
   - **Upstream port**: the port Home Assistant answers on. This is `8123` on
     most installations. Home Assistant's HTTP documentation says Home
     Assistant OS defaults to port `80` from release 2026.8, so use the port
     in the address you open Home Assistant with on your LAN. The examples use
     `8123`.
   - **Alias**: the name clients use, for example `ha-api.int`. The Twingate
     Client recognizes it; choose a name that does not clash with a real host
     name.
   - **Downstream port**: the port clients use with the alias. With `80`,
     clients use `http://ha-api.int`.

Replace these placeholders in the examples:

| Placeholder | Value |
| --- | --- |
| `<network>` | Your Twingate network name, from `https://<network>.twingate.com`. |
| `<api-token>` | Your Twingate API key. |
| `<remote-network-id>` | ID of the Remote Network the Connector add-on belongs to. Open **Network** > **Remote Networks** in the Admin Console and select it; the ID is the last part of the URL, `https://<network>.twingate.com/networks/<remote-network-id>`. |
| `<home-assistant-ip>` | LAN IP address of the Home Assistant host. |

Clients connect with plain `http://`. The traffic is still encrypted: inside
the Twingate tunnel, and inside the TLS connection between the Twingate Client
and the Gateway.

#### Option A: Terraform

The CA's `certificate` argument is write-only, which needs Terraform 1.11 or
later. The `twingate_web_app_resource` resource needs provider 5.0.0 or later.

1. Put `ca.pem` in an empty folder and create `main.tf` next to it:

   ```hcl
   terraform {
     required_version = ">= 1.11"

     required_providers {
       twingate = {
         source  = "Twingate/twingate"
         version = "~> 5.0"
       }
     }
   }

   provider "twingate" {
     network = "<network>"
     # The API key is read from the TWINGATE_API_TOKEN environment variable.
   }

   locals {
     remote_network_id = "<remote-network-id>"
     home_assistant_ip = "<home-assistant-ip>"
   }

   resource "twingate_x509_certificate_authority" "home_assistant_gateway" {
     name        = "Home Assistant Gateway add-on"
     certificate = file("${path.module}/ca.pem")
   }

   resource "twingate_gateway" "home_assistant" {
     remote_network_id = local.remote_network_id
     address           = "${local.home_assistant_ip}:8443"
     x509_ca_id        = twingate_x509_certificate_authority.home_assistant_gateway.id
   }

   resource "twingate_web_app_resource" "home_assistant_api" {
     name              = "Home Assistant API"
     remote_network_id = local.remote_network_id
     gateway_id        = twingate_gateway.home_assistant.id
     address           = local.home_assistant_ip
     alias             = "ha-api.int"

     downstream = {
       port = 80
     }

     upstream = {
       port = 8123
     }
   }
   ```

2. Apply it:

   ```bash
   export TWINGATE_API_TOKEN="<api-token>"
   terraform init
   terraform apply
   ```

#### Option B: Twingate API with curl

Run these commands in the folder that holds `ca.pem`. Each request prints the
JSON response and saves it to a file. Check that it contains `"ok": true`; if
not, the `error` field says why.

1. Set the values and define a helper that sends a GraphQL request:

   ```bash
   export TWINGATE_NETWORK="<network>"
   export TWINGATE_API_TOKEN="<api-token>"
   export REMOTE_NETWORK_ID="<remote-network-id>"
   export HOME_ASSISTANT_IP="<home-assistant-ip>"

   twingate_graphql() {
     curl -sS -X POST "https://${TWINGATE_NETWORK}.twingate.com/api/graphql/" \
       -H "X-API-KEY: ${TWINGATE_API_TOKEN}" \
       -H "Content-Type: application/json" \
       --data-binary @-
   }
   ```

   If a request prints nothing or an HTML page instead of JSON, replace
   `${TWINGATE_NETWORK}.twingate.com` with the exact host name of your Admin
   Console address.

2. Register the CA:

   ```bash
   QUERY='mutation($name: String!, $certificate: String!) {
     x509CertificateAuthorityCreate(name: $name, certificate: $certificate) {
       ok
       error
       entity { id }
     }
   }'

   jq -n --arg query "$QUERY" --arg certificate "$(cat ca.pem)" \
     '{query: $query, variables: {name: "Home Assistant Gateway add-on", certificate: $certificate}}' \
     | twingate_graphql | tee ca.json

   X509_CA_ID=$(jq -r '.data.x509CertificateAuthorityCreate.entity.id' ca.json)
   echo "X509_CA_ID=${X509_CA_ID}"
   ```

3. Create the Gateway:

   ```bash
   QUERY='mutation($address: String!, $remoteNetworkId: ID!, $x509CAId: ID!) {
     gatewayCreate(address: $address, remoteNetworkId: $remoteNetworkId, x509CAId: $x509CAId) {
       ok
       error
       entity { id }
     }
   }'

   jq -n --arg query "$QUERY" \
     --arg address "${HOME_ASSISTANT_IP}:8443" \
     --arg remoteNetworkId "$REMOTE_NETWORK_ID" \
     --arg x509CAId "$X509_CA_ID" \
     '{query: $query, variables: {address: $address, remoteNetworkId: $remoteNetworkId, x509CAId: $x509CAId}}' \
     | twingate_graphql | tee gateway.json

   GATEWAY_ID=$(jq -r '.data.gatewayCreate.entity.id' gateway.json)
   echo "GATEWAY_ID=${GATEWAY_ID}"
   ```

4. Create the Web App Resource:

   ```bash
   QUERY='mutation($name: String!, $address: String!, $alias: String, $gatewayId: ID!, $remoteNetworkId: ID!, $downstream: WebAppDownstreamInput!, $upstream: WebAppUpstreamInput!) {
     webAppResourceCreate(
       name: $name,
       address: $address,
       alias: $alias,
       gatewayId: $gatewayId,
       remoteNetworkId: $remoteNetworkId,
       downstream: $downstream,
       upstream: $upstream
     ) {
       ok
       error
       entity { id }
     }
   }'

   jq -n --arg query "$QUERY" \
     --arg address "$HOME_ASSISTANT_IP" \
     --arg gatewayId "$GATEWAY_ID" \
     --arg remoteNetworkId "$REMOTE_NETWORK_ID" \
     '{query: $query, variables: {
        name: "Home Assistant API",
        address: $address,
        alias: "ha-api.int",
        gatewayId: $gatewayId,
        remoteNetworkId: $remoteNetworkId,
        downstream: {port: 80},
        upstream: {port: 8123}
      }}' \
     | twingate_graphql | tee resource.json
   ```

Keep the printed `GATEWAY_ID`; you need it if you ever replace the CA.

After either option, the CA is listed in the Admin Console under
**Settings** > **Certificate Authorities**.

**Upstream TLS:** these examples assume Home Assistant answers plain HTTP on
its port. If you set an SSL certificate in Home Assistant's HTTP server
settings so that it serves HTTPS itself, the Resource needs an upstream TLS
mode. The Terraform provider has `upstream.tls_mode` from version 5.2.0:
`VERIFY_CA` for a certificate from a public CA (the host name is not checked,
which matters because the Gateway connects by IP address) or `INSECURE` for a
self-signed certificate. The public API reference does not list this field.

**Downstream TLS:** the Resource's downstream TLS mode defaults to none, which
is what this guide uses. The Terraform provider also offers
`downstream.tls_mode = "TLS13"` (provider 5.2.0 or later), where clients
connect with `https://`; every client device must then trust the add-on's CA.
This guide does not cover that setup.

### Step 4: Add the Home Assistant token to the add-on

1. Decide which Home Assistant user the API calls run as. A dedicated user
   keeps those calls apart from your own in Home Assistant and lets you revoke
   them separately. For the MCP endpoint `/api/mcp` with default settings,
   the user must be an administrator (see step 7).
2. Signed in as that user, open the user profile, then the **Security** tab.
   Under **Long-lived access tokens**, create a token, for example named
   `Twingate Gateway`. Copy it; Home Assistant shows it only once.
3. On the add-on's **Configuration** tab, add the header. In YAML mode the
   option looks like this:

   ```yaml
   request_headers:
     - name: Authorization
       value: "Bearer <long-lived-token>"
   ```

   In the form, add one entry with the name `Authorization` and the value
   `Bearer <long-lived-token>`. Keep the space after `Bearer`.
4. Save and restart the add-on. The log then shows:

   ```text
   [12:00:00] INFO: Request headers injected into Web App requests: Authorization (values are not logged).
   ```

### Step 5: Grant access in Twingate

1. In the Admin Console, open the **Home Assistant API** Resource and give
   access only to the groups that should use the Home Assistant API.
2. For unattended agents, use a service account: under **Team** >
   **Services**, create a service account, add the **Home Assistant API**
   Resource to it and generate a Service Key. Run the Twingate Client in
   headless mode with that key on the agent's machine
   ([Linux](https://www.twingate.com/docs/linux-headless),
   [Windows](https://www.twingate.com/docs/windows-headless)). See
   [Services](https://www.twingate.com/docs/services).
3. For people, install the [Twingate Client](https://www.twingate.com/download)
   on the machine that runs the script or agent and sign in.

### Step 6: Test

On a machine with a signed-in Twingate Client that has access to the
Resource, run:

```bash
curl http://ha-api.int/api/
```

Do not pass an `Authorization` header. The expected response is:

```json
{"message": "API running."}
```

Any other Home Assistant REST endpoint works the same way, for example
`curl http://ha-api.int/api/states`. Each request appears under
**Recent requests** in the Web UI, and the audit log in the add-on log
records it in full.

### Step 7: Connect an MCP client (optional)

1. Enable the Model Context Protocol integration (`mcp_server`) in Home
   Assistant. In current releases, go to **Settings** > **System** > **AI**
   and select **Enable** on the **Model Context Protocol** card if it is
   shown.
2. Choose what the endpoint exposes. By default the main URL `/api/mcp`
   exposes all sets of AI tools, including the **Home Assistant** set, which
   can read all entities, logs and history and perform any action, and it
   requires an administrator account. To limit it:
   - Next to **Main URL**, select **Configure**, turn off
     **Expose all AI tools** and select only **Device control**. You can also
     turn on **Read-only**. If the token's user is not an administrator, also
     turn off **Require an administrator account**.
   - Or use the individual URL `/api/mcp/assist`, which exposes only
     **Device control** and does not require an administrator account.
   - **Device control** only reaches the entities exposed to voice
     assistants. Choose them under **Settings** > **Voice assistants**, on
     the **Expose** tab.
3. Add the server to your MCP client with the alias URL and no
   authentication. For example, with Claude Code:

   ```bash
   claude mcp add --transport http homeassistant http://ha-api.int/api/mcp
   ```

   No header and no OAuth sign-in are needed: the Gateway adds the token. The
   sign-in steps in Home Assistant's MCP documentation do not apply here.

Other MCP clients that support the Streamable HTTP transport work the same
way: point them at `http://ha-api.int/api/mcp` (or `/api/mcp/assist`) without
authentication.

## Web UI

Select **Open Web UI** on the add-on's **Info** tab, or turn on
**Show in sidebar** there to open it from the Home Assistant sidebar. The page
is read-only and refreshes every 5 seconds. It shows:

- **Setup**: the CA certificate with a **Copy** button, its subject, SHA-256
  fingerprint and expiry, and the Gateway address to register in Twingate.
  The add-on cannot see the host's LAN IP address, so the address reads
  `<home-assistant-ip>:8443` unless you opened Home Assistant by IP address;
  then it suggests that address. The port is the host port set in the
  **Network** section.
- **Status**: whether the Gateway answers its health check, the Gateway
  version and whether a newer 2.x release is available (see
  [Gateway updates](#gateway-updates)), the Twingate network, whether the
  Twingate signing keys are working, the static certificate, the add-on
  version and the Gateway's uptime.
- **Configuration**: the names of the injected request headers (never their
  values), the certificate IP addresses, the audit log setting, the log level
  and whether the CA is your own.
- **Traffic**: open connections, closed proxy connections (connections from
  Twingate Clients; health checks and rejected connections are not
  included), successful and failed authentications, connections rejected
  before a request (any connection that never completed TLS and a request,
  including port probes and TLS handshakes that fail because the CA is not
  registered in Twingate), HTTP responses by status class, latency, and
  requests to Home Assistant, from the Gateway's metrics. The counters start
  at zero when the add-on starts.
- **Recent requests**: the newest 100 requests with time, Twingate user,
  method, path, status and duration.

**Signing keys** is derived from what the add-on can observe: successful
client authentications (the Gateway accepts a Twingate token only after
verifying it with the signing keys), a check of the signing-key URL
`https://<network>.twingate.com/api/v1/jwk/ec` that the Web UI makes shortly
after the add-on starts and then every 15 minutes, or every 2 minutes while
the check fails, and the network check at startup.

What the Web UI never shows: request header values, the CA private key, the
Supervisor token, or the headers recorded in the audit log. Paths in
**Recent requests** are shown without their query string (marked `?…`),
because query strings can carry secrets. For the same reason the webhook ID
in `/api/webhook/<id>` paths is masked (`/api/webhook/***`): anyone who knows
it can trigger the webhook. The Web UI keeps the recent requests in memory
only.

How it gets the audit log: with `audit_log: addon_log`, the Gateway writes
its audit log to its standard output. `s6-log`, the logger of the add-on's
service supervisor, copies every line unchanged to the add-on log and also
keeps a small copy of the newest entries in memory
(`/dev/shm/twingate-gateway-audit`, about 1.5 MiB; older entries are
deleted). A small relay follows this copy and passes a summary without
headers, query strings or webhook IDs to the Web UI. With
`audit_log: file`, the relay reads `audit.log` instead.
The Gateway does not wait for the relay or the Web UI: if they stop, hang,
restart or cannot start, requests through the Gateway and the audit log are
not affected, and only the **Recent requests** list may be out of date. The
Web UI then shows a warning in that section when the relay has not reported
for 15 seconds. When the relay starts again, it reads the newest entries of
the copy, so requests made while it was down usually appear in the list.
The same holds when the copy cannot be kept: if `/dev/shm` is full, new
entries are missing from the copy, and `s6-log` keeps them in memory until
it can write them; if the copy cannot be set up, `s6-log` copies the audit
log to the add-on log only until the add-on restarts, and says so in the
log. Either way requests and the add-on log are not affected, and the Web UI
shows a warning under **Recent requests**.

The memory of `s6-log` is limited to 64 MiB, enough for about 60 MB of
entries waiting for a full `/dev/shm`, or for a single entry of about 18 MB.
When `s6-log` needs more, it logs
`s6-log: fatal: unable to stralloc_catb: Out of memory` and from then on
copies the audit log to the add-on log only, until the add-on restarts; the
Web UI then says that new requests are not shown. The entries `s6-log` had
just read when it stopped (about 8 KB, usually fewer than 10 entries) are
lost; all other entries are in the add-on log, and requests through the
Gateway are not affected.

Access: the Web UI is served through Home Assistant ingress only. Home
Assistant signs the user in; by default only administrators see the sidebar
entry. The Web UI has no port on the host and accepts connections only from
the Supervisor's ingress proxy. It runs as the unprivileged user `nobody`,
which cannot read the Gateway configuration, the Supervisor token,
`audit.log`, the copy of the audit log or the private key of the CA the
add-on creates. With your own CA, the permissions of your key file decide;
see [`custom_ca_keyfile`](#options-custom_ca_certfile-and-custom_ca_keyfile).
The relay runs as a second unprivileged user, `audit-relay`, which can read
the copy of the audit log but none of the other files named above, and
`s6-log` as a third, `audit-log`, which writes the copy. None of these users
can stop or signal another's processes or the Gateway. With
`audit_log: file`, the relay runs as root instead, because it needs root to
read `audit.log`.

## Configuration

Example configuration:

```yaml
network: <network>
log_level: info
request_headers:
  - name: Authorization
    value: "Bearer <long-lived-token>"
certificate_ip_addresses: []
audit_log: addon_log
```

The add-on checks all options when it starts. If an option is invalid, it
logs an error that names the option (never a header value) and stops.

### Option: `network` (required)

Your Twingate network name: the `<network>` part of
`https://<network>.twingate.com`, 1 to 63 lowercase letters and digits. A
pasted address such as `https://<network>.twingate.com/` is accepted. The
Gateway uses it to fetch Twingate's public signing keys. At startup the add-on
checks that the network exists and stops if Twingate reports that it does not;
if Twingate cannot be reached, it logs a warning and starts anyway.

### Option: `log_level`

Level of the Gateway's system log: `debug`, `info` (default), `warn` or
`error`. It does not affect the audit log or the add-on's own startup
messages.

### Option: `request_headers`

HTTP headers that the Gateway adds to every request it forwards. Each entry
has a `name` and a `value`. The value field is masked in the user interface.

- Headers apply to every Web App Resource that uses this Gateway.
- A header replaces any header of the same name sent by the client.
- A per-Resource header rewrite configured in Twingate for the same name
  overrides the add-on's header.
- A value is either a static string, such as `Bearer <long-lived-token>`, or
  text with exactly one placeholder that the Gateway fills in per request:

  | Placeholder | Value |
  | --- | --- |
  | `{{jwt}}` | The Twingate access token of the connection (a JWT signed by Twingate; not a Home Assistant token). |
  | `{{username}}` | The Twingate username. |
  | `{{groups}}` | The user's Twingate groups, comma-separated. |
  | `{{clientGeoCity}}` | City of the client device. |
  | `{{clientGeoRegion}}` | Region of the client device. |
  | `{{clientGeoCountry}}` | Country of the client device. |
  | `{{clientGeoLatLong}}` | Latitude and longitude of the client device. |

- Names may contain only letters, digits and ``!#$%&'*+-.^_`|~`` (no spaces
  or colons). Values may contain only printable ASCII characters. Each name
  may appear once; names are case-insensitive.
- The add-on logs header names at startup but never their values. The
  Gateway's audit log does not record injected headers.

Default: no headers.

### Option: `certificate_ip_addresses`

IPv4 addresses for which the add-on issues a static TLS certificate, signed
by the add-on's CA. You only need this if clients reach a Resource on this
Gateway by IP address instead of by alias. IPv6 addresses are rejected: the
Gateway cannot proxy to an IPv6 Resource address.

The Gateway issues a certificate on demand for whatever host name a client
dials, so a Resource with an alias such as `ha-api.int` needs no setup. A
client that dials a bare IP address sends no host name in the TLS handshake,
so the Gateway cannot issue a certificate for it on demand; the static
certificate covers that case. The recommended setup is an alias.

The static certificate is valid for 825 days. It is issued again at startup
when the list of addresses or the CA changes, or when it expires within 30
days. Because this check runs only when the add-on starts, restart the add-on
at least once every two years.

Default: empty.

### Option: `audit_log`

Where the Gateway writes its audit log, which records every request with the
Twingate identity, the incoming request headers and the response status:

- `addon_log` (default): the add-on's **Log** tab.
- `file`: `audit.log` in this add-on's configuration folder (the add-on's
  own folder under `addon_configs` on the Home Assistant host, mounted at
  `/config` inside the add-on). The file is rotated at 10 MiB and three
  compressed old files are kept.

With either setting, the Web UI shows summaries of the newest 100 requests
(see [Web UI](#web-ui)).

### Options: `custom_ca_certfile` and `custom_ca_keyfile`

Use your own CA instead of the one the add-on creates. Set both options to
file names relative to the Home Assistant `ssl` folder, for example
`twingate/ca.crt` and `twingate/ca.key`; a leading `/ssl/` is also accepted.

Requirements:

- The certificate is a PEM X.509 CA certificate (basic constraints `CA:TRUE`)
  that has not expired. If it has a key usage extension, it must allow
  certificate signing.
- The private key is an unencrypted PEM key that belongs to the certificate.
- Make the key file readable by its owner only (`chmod 600`). Unprivileged
  processes in the add-on, such as the Web UI, can read a key file that is
  readable by others. The add-on logs a warning at startup when the key is
  readable by its group or by others, and starts anyway.

The add-on then shows this certificate in the Web UI and prints it in the log
instead of its own; that is the one to register in Twingate. The CA the
add-on created stays in its data folder and is used again if you clear both
options.

Default: not set.

### Network port: `8443/tcp`

The Gateway's TLS listener. The Connector forwards connections for Web App
Resources to `<home-assistant-ip>:<host port>`, so the Gateway address in
Twingate must use the host port configured here (default `8443`).

## TLS certificates and the CA

- The add-on creates an ECDSA P-256 CA, valid for 10 years, on first start.
  It warns in the log when the CA expires within 30 days.
- It creates a new CA, with a warning in the log, when the stored CA cannot
  be used (for example it expired or a file is missing or damaged). A
  reinstalled add-on also starts with a new CA, because uninstalling removes
  the add-on's data. Each new CA must be registered in Twingate; see
  [Troubleshooting](#clients-cannot-connect-after-the-ca-changed).
- The CA is part of the add-on's data, so a backup of the add-on contains the
  CA private key, and restoring the backup restores the CA.

## Gateway updates

The add-on follows the newest Twingate Gateway 2.x release: it takes the
Gateway from the image tag `twingate/gateway:2` on Docker Hub, which Twingate
moves to each new 2.x release. The Gateway is taken when Home Assistant builds
the add-on, that is when you install, update or rebuild it, and keeps that
version until the next build. The log names it at every start
(`Starting Twingate Gateway 2.1.0 on port 8443/tcp ...`), and the Web UI shows
it under **Status**.

To update the Gateway to the newest 2.x release, rebuild the add-on:

1. Open **Settings** > **Apps** > **Twingate Gateway** (in older Home
   Assistant versions, **Apps** are called **Add-ons**).
2. On the **Info** tab, open the menu (⋮) of the **Controls** card and select
   **Rebuild**.

Or run `ha apps rebuild <slug>` in the Home Assistant command line
(`ha addons rebuild <slug>` with older versions of the command line); the Web
UI shows the command with this add-on's slug. Home Assistant builds the image
again with the release that `twingate/gateway:2` points to at that moment and
starts the add-on again if it was running. The configuration, the CA and the
certificates it issued are kept, so nothing changes in Twingate. The Gateway
accepts no connections until the rebuild is done.

The Web UI checks for a newer release shortly after the add-on starts and then
once a day. It reads Docker Hub's public list of the image's tags,
`https://hub.docker.com/v2/namespaces/twingate/repositories/gateway/tags?page_size=100`
(and at most two further pages of it), and finds the release that the tag `2`
points to by comparing their platform images. A newer release counts only
when `2` points to it: a final 2.x.y version, never one with a suffix such as
`-dev` or another major version, and not a release that Twingate has published
but `2` does not point to yet, because a rebuild would not install it. The
request has a generic `User-Agent` and no add-on name, network name or other
data about your installation; like any request, it shows Docker Hub your
public IP address. It is not a pull and does not count against Docker Hub's
pull rate limit.

When a newer release is available, the Web UI shows a notice with the steps
above at the top of the page, and the log says so after each start of the
add-on and then at most once a day while it remains so:

```text
Web UI: Twingate Gateway 2.2.0 is available; this add-on runs Gateway 2.1.0. To update, rebuild the add-on: ...
```

Otherwise **Status** shows `Up to date (checked <time>)` next to the Gateway
version. If the check fails, for example without internet access, it is tried
again after 5, 15 and then every 60 minutes. The Web UI then shows when the
last check succeeded, or that none has yet; nothing else changes. The version
it compares is the one the Gateway reports in its audit log, or, until the
first request, the version recorded when the add-on was built. The Web UI's
status document (`api/status`) has the result under `gateway_update`
(`running`, `latest`, `update_available`, `checked_at`).

A new major version of the Gateway (3.x) is never installed by a rebuild. It
comes with an update of the add-on, because its configuration, metrics or
audit log may change.

## Security considerations

### Keep the Home Assistant token in the add-on

Put the token in the add-on's `request_headers` option, not in a per-Resource
header rewrite in Twingate (`requestHeaderRewrites` in the API,
`request_header_rewrites` in Terraform). Per-Resource rewrites are carried
inside the Twingate access token that is delivered to each user's device. That
token is signed but not encrypted, so anyone who has access to the Resource
can read the value, and it is also readable through the Twingate API. Headers
set in the add-on stay on the Home Assistant host.

A per-Resource rewrite for `Authorization` would also override the add-on's
header, so do not define one on this Resource.

### Use this Gateway only for the Home Assistant API

The add-on's headers apply to every Web App Resource that uses this Gateway.
Any other Resource bound to it would receive your Home Assistant token. Bind
only the Home Assistant API Resource to this Gateway.

### Twingate access is the only gate

Anyone granted the Resource, whether a user, a group member or a service
account, acts as the token's Home Assistant user with all of that user's
rights. Home Assistant sees the same token on every request and cannot tell
callers apart; only the Gateway's audit log records who made a request.

- Grant the Resource only to the groups and service accounts that need it.
- Use a dedicated Home Assistant user for the token, with no more rights than
  the API use needs.
- To revoke one caller, remove its access in Twingate. Connections already
  open close when their Twingate access token expires.
- To revoke everyone at once, delete the long-lived token in Home Assistant.

### Keep browser access to Home Assistant separate

Use a dedicated alias, such as `ha-api.int`, for API and agent access, and
keep normal browser access to Home Assistant on an ordinary Twingate Resource
that does not use this Gateway. If you opened the Home Assistant frontend
through the Gateway:

- The frontend's REST calls would carry the injected token instead of the
  signed-in user's own, so they would run as the token's owner.
- The audit log would record the browser's own request headers unredacted,
  including its session tokens.

### What the audit log contains

The Gateway logs every request with the Twingate identity, the method and URL,
the request headers as sent by the client (unredacted) and the response status
and headers. Headers the Gateway injects are not logged, so the Home Assistant
token does not appear. Clients should not send credentials of their own.
Anyone who can read the add-on log, or the `audit.log` file when
`audit_log: file` is set, can read these entries. The copy of the newest
entries that the add-on keeps for the Web UI's relay with
`audit_log: addon_log` is kept in memory and is readable only by root,
`s6-log`'s user and the relay's user. The Web UI shows only a summary of
each entry, without headers or query string and with webhook IDs masked.

### Network exposure

- Port 8443 is reachable on your LAN. The Gateway proxies only connections
  that present a valid Twingate access token; the only request it serves
  without one is its `/healthz` health check, which returns an empty
  response.
- The Gateway's only outbound connection is to `https://<network>.twingate.com`
  to fetch Twingate's public signing keys; the Web UI checks the same address
  every 15 minutes, or every 2 minutes while the check fails. Audit logs stay
  on the Home Assistant host.
- Once a day the Web UI reads the public list of image tags of the Gateway
  from `https://hub.docker.com`, with nothing about your installation (see
  [Gateway updates](#gateway-updates)).
- The Web UI has no port on your LAN. It is reachable only through Home
  Assistant ingress and accepts connections only from the Supervisor's
  ingress proxy.
- The add-on does not change direct access to Home Assistant on your LAN.
- No reverse proxy or trusted proxy settings are needed in Home Assistant:
  the Gateway does not send an `X-Forwarded-For` header.

### Secrets at rest

The token is stored in the add-on options and the CA private key in the
add-on's data folder. Both are included in Home Assistant backups of the
add-on, so protect your backups.

## Troubleshooting

### The add-on stops right after starting

Read the **Log** tab. The add-on validates its options and logs an error such
as `Option 'network' must be your Twingate network name...` or
`request_headers entry 1 (Authorization): 'value' is required`, then stops.
Fix the option and start the add-on again.

### Clients cannot connect after the CA changed

If the log shows:

```text
WARNING: Creating a new CA. Register the new CA certificate shown below in Twingate; Clients will not trust this Gateway until you do.
```

or you reinstalled the add-on, Twingate still has the old CA and Twingate
Clients reject the Gateway's certificate. The Gateway log then shows
`failed to perform TLS handshake` errors, and the Web UI counts them under
**Rejected before a request**. Copy the new certificate from the Web UI (or
from the log) into `ca.pem` and register it:

- Terraform: replace `ca.pem` and run `terraform apply`. The provider replaces
  the CA when the certificate changes and points the Gateway at the new one.
- API: create a new CA with `x509CertificateAuthorityCreate` as in step 3,
  then assign it to the Gateway:

  ```bash
  QUERY='mutation($id: ID!, $x509CAId: ID) {
    gatewayUpdate(id: $id, x509CAId: $x509CAId) {
      ok
      error
      entity { id }
    }
  }'

  jq -n --arg query "$QUERY" --arg id "$GATEWAY_ID" --arg x509CAId "$X509_CA_ID" \
    '{query: $query, variables: {id: $id, x509CAId: $x509CAId}}' \
    | twingate_graphql
  ```

### Connecting by IP address fails with a TLS error

A client that dials the Resource by IP address sends no host name, and the
Gateway has no certificate for it unless the address is listed in
`certificate_ip_addresses`. Use the alias, or add the address to
`certificate_ip_addresses` and restart the add-on.

### Requests time out

The Connector cannot reach the Gateway. Check that:

- The add-on is running.
- The Gateway address in Twingate is `<home-assistant-ip>:<host port>` and
  matches the host port in the add-on's **Network** section.
- The Gateway and the Resource are in the Remote Network of the Connector
  add-on, and the Connector is online.

### `502 Bad Gateway`

The Gateway cannot reach Home Assistant. The add-on log shows a
`proxy error`, for example with `connection refused`. Check that the
Resource address is the Home Assistant host's LAN IP and that the upstream
port is the port Home Assistant answers on: `8123` on most installations, or
`80`, the Home Assistant OS default from 2026.8. If Home Assistant serves
HTTPS itself, see **Upstream TLS** in step 3.

### `401 Unauthorized` from Home Assistant

Home Assistant rejected the token. Check that:

- The header name is `Authorization` and the value is `Bearer `, a space and
  the full token.
- The token still exists under **Long-lived access tokens** in the user's
  profile.
- You restarted the add-on after changing the option.
- The Resource has no per-Resource header rewrite for `Authorization` in
  Twingate.

### MCP client gets `403 Forbidden` or `401 Unauthorized`

- `403`: the token's user is not an administrator, and the endpoint requires
  one. That is the default for `/api/mcp`, and always the case when it
  exposes the **Home Assistant** set of AI tools. Use an administrator's
  token, change the main URL settings as in step 7, or use `/api/mcp/assist`.
- `401`: the token is wrong; see the previous section.
- `404`: the Model Context Protocol integration is not enabled.

### The add-on stops with "Twingate network ... not found"

If the log shows:

```text
FATAL: Twingate network '<name>' not found: https://<name>.twingate.com/api/v1/jwk/ec answered 404 Not Found. ...
```

the `network` option is wrong. Set it to the name from your Admin Console
address and start the add-on again.

If instead the log shows `WARNING: Could not reach ... to check the network
name. Starting anyway.`, Twingate was not reachable at startup, for example
while the host was still connecting to the network. The add-on starts anyway.
If the Gateway later logs `No redirect received` with `"status_code": 404`
for `https://<network>.twingate.com/api/v1/jwk/ec`, the network name is wrong.

### Errors in the log when the add-on stops or restarts

When the add-on stops or restarts, Gateway 2.1.0 may log
`HTTP proxy stopped with error` with `use of closed network connection`,
followed by `Error: use of closed network connection` and the Gateway's usage
text, right after `Graceful shutdown complete`. This is expected and
harmless.

### Long-running connections drop

The Gateway closes each connection when its Twingate access token expires.
WebSocket connections and other long-lived streams are therefore dropped
periodically. Clients must reconnect.

## Support

- Problems with this add-on: open an issue at
  [github.com/Twingate-Community/home-assistant-add-on](https://github.com/Twingate-Community/home-assistant-add-on/issues).
- The Twingate Gateway itself: [github.com/Twingate/gateway](https://github.com/Twingate/gateway)
  and its [wiki](https://github.com/Twingate/gateway/wiki).
