# Home Assistant Add-on: Twingate Gateway

This add-on lets scripts and AI agents use the Home Assistant API through
Twingate without ever holding a Home Assistant credential.

It runs the [Twingate Gateway](https://github.com/Twingate/gateway) in Web App
mode, and next to it a small proxy for the Home Assistant API. Who may use the
API is decided in Twingate, per user, group or service account, and what each
caller may do is decided by its Twingate groups in this add-on's options:

- **Read**: read states, registries, history and more, over REST and the
  WebSocket API, without changing anything.
- **MCP**: use the Model Context Protocol endpoint `/api/mcp`. What an MCP
  client can do there is set in Home Assistant's MCP Server settings; with
  their defaults it can perform any action on any entity.
- **Full**: use the whole API, except routes into the Supervisor and the
  host, account and token management and backups, which are blocked for
  everyone.

The proxy reaches Home Assistant through the Supervisor with the token that
Home Assistant gives this add-on when it starts. You create no Home Assistant
token, and none is stored in the add-on options or in backups. It covers the
REST API (`/api/...`), MCP (`/api/mcp`) and the WebSocket API
(`/api/websocket`).

The earlier setup, in which the Gateway adds a long-lived access token to
every request, keeps working; see
[Alternative: a long-lived token in a request header](#alternative-a-long-lived-token-in-a-request-header).

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
5. The Gateway forwards the request to the Resource address and upstream
   port, which point at the proxy in this add-on, writes an audit log entry
   with the Twingate identity, and adds the connection's Twingate token as
   the header `X-Twingate-Gateway-Token`.
6. The proxy verifies that token itself (signature, network, expiry, and
   that it was issued for this Resource), takes the caller's Twingate
   username and groups from it, and applies the access rules.
7. An allowed request goes to Home Assistant through the Supervisor
   (`http://supervisor/core/api/...`, `ws://supervisor/core/websocket`),
   authenticated with the add-on's Supervisor token. Home Assistant runs it
   as its built-in **Supervisor** user, an administrator.
8. The proxy logs the request with the Twingate username and its decision
   in the add-on log, and shows it in the Web UI.

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
  static address). The Gateway address uses it.
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

The add-on asks for access to the Home Assistant API (`homeassistant_api`
in its configuration); the Supervisor grants it when the add-on is installed
or updated.

## Setup

### Step 1: Install and configure the add-on

1. Add this repository to Home Assistant (see the repository README) and
   install the **Twingate Gateway** add-on.
2. On the **Configuration** tab, set `network` to your Twingate network name:
   the `<network>` part of `https://<network>.twingate.com`. This is the same
   value you entered in the Connector add-on.
3. Decide who may do what, by Twingate group (see
   [Access rules](#access-rules)). For example:

   ```yaml
   read_groups: []          # empty: everyone with access to the Resource may read
   mcp_groups:
     - Home Agents
   full_groups:
     - Home Admins
   ```

   You can change this later; the add-on applies it at its next start.
4. Leave the other options at their defaults.
5. In the **Network** section, container port `8443/tcp` is published on host
   port `8443`. Keep it. If you change the host port, use that port in the
   Gateway address in step 3. Leave `8124/tcp` (the API proxy) empty.
6. Start the add-on.

### Step 2: Copy the CA certificate and the Resource address from the Web UI

On its first start the add-on creates a certificate authority (CA) and keeps
it in the add-on's data folder. The Gateway uses this CA to sign the TLS
certificates it presents to Twingate Clients. Twingate Clients trust the
Gateway only after the CA certificate is registered in Twingate.

1. On the add-on's **Info** tab, select **Open Web UI**.
2. In the **Setup** section, select **Copy** next to the CA certificate and
   paste it into a file named `ca.pem` on the machine where you will run
   Terraform or `curl`.
3. In the **Home Assistant API proxy** section, note the address under
   **Twingate Resource**, for example
   `a0d7b954-twingate-gateway.local.hass.io`. This is the add-on's own name
   on Home Assistant's internal network; the Gateway reaches the proxy there,
   on port `8124`.

The **Setup** section also shows the certificate's subject, SHA-256
fingerprint and expiry date, and the Gateway address you need in step 3. This
is the public certificate only; the CA private key never leaves the add-on.
If **Copy** does not work in your browser, select the certificate text and
copy it.

The add-on also prints the CA certificate and the Resource address on every
start, so you can copy them from the **Log** tab instead. It looks like this:

```text
[12:00:00] INFO: The Gateway signs its TLS certificates with this CA. Twingate Clients trust the Gateway only if this CA certificate is registered in Twingate as the X.509 certificate authority of the Gateway.
[12:00:00] INFO: CA subject: CN=Twingate Gateway add-on CA 1a2b3c4d
[12:00:00] INFO: CA expires: Nov 20 12:00:00 2036 GMT
[12:00:00] INFO: CA SHA-256 fingerprint: 3F:A1:...:9C
[12:00:00] INFO: CA certificate (PEM, certificate only):
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
...
[12:00:00] INFO: Home Assistant API proxy on port 8124/tcp. Point a Web App Resource at a0d7b954-twingate-gateway.local.hass.io with upstream port 8124 to use it without a Home Assistant token.
```

Copy everything from `-----BEGIN CERTIFICATE-----` to
`-----END CERTIFICATE-----`, including those two lines, into a file named
`ca.pem` on the machine where you will run Terraform or `curl`.

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
   - **Address**: the add-on's address from step 2, for example
     `a0d7b954-twingate-gateway.local.hass.io`. The Gateway runs in the same
     add-on and sends requests to this address, which is the API proxy.
   - **Upstream port**: `8124`, the proxy's port.
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
| `<proxy-address>` | The Resource address from step 2, for example `a0d7b954-twingate-gateway.local.hass.io`. |

Clients connect with plain `http://`. The traffic is still encrypted: inside
the Twingate tunnel, and inside the TLS connection between the Twingate Client
and the Gateway. Between the Gateway and the proxy it stays inside the add-on.

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
     proxy_address     = "<proxy-address>"
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
     address           = local.proxy_address
     alias             = "ha-api.int"

     downstream = {
       port = 80
     }

     upstream = {
       port = 8124
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
   export PROXY_ADDRESS="<proxy-address>"

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
     --arg address "$PROXY_ADDRESS" \
     --arg gatewayId "$GATEWAY_ID" \
     --arg remoteNetworkId "$REMOTE_NETWORK_ID" \
     '{query: $query, variables: {
        name: "Home Assistant API",
        address: $address,
        alias: "ha-api.int",
        gatewayId: $gatewayId,
        remoteNetworkId: $remoteNetworkId,
        downstream: {port: 80},
        upstream: {port: 8124}
      }}' \
     | twingate_graphql | tee resource.json
   ```

Keep the printed `GATEWAY_ID`; you need it if you ever replace the CA.

After either option, the CA is listed in the Admin Console under
**Settings** > **Certificate Authorities**.

**Upstream TLS and downstream TLS:** keep both at their defaults (none). The
proxy speaks plain HTTP inside the add-on and accepts only tokens for
Resources with upstream TLS mode none. The Terraform provider also offers
`downstream.tls_mode = "TLS13"` (provider 5.2.0 or later), where clients
connect with `https://`; every client device must then trust the add-on's CA.
This guide does not cover that setup.

**Using the host's IP address instead:** if you prefer the Resource address
to be the Home Assistant host's LAN IP address, as in the request header
setup, publish the proxy: in the add-on's **Network** section, set a host
port for `8124/tcp` (for example `8124`), restart the add-on, and use that
host port as the Resource's upstream port. The Gateway then reaches the proxy
through the host. This works too, but it opens the proxy's port on your LAN
(it still answers only requests with a valid Twingate token for this
Resource; see [Network exposure](#network-exposure)). The add-on's host name
is recommended.

### Step 4: Grant access in Twingate

1. In the Admin Console, open the **Home Assistant API** Resource and give
   access only to the groups that should use the Home Assistant API.
2. Make sure the groups named in `read_groups`, `mcp_groups` and
   `full_groups` exist in Twingate with exactly those names (letter case
   counts).
3. For unattended agents, use a service account: under **Team** >
   **Services**, create a service account, add the **Home Assistant API**
   Resource to it and generate a Service Key. Run the Twingate Client in
   headless mode with that key on the agent's machine
   ([Linux](https://www.twingate.com/docs/linux-headless),
   [Windows](https://www.twingate.com/docs/windows-headless)). See
   [Services](https://www.twingate.com/docs/services). The proxy matches a
   service account by the groups in its Twingate token, like a user.
4. For people, install the [Twingate Client](https://www.twingate.com/download)
   on the machine that runs the script or agent and sign in.

### Step 5: Test

On a machine with a signed-in Twingate Client that has access to the
Resource, run:

```bash
curl http://ha-api.int/api/
```

Do not pass an `Authorization` header. The expected response, for a caller
with the Read or Full grant, is:

```json
{"message": "API running."}
```

Any other Home Assistant REST endpoint works the same way, for example
`curl http://ha-api.int/api/states`. Each request appears under
**Recent proxied requests** in the Web UI and in the add-on log, for
example:

```text
Proxy: alice@example.com [read] GET /api/states -> 200 in 14 ms
```

A request your grants do not allow is answered with `403 Forbidden`.

### Step 6: Use the WebSocket API (optional)

Home Assistant's WebSocket API at `ws://ha-api.int/api/websocket` works
through the proxy, with the Read or Full grant. Clients go through the normal
authentication exchange, with any non-empty text as the access token: the
proxy identified the caller already, by its Twingate token.

1. The proxy sends `{"type": "auth_required", "ha_version": "..."}`.
2. The client sends `{"type": "auth", "access_token": "twingate"}` (any
   non-empty placeholder).
3. The proxy answers `{"type": "auth_ok", "ha_version": "..."}`, or
   `auth_invalid` for an empty or malformed message, as Home Assistant does.

After that the client sends commands as usual. A command the caller's grants
do not allow gets an error result for its `id`, in Home Assistant's form
(`"success": false`, `"code": "unauthorized"`), and the connection stays
open. Client libraries that ask for a long-lived token accept the
placeholder. The connection closes when the caller's Twingate token expires;
reconnect then.

### Step 7: Connect an MCP client (optional)

1. Enable the Model Context Protocol integration (`mcp_server`) in Home
   Assistant. In current releases, go to **Settings** > **System** > **AI**
   and select **Enable** on the **Model Context Protocol** card if it is
   shown.
2. Choose what the endpoint exposes. The proxy passes the main URL
   `/api/mcp` to callers with the MCP grant; **what it offers is set in Home
   Assistant, not by the proxy.** By default it exposes all sets of AI tools,
   including the **Home Assistant** set, which can read all entities, logs
   and history and has a tool (`homeassistant__call_action`) that performs
   any action on any entity, not only on the entities exposed to Assist. To
   limit it, next to **Main URL**, select **Configure**, turn off
   **Expose all AI tools** and select only **Device control**. You can also
   turn on **Read-only**. **Device control** only reaches the entities
   exposed to voice assistants; choose them under **Settings** >
   **Voice assistants**, on the **Expose** tab.
   **Require an administrator account** can stay on: the proxy acts as Home
   Assistant's Supervisor user, an administrator.
3. Give the agent's Twingate group the MCP grant (`mcp_groups`).
4. Add the server to your MCP client with the alias URL and no
   authentication. For example, with Claude Code:

   ```bash
   claude mcp add --transport http homeassistant http://ha-api.int/api/mcp
   ```

   No header and no OAuth sign-in are needed. The sign-in steps in Home
   Assistant's MCP documentation do not apply here.

Other MCP clients that support the Streamable HTTP transport work the same
way. The individual URLs `/api/mcp/<id>`, such as `/api/mcp/assist`, need
the Full grant: they would let MCP callers bypass the main URL's settings.
Whatever Home Assistant exposes, the proxy refuses for every caller calls
to the Supervisor integration's MCP tools (`hassio__...`, which read the
logs of the host and of every add-on through the Supervisor) and calls of
`call_action` tools for actions of the `hassio` and `backup` domains (see
[MCP](#mcp)).

## Access rules

Three options give Twingate groups grants for the proxy:

| Grant | Option | Allows | When the option is empty |
| --- | --- | --- | --- |
| Read | `read_groups` | Reads over REST and WebSocket, no actions, no templates | Everyone with access to the Resource has it |
| MCP | `mcp_groups` | `/api/mcp`, every method; what it can do is set in Home Assistant's MCP Server settings (by default: any action on any entity) | Nobody has it |
| Full | `full_groups` | Everything that is not always blocked; includes Read and MCP | Nobody has it |

- A caller holds the grants of all its Twingate groups together. Read and
  MCP are independent: MCP does not include Read, and Read does not include
  MCP.
- **Read is open by default.** With `read_groups` empty, anyone Twingate lets
  through can read all states. Once `read_groups` names at least one group,
  a caller in none of the three lists gets `403 Forbidden` for everything.
- Group names are matched exactly, including letter case, against the groups
  in the caller's Twingate token.
- The add-on logs the effective rules at every start, for example
  `Proxy access rule: Read: everyone with access to the Resource`, and the
  Web UI shows them.
- Every caller acts as the same Home Assistant user, the built-in
  **Supervisor** user, which is an administrator. Home Assistant's own
  permissions therefore do not apply per person, and Home Assistant's logs
  and history show the Supervisor user. The add-on log and the Web UI record
  who made each request.

### Read

Read is an allow-list: everything not listed is denied, including commands
that a later Home Assistant release adds.

REST (`HEAD` is allowed wherever `GET` is):

| Request | What it returns |
| --- | --- |
| `GET /api/` | API status |
| `GET /api/config`, `GET /api/core/state`, `GET /api/components` | Configuration, run state, loaded integrations |
| `GET /api/states`, `GET /api/states/<entity_id>` | States |
| `GET /api/services`, `GET /api/events` | Available actions, event listener counts |
| `GET /api/history/period[/<time>]`, `GET /api/logbook[/<time>]` | History, logbook |
| `GET /api/calendars`, `GET /api/calendars/<entity_id>` | Calendars and their events |
| `GET /api/config/config_entries/entry` | Integration entries (no credentials) |

WebSocket commands: `ping`, `supported_features`, `unsubscribe_events`,
`get_states`, `get_config`, `get_services`, `subscribe_entities`,
`subscribe_events` (only for the event types Home Assistant lets
non-administrators subscribe to, such as `state_changed` and the registry
updates; not `call_service` or all events, which can carry codes and
passwords), `entity/source`, `manifest/list`, `manifest/get`,
`extract_from_target`, `get_services_for_target`, `auth/current_user`
(the connection's own user, which client libraries such as Node-RED's ask
for right after connecting), `config/entity_registry/list`, `config/entity_registry/list_for_display`,
`config/entity_registry/get`, `config/entity_registry/get_entries`,
`config/device_registry/list`, `config/area_registry/list`,
`config/floor_registry/list`, `config/label_registry/list`,
`config/category_registry/list`, `config_entries/get`,
`history/history_during_period`, `history/stream`, `logbook/get_events`,
`logbook/event_stream`, `recorder/statistics_during_period`,
`recorder/statistic_during_period`, `recorder/list_statistic_ids`,
`recorder/get_statistics_metadata`, `energy/get_prefs`, `energy/info`,
`search/related`, `todo/item/list`, `todo/item/subscribe`,
`calendar/event/subscribe`, `weather/subscribe_forecast`,
`persistent_notification/get`, `persistent_notification/subscribe`,
`repairs/list_issues`, `lovelace/config`, `lovelace/dashboards/list` and
`lovelace/info`.

Deliberately not in Read, although they change nothing: the event stream
`/api/stream` and subscriptions to all events (they carry the data of every
action, including codes), logs and diagnostics (`/api/error_log`,
`system_log/list`, traces), camera and image proxies and anything that
returns URLs that work like credentials (`camera/stream`,
`media_source/resolve_media`, `auth/sign_path`), and the configuration of
automations and scripts (it can hold codes and webhook IDs, and anyone who
knows a webhook ID can trigger it). Webhooks (`/api/webhook/...`) need Full,
because calling one runs automations. Templates (`POST /api/template`,
`render_template`) need Full too: a template cannot act, but an expensive
one can keep Home Assistant busy.

Read sees every state with all its attributes. Some attributes work like
credentials outside the proxy: for example, the `access_token` of a camera
entity lets anyone who reaches Home Assistant directly fetch that camera's
images.

### MCP

The MCP grant allows the path `/api/mcp` with every method the Supervisor
passes on (`GET`, `POST`, `DELETE`). **What an MCP client can do is what
Home Assistant's MCP Server settings expose** (see step 7). With their
defaults that includes `homeassistant__call_action`, which performs any
action on any entity, so the MCP grant is then close to Full for actions; it
is limited to the entities exposed to Assist only if you configure the MCP
Server integration that way.

The proxy reads every request to `/api/mcp` and `/api/mcp/<id>` before
passing it on. It accepts only `Content-Type: application/json` (with no
charset, or `charset=utf-8`) and a body of UTF-8 JSON, and answers anything
else with `400 Bad Request`. It refuses, for every caller, calls to the
Supervisor integration's tools (`hassio__...`), and calls of any
`call_action` tool whose action is in the `hassio` or `backup` domain or is
not given as plain text `domain.action`; the client gets a JSON-RPC error.
It does not look into other tools.

### Full

Full allows every request that is not always blocked. The Supervisor passes
on `GET`, `HEAD`, `POST` and `DELETE` only; other methods get
`405 Method Not Allowed`.

### Always blocked

Blocked for every caller, Full included, because they lead from Home
Assistant into the Supervisor or the host, manage accounts and credentials,
or restore the system:

- REST: `/api/hassio...` (Home Assistant's proxies into the Supervisor,
  including its add-on ingress proxy and Supervisor login endpoints),
  `/api/backup/...` (downloading and uploading backups),
  `/api/onboarding...` (creating the owner account and restoring backups
  during onboarding), `/api/repairs/issues/fix...` (repair flows; those of
  the Supervisor reboot the host or repair the system), and actions of the
  `hassio` and `backup` domains (`/api/services/hassio/...`,
  `/api/services/backup/...`).
- WebSocket: every command type under `supervisor/` (including
  `supervisor/api`, which reaches the whole Supervisor API), `hassio/`,
  `auth` (long-lived access tokens, signed paths, refresh tokens, MFA;
  only `auth/current_user`, which reads the connection's own user, is
  allowed),
  `config/auth/` (users), `config/auth_provider/` (passwords and usernames),
  `backup/` (creating, restoring and configuring backups) and
  `debug_console/` (runs Python inside Home Assistant); `call_service` for
  the `hassio` and `backup` domains; and `execute_script` when any of its
  steps calls such an action, or names its action with a template.
- MCP: calls to tools of the Supervisor integration (`hassio__...`), and
  `call_action` calls for actions of the `hassio` and `backup` domains.

Domains and paths are compared without regard to letter case, after
decoding. Paths that could mean something else after another decoding
(encoded slashes, dots, percent signs, question marks or hashes, empty
segments) are refused with `400 Bad Request`.

**Full is not a security boundary.** It is a block-list on an administrator
API, and there are indirect routes to the blocked actions: an automation or
script that calls them, the update entities and switches of add-ons that
Home Assistant's Supervisor integration provides, `shell_command` actions,
and more. Give Full only to people and agents you would trust with an
administrator account.

## Alternative: a long-lived token in a request header

Before version 0.3.0, the Gateway added a Home Assistant long-lived access
token to every request it forwarded to Home Assistant on port 8123. This
still works unchanged; nothing needs to change in an existing setup. It
covers REST and MCP, not the WebSocket API, and every caller has all the
rights of the token's user. To set it up:

1. In step 3, use the Home Assistant host's LAN IP address as the
   Resource's **Address** and the port Home Assistant answers on (`8123` on
   most installations; Home Assistant OS defaults to port `80` from release
   2026.8) as its **Upstream port**.
2. Decide which Home Assistant user the API calls run as. A dedicated user
   keeps those calls apart from your own in Home Assistant and lets you
   revoke them separately. For the MCP endpoint `/api/mcp` with default
   settings, the user must be an administrator.
3. Signed in as that user, open the user profile, then the **Security** tab.
   Under **Long-lived access tokens**, create a token, for example named
   `Twingate Gateway`. Copy it; Home Assistant shows it only once.
4. On the add-on's **Configuration** tab, add the header. In YAML mode the
   option looks like this:

   ```yaml
   request_headers:
     - name: Authorization
       value: "Bearer <long-lived-token>"
   ```

   In the form, add one entry with the name `Authorization` and the value
   `Bearer <long-lived-token>`. Keep the space after `Bearer`.
5. Save and restart the add-on. The log then shows:

   ```text
   [12:00:00] INFO: Request headers injected into Web App requests: Authorization (values are not logged).
   ```

The group options do not apply to this setup; the proxy only handles
requests for a Resource that points at it. Both setups can be used side by
side on one Gateway, with two Resources.

**Upstream TLS:** this setup assumes Home Assistant answers plain HTTP on its
port. If you set an SSL certificate in Home Assistant's HTTP server settings
so that it serves HTTPS itself, the Resource needs an upstream TLS mode. The
Terraform provider has `upstream.tls_mode` from version 5.2.0: `VERIFY_CA`
for a certificate from a public CA (the host name is not checked, which
matters because the Gateway connects by IP address) or `INSECURE` for a
self-signed certificate. The public API reference does not list this field.

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
- **Home Assistant API proxy**: whether the proxy is running, whether it has
  loaded Twingate's signing keys, the Resource address and upstream port to
  use, request counts, and the access rules: which groups hold Read, MCP and
  Full.
- **Recent proxied requests**: the newest 100 requests and WebSocket
  commands the proxy handled, with time, Twingate user, grant, request,
  decision (allowed, denied, blocked, no valid token, too many at once),
  status and duration.
- **Traffic**: open connections, closed proxy connections (connections from
  Twingate Clients; health checks and rejected connections are not
  included), successful and failed authentications, connections rejected
  before a request (any connection that never completed TLS and a request,
  including port probes and TLS handshakes that fail because the CA is not
  registered in Twingate), HTTP responses by status class, latency, and
  requests to the upstream, from the Gateway's metrics. The counters start
  at zero when the add-on starts.
- **Recent requests**: the newest 100 requests through the Gateway, from its
  audit log, with time, Twingate user, method, path, status and duration.

**Signing keys** is derived from what the add-on can observe: successful
client authentications (the Gateway accepts a Twingate token only after
verifying it with the signing keys), a check of the signing-key URL
`https://<network>.twingate.com/api/v1/jwk/ec` that the Web UI makes shortly
after the add-on starts and then every 15 minutes, or every 2 minutes while
the check fails, and the network check at startup.

What the Web UI never shows: request header values, Twingate tokens, the CA
private key, the Supervisor token, or the headers recorded in the audit log.
Paths are shown without their query string (marked `?…`), because query
strings can carry secrets. For the same reason the webhook ID in
`/api/webhook/<id>` paths is masked (`/api/webhook/***`): anyone who knows it
can trigger the webhook. The Web UI keeps the recent requests in memory only.

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

The proxy sends its state and the summaries of its newest requests to the
Web UI itself, every 5 seconds and after each request, without ever waiting
for it. When the proxy has not reported for 15 seconds, the Web UI says so
under **Home Assistant API proxy**.

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
`audit.log`, the copy of the audit log, the proxy's configuration or memory,
or the private key of the CA the add-on creates. With your own CA, the
permissions of your key file decide; see
[`custom_ca_keyfile`](#options-custom_ca_certfile-and-custom_ca_keyfile).
The relay runs as a second unprivileged user, `audit-relay`, which can read
the copy of the audit log but none of the other files named above, `s6-log`
as a third, `audit-log`, which writes the copy, and the API proxy as a
fourth, `api-proxy`, the only process besides root that has the Supervisor
token. None of these users can read another's files or memory, or stop or
signal another's processes or the Gateway. With `audit_log: file`, the relay
runs as root instead, because it needs root to read `audit.log`.

## Configuration

Example configuration:

```yaml
network: <network>
log_level: info
read_groups: []
mcp_groups:
  - Home Agents
full_groups:
  - Home Admins
request_headers: []
certificate_ip_addresses: []
audit_log: addon_log
```

The add-on checks all options when it starts. If an option is invalid, it
logs an error that names the option (never a header value) and stops.

### Option: `network` (required)

Your Twingate network name: the `<network>` part of
`https://<network>.twingate.com`, 1 to 63 lowercase letters and digits. A
pasted address such as `https://<network>.twingate.com/` is accepted. The
Gateway uses it to fetch Twingate's public signing keys, and so does the API
proxy. At startup the add-on checks that the network exists and stops if
Twingate reports that it does not; if Twingate cannot be reached, it logs a
warning and starts anyway.

### Option: `log_level`

Level of the Gateway's system log: `debug`, `info` (default), `warn` or
`error`. It does not affect the audit log, the API proxy's request log or the
add-on's own startup messages.

### Options: `read_groups`, `mcp_groups` and `full_groups`

Lists of Twingate group names that get the Read, MCP and Full grants of the
API proxy; see [Access rules](#access-rules). Names are matched exactly,
including letter case; spaces around a name are removed, and each name
counts once. A name may not be empty or contain line breaks.

Default: all three empty, which means everyone with access to the Resource
has Read, and nobody has MCP or Full.

### Option: `request_headers`

HTTP headers that the Gateway adds to every request it forwards, for the
[setup with a long-lived token](#alternative-a-long-lived-token-in-a-request-header).
Not needed with the API proxy. Each entry has a `name` and a `value`. The
value field is masked in the user interface.

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
  may appear once; names are case-insensitive. `X-Twingate-Gateway-Token` is
  reserved: the add-on sets it itself.
- The add-on logs header names at startup but never their values. The
  Gateway's audit log does not record injected headers.

Besides these headers, the add-on always makes the Gateway add
`X-Twingate-Gateway-Token: {{jwt}}`, the client's Twingate token, so that
the API proxy can identify the caller. It is added to requests for every Web
App Resource on this Gateway, including a Resource that points at Home
Assistant on port 8123 in the request header setup; Home Assistant ignores
it.

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
(see [Web UI](#web-ui)). The API proxy's request log always goes to the
add-on log.

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

### Network port: `8124/tcp`

The API proxy. Leave it empty (the default) when the Resource uses the
add-on's address from step 2: the Gateway reaches the proxy inside the
add-on. Set a host port only for a Resource that uses the Home Assistant
host's LAN IP address, and use that host port as the Resource's upstream
port.

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

### The add-on acts as a Home Assistant administrator

The proxy uses the Supervisor token that Home Assistant gives the add-on, and
Home Assistant runs every proxied request as its Supervisor user, an
administrator. The add-on could act as an administrator with the request
header setup too, through the token in its options; the difference is that
the Supervisor token is issued by Home Assistant to the add-on at every start
and is not stored in the options or in backups. Inside the add-on, only the
proxy's own user (`api-proxy`) and root have it; it is never logged and never
shown in the Web UI.

The access rules are applied by the proxy, so a mistake in them is an access
control mistake. Read and MCP are allow-lists; Full is a block-list and not
a security boundary (see [Always blocked](#always-blocked)).

### How the proxy knows the caller

The proxy does not trust a header just because it is there: anything that
can reach its port could send one. Instead it verifies the Twingate token
that the Gateway passes on in `X-Twingate-Gateway-Token`, as the Gateway
does: an ES256 signature by one of the network's signing keys (from
`https://<network>.twingate.com/api/v1/jwk/ec`, read again every hour and
when a token names a key it does not know, at most once a minute), the
issuer, the network as audience, the expiry, and the token type and version.
The username and groups come only from the verified token. A request without
a valid token gets `401 Unauthorized` and nothing else; the add-on log names
the reason, at most once a minute per address.

The token must also be for this proxy: a Web App Resource with upstream TLS
mode none and either the add-on's address (its host name, with or without
`.local.hass.io`) with upstream port `8124`, or, only while `8124/tcp` is
published on the host, an IPv4 address with the published host port. The
proxy checks the Resource's address and port, not its identity; see the
second limit below.

Limits of this check:

- **The proxy cannot check the token's client-key binding.** The Gateway
  accepts a token only together with proof that the client holds the key the
  token was issued for, tied to the TLS connection; the proxy sees only the
  token. Someone who holds a valid token for this Resource, in practice the
  authorised client itself, can present it to the proxy's port directly
  until it expires, bypassing the Gateway's audit log. The proxy logs every request itself, with the Twingate username, so
  such requests still appear in the add-on log. With the recommended
  Resource address, the proxy's port is not published, and only Home
  Assistant and other add-ons on Home Assistant's internal network can reach
  it.
- **Tokens of other Resources are accepted if their address and port
  match.** The proxy cannot tell your Resources apart by their identity.
  With the add-on's host name, a token of any Web App Resource in your
  Twingate network with that host name and upstream port `8124` is accepted,
  for example one of another Home Assistant that runs this add-on. With a
  published port, a token of any Web App Resource that points at any IPv4
  address with that upstream port is accepted, for example a device on your
  LAN that uses the same port number. Tokens of other Resources are refused.

### The Twingate token goes to every Web App Resource on this Gateway

The Gateway adds `X-Twingate-Gateway-Token` to requests for every Web App
Resource that uses this Gateway. An upstream that receives it learns the
caller's Twingate username and groups and holds a token it could present to
the proxy, which refuses it unless the token is for the proxy's Resource.
Bind only Home Assistant Resources to this Gateway, and do not define a
per-Resource header rewrite for `X-Twingate-Gateway-Token` in Twingate: it
would replace the token, and the proxy would refuse every request.

### Keep a Home Assistant token in the add-on

In the request header setup, put the token in the add-on's `request_headers`
option, not in a per-Resource header rewrite in Twingate
(`requestHeaderRewrites` in the API, `request_header_rewrites` in Terraform).
Per-Resource rewrites are carried inside the Twingate access token that is
delivered to each user's device. That token is signed but not encrypted, so
anyone who has access to the Resource can read the value, and it is also
readable through the Twingate API. Headers set in the add-on stay on the Home
Assistant host. A per-Resource rewrite for `Authorization` would also override
the add-on's header, so do not define one on this Resource. The add-on's
headers, including the token, apply to every Web App Resource on this
Gateway.

### Twingate access is the first gate

Twingate decides who reaches the Resource at all: users, groups, service
accounts, device and policy checks. Then the proxy decides what each caller
may do. In the request header setup, the token's rights apply to everyone
Twingate lets through.

- Grant the Resource only to the groups and service accounts that need it.
- Remember that an empty `read_groups` gives everyone with access to the
  Resource Read.
- To revoke one caller, remove its access in Twingate. Connections already
  open close when their Twingate access token expires.
- To revoke everyone at once, stop the add-on (or, in the request header
  setup, delete the long-lived token in Home Assistant).

### Keep browser access to Home Assistant separate

Use a dedicated alias, such as `ha-api.int`, for API and agent access, and
keep normal browser access to Home Assistant on an ordinary Twingate Resource
that does not use this Gateway. The proxy serves the API paths only (`/api/`)
and not the frontend. In the request header setup, opening the frontend
through the Gateway would make its REST calls carry the injected token
instead of the signed-in user's own, and the audit log would record the
browser's own request headers unredacted, including its session tokens.

### Limits per caller

The proxy keeps at most 16 WebSocket connections and 16 REST or MCP
requests in progress per Twingate user, and 64 of each in all. Beyond a
user's share it answers `429 Too Many Requests`, beyond the total
`503 Service Unavailable`. A request that cannot get a connection to the
Supervisor within 15 seconds gets `503` instead of waiting.

### Web pages of other sites

The Twingate Client adds the caller's identity to every connection to the
Resource from its device, also to connections that a browser on that device
opens for any website. A malicious page could therefore send requests to
`http://ha-api.int` as the device's user, or open the WebSocket API, whose
authentication accepts any placeholder through the proxy. The proxy refuses
such requests with `403 Forbidden`: browsers mark them with a
`Sec-Fetch-Site` header other than `same-origin` or `none`, or with an
`Origin` header that is not the address the request was sent to. Scripts and
agents send neither header, or, like some WebSocket libraries, the address
itself as `Origin`, which is accepted. In the request header setup the
Gateway passes such requests on to Home Assistant with the injected token;
another reason to keep browsers away from the alias.

### What the logs contain

The Gateway logs every request with the Twingate identity, the method and URL,
the request headers as sent by the client (unredacted) and the response status
and headers. Headers the Gateway injects, including the Twingate token for the
proxy, are not logged. Clients should not send credentials of their own.
Anyone who can read the add-on log, or the `audit.log` file when
`audit_log: file` is set, can read these entries. The copy of the newest
entries that the add-on keeps for the Web UI's relay with
`audit_log: addon_log` is kept in memory and is readable only by root,
`s6-log`'s user and the relay's user. The Web UI shows only a summary of
each entry, without headers or query string and with webhook IDs masked.

The proxy logs one line per request and per WebSocket command with the
Twingate username, its grants, the method and path (without the query string,
webhook IDs masked) and the outcome, and a summary when a WebSocket
connection closes. It never logs headers, tokens or message contents.

### Network exposure

- Port 8443 is reachable on your LAN. The Gateway proxies only connections
  that present a valid Twingate access token; the only request it serves
  without one is its `/healthz` health check, which returns an empty
  response.
- The proxy's port 8124 is not published by default. Home Assistant and
  other add-ons on Home Assistant's internal network can reach it, and get
  `401 Unauthorized` without a valid Twingate token for this Resource. If you
  publish it, the same holds for your whole LAN.
- The Gateway's only outbound connection is to `https://<network>.twingate.com`
  to fetch Twingate's public signing keys; the proxy fetches the same keys,
  and the Web UI checks the same address every 15 minutes, or every 2 minutes
  while the check fails. Audit logs stay on the Home Assistant host.
- Once a day the Web UI reads the public list of image tags of the Gateway
  from `https://hub.docker.com`, with nothing about your installation (see
  [Gateway updates](#gateway-updates)).
- The Web UI has no port on your LAN. It is reachable only through Home
  Assistant ingress and accepts connections only from the Supervisor's
  ingress proxy.
- The add-on does not change direct access to Home Assistant on your LAN.
- No reverse proxy or trusted proxy settings are needed in Home Assistant:
  the proxy talks to Home Assistant through the Supervisor, and the Gateway
  does not send an `X-Forwarded-For` header.

### Secrets at rest

With the API proxy, no Home Assistant token is stored anywhere. In the
request header setup, the token is stored in the add-on options. The CA
private key is in the add-on's data folder. Both are included in Home
Assistant backups of the add-on, so protect your backups.

## Troubleshooting

### The add-on stops right after starting

Read the **Log** tab. The add-on validates its options and logs an error such
as `Option 'network' must be your Twingate network name...`,
`request_headers entry 1 (Authorization): 'value' is required` or
`read_groups entry 2: is empty`, then stops. Fix the option and start the
add-on again.

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

### `401 Unauthorized` from the proxy

The proxy refused the caller's Twingate token. The add-on log says why, for
example:

```text
Proxy: refused a request from 172.30.33.5 without a valid Twingate token for this proxy: the token is for Resource address '192.168.1.10' with upstream port 8124, not this proxy. Answered 401.
```

Check that the Resource's address is the add-on's address shown in the Web
UI and its upstream port is `8124`, or, with the host's IP address, that
`8124/tcp` is published and the Resource uses that host port. Check that the
Resource's upstream TLS mode is none, and that it has no per-Resource header
rewrite for `X-Twingate-Gateway-Token`. When the log says
`signing keys not available`, the add-on cannot reach
`https://<network>.twingate.com`.

### `403 Forbidden` from the proxy

The caller's Twingate groups have no grant that allows the request. The
add-on log shows the caller's grants in brackets, for example
`Proxy: bob@example.com [mcp] GET /api/states -> 403 (denied)`. Check the
group names in `read_groups`, `mcp_groups` and `full_groups` against the
groups in Twingate, including letter case. `blocked for every caller` means
the request is [always blocked](#always-blocked), or came from a web page of
another site (see [Web pages of other sites](#web-pages-of-other-sites)).

### WebSocket clients get `auth_invalid`

Send an `auth` message with a non-empty `access_token`, for example
`{"type": "auth", "access_token": "twingate"}`, within 10 seconds of
`auth_required`. The message `Home Assistant cannot be reached through the
Supervisor` means the Supervisor refused the add-on; restart the add-on.

### `502 Bad Gateway`

The Gateway cannot reach the upstream, or the proxy cannot reach Home
Assistant through the Supervisor. The add-on log shows a `proxy error` from
the Gateway, for example with `connection refused`, or a `-> 502` line from
the proxy. With the API proxy, check that the Resource's address and upstream
port are the ones shown in the Web UI and that the proxy is running (Web UI,
**Home Assistant API proxy**). In the request header setup, check that the
Resource address is the Home Assistant host's LAN IP and that the upstream
port is the port Home Assistant answers on: `8123` on most installations, or
`80`, the Home Assistant OS default from 2026.8. If Home Assistant serves
HTTPS itself, see **Upstream TLS** in the request header setup.

### `401 Unauthorized` from Home Assistant (request header setup)

Home Assistant rejected the token. Check that:

- The header name is `Authorization` and the value is `Bearer `, a space and
  the full token.
- The token still exists under **Long-lived access tokens** in the user's
  profile.
- You restarted the add-on after changing the option.
- The Resource has no per-Resource header rewrite for `Authorization` in
  Twingate.

### MCP client gets `403 Forbidden` or `401 Unauthorized`

- With the API proxy, `403`: the caller's groups have no MCP grant (Read
  does not include MCP), or it used `/api/mcp/<id>`, which needs Full.
  `400`: the client did not send `Content-Type: application/json` in UTF-8.
- In the request header setup, `403`: the token's user is not an
  administrator, and the endpoint requires one. That is the default for
  `/api/mcp`, and always the case when it exposes the **Home Assistant** set
  of AI tools. Use an administrator's token, change the main URL settings as
  in step 7, or use `/api/mcp/assist`.
- `401`: see the sections above.
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

The Gateway closes each connection when its Twingate access token expires,
and the proxy closes WebSocket connections and streams at the same moment.
WebSocket connections and other long-lived streams are therefore dropped
periodically. Clients must reconnect.

## Support

- Problems with this add-on: open an issue at
  [github.com/Twingate-Community/home-assistant-add-on](https://github.com/Twingate-Community/home-assistant-add-on/issues).
- The Twingate Gateway itself: [github.com/Twingate/gateway](https://github.com/Twingate/gateway)
  and its [wiki](https://github.com/Twingate/gateway/wiki).
