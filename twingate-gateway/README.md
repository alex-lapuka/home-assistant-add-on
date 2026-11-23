# Home Assistant Add-on: Twingate Gateway

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]

This add-on installs the Twingate Gateway, allowing scripts and AI agents to
access the Home Assistant API through Twingate without a Home Assistant
credential.

It runs the [Twingate Gateway](https://github.com/Twingate/gateway) in Web App
mode, together with a proxy that reaches Home Assistant through the
Supervisor, so no long-lived token is needed. The proxy identifies each caller
by its Twingate token and logs it. Three toggles in the add-on options set
what every caller may do: read (REST and WebSocket), use the Model Context
Protocol endpoint `/api/mcp`, or make changes. Who may use the API at all is
decided in Twingate, by granting and revoking access to the Resource per
user, group or service account. It works together with the Twingate
Connector add-on from this repository.

This add-on is experimental. For setup, see the [documentation](DOCS.md) (the
**Documentation** tab in Home Assistant).

If you need support, open an issue on
[GitHub](https://github.com/Twingate-Community/home-assistant-add-on/issues).

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
