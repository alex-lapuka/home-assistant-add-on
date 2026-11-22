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
