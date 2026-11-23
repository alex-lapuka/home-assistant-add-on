# CHANGELOG

## 1.0.0

- Initial release

## 1.1.0

- Clean up and add log level support

## 1.2.0

- Add a read-only status page (Open Web UI): the Connector's state, version, configuration, traffic, recent warnings and errors and, optionally, recent connections. IP addresses and email addresses in the warnings and errors are masked on the page; the add-on log is unchanged
- The Connector's output now passes through `s6-log`, which copies every line unchanged to the add-on log and keeps a small copy in memory for the status page. The status page cannot slow down or stop the Connector. `s6-log` uses at most 16 MiB of memory: if lines waiting for a full `/dev/shm` reach this limit, it stops keeping the copy until the add-on restarts, and the lines it had just read (about 8 KB) are lost
- Add the `connection_logs` option (off by default) for the Connector's connection logs, which contain user email addresses and locations
- Enable the Connector's Prometheus metrics on port 9999 inside the add-on container (not published on the host)
- Fix the `info` log level, which set Twingate level 3 (errors only) instead of level 5; add the `warn` and `error` log levels. If you use `info` (the default), the add-on log now has more lines (warnings and information); choose `error` to log errors only, as before
- Fix the hostname label, which never reached the Connector
- The add-on is now built on your device from this repository instead of being downloaded as a ready-made image: installing and updating take longer and need internet access, and backups of the add-on include the image, so they are larger
