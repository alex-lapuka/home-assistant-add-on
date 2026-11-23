# Generated folder

This folder, the Twingate Connector (Exit) add-on, is a copy of
[`twingate-connector`](../twingate-connector), made by
[`scripts/sync-connector-exit.sh`](../scripts/sync-connector-exit.sh). Do not
edit it by hand. Change `twingate-connector/` instead (or the script, for
the differences between the two add-ons), then run

    scripts/sync-connector-exit.sh

and commit both folders. The Lint workflow runs
`scripts/sync-connector-exit.sh --check`, which fails when this folder is not
what the script writes. The script lists the differences.
