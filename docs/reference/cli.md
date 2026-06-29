# CLI

All binaries support `help` and `version`:

```sh
bao-kms-unseal version
bao-unseald version
bao-unsealctl version
```

`bao-unseald` also supports broker startup and local diagnostics:

```sh
bao-unseald serve -config broker.json
bao-unseald config validate -config broker.json
bao-unseald debug schema
```

`bao-unsealctl` supports the local lifecycle flow:

```sh
bao-unsealctl init -state broker.db
bao-unsealctl status -state broker.db

bao-unsealctl enroll request -subject-id node-a -out request.json
bao-unsealctl enroll issue -state broker.db -request request.json -grant grant.json
bao-unsealctl enroll apply -state broker.db -grant grant.json

bao-unsealctl recover begin -package recovery.json -shares-file shares.json
bao-unsealctl enroll request -subject-id recovered-broker -out target-request.json
bao-unsealctl recover enroll -state broker.db -package recovery.json \
  -shares-file shares.json -session recovery.json.session -request target-request.json
bao-unsealctl recover finish -session recovery.json.session

bao-unsealctl tpm provision -state-path /var/lib/openbao-attested-unseal \
  -package recovery.json -shares-file shares.json
bao-unsealctl tpm status -state-path /var/lib/openbao-attested-unseal
```

Use `--format json` on lifecycle commands for automation.
