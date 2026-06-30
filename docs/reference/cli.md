# CLI

All binaries support `help` and `version`:

```sh
bao-kms-unseal version
bao-unseald version
bao-unsealctl version
bao-unseal-agent version
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

bao-unsealctl k8s publish-node -addr 127.0.0.1:8443 -plaintext \
  -cluster-id prod-eu1 -node-name kind-worker
bao-unsealctl k8s check -addr 127.0.0.1:8443 -plaintext \
  -cluster-id prod-eu1 -node-name kind-worker -token-file token.jwt

bao-unsealctl tpm provision -state-path /var/lib/openbao-attested-unseal \
  -package recovery.json -shares-file shares.json
bao-unsealctl tpm status -state-path /var/lib/openbao-attested-unseal
```

Use `--format json` on lifecycle commands for automation.

`bao-unseal-agent` is the node-local evidence publisher. The first beta command
publishes one synthetic `fake-local` evidence record and exits:

```sh
bao-unseal-agent publish-once -addr 127.0.0.1:8443 -plaintext \
  -cluster-id prod-eu1 -node-name kind-worker
```

`k8s publish-node` is a beta lab helper. It publishes synthetic `fake-local`
node evidence to a broker admin API so kind and local tests can exercise node
evidence policy before a production node attestation agent exists. Use TLS by
default; `-plaintext` is only for local test brokers.

`k8s check` verifies broker admin reachability and node evidence freshness. With
`-token-file`, it also asks the broker to evaluate Kubernetes workload evidence
for diagnostics without invoking wrap or unwrap.
