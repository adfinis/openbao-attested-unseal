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

`bao-unseal-agent` is the node-local evidence publisher. For local tests, it
can publish one synthetic `fake-local` evidence record and exit:

```sh
bao-unseal-agent publish-once -addr 127.0.0.1:8443 -plaintext \
  -cluster-id prod-eu1 -node-name kind-worker
```

For generic TPM 2.0 evidence, select `generic-tpm2-quote` and the PCR selection
to quote. The agent obtains the nonce from the broker and submits the raw quote;
the broker config must enroll the node UID, AK public hash, TPM policy, and the
agent client-certificate fingerprint for that node:

```sh
bao-unseal-agent publish-once -addr bao-unseald.openbao.svc:8443 \
  -cluster-id prod-eu1 -node-name "$NODE_NAME" -node-uid "$NODE_UID" \
  -provider-id generic-tpm2-quote \
  -tpm-device /dev/tpmrm0 -tpm-pcr-bank sha256 -tpm-pcrs 7 \
  -platform-hint generic-pc-secureboot
```

Use `run` when the agent should keep node evidence fresh:

```sh
bao-unseal-agent run -addr 127.0.0.1:8443 -plaintext \
  -cluster-id prod-eu1 -node-name kind-worker \
  -ttl 5m -interval 1m
```

`run` publishes immediately, then repeats every `-interval`. The interval must
be shorter than the evidence `-ttl`. By default the agent keeps retrying after
publish failures; set `-max-failures` to exit after a bounded number of
consecutive failures. With `-format json`, `run` emits newline-delimited JSON
events.

`k8s publish-node` is a preview lab helper. It publishes synthetic `fake-local`
node evidence to a broker admin API so kind and local tests can exercise node
evidence policy. It uses the same challenge-bound submission flow, but does not
accept custom evidence hashes and makes no TPM or platform claim. Use TLS by
default; `-plaintext` is only for local test brokers.

`k8s check` verifies broker admin reachability and node evidence freshness. With
`-token-file`, it also asks the broker to evaluate Kubernetes workload evidence
for diagnostics without invoking wrap or unwrap.
