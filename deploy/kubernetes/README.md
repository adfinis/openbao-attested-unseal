# Kubernetes Deployment Profile

Status: draft

These manifests describe the beta Kubernetes broker profile. They are intended
as a small, inspectable starting point for kind and lab deployments.

## Files

- `rbac.yaml`: namespace, service accounts, TokenReview permission for
  `bao-unseald`, and namespaced Pod lookup permission.
- `bao-unseald.yaml`: broker ConfigMap, Deployment, and Service skeleton.

## Current Scope

The RBAC manifest is exercised by the kind e2e test. The broker Deployment is a
deployment sketch and expects a locally supplied or published image containing
`bao-unseald`.

`bao-unseald.yaml` includes a deterministic development wrapping key so the
example remains syntactically and semantically valid for local labs. Replace it
before any non-lab use.

The broker example also sets `allow_plaintext_for_tests` because it does not
ship TLS material, and enables `allow_fake_node_evidence_publish` for synthetic
node evidence. This is only for kind and local smoke testing. Production
manifests must provide broker TLS and disable fake evidence publishing.

For local policy testing, a temporary fake node evidence record can be seeded
through a port-forwarded broker:

```sh
kubectl -n openbao port-forward svc/bao-unseald 18443:8443

bao-unsealctl k8s publish-node \
  -addr 127.0.0.1:18443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

The first production-ready manifest follow-up is to replace the development
wrapping key, plaintext transport, and fake/local node evidence assumptions
with real secret management, TLS, and a node evidence publisher.
