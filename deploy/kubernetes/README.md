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

The first production-ready manifest follow-up is to replace the development
wrapping key and fake/local node evidence assumptions with real secret
management and a node evidence publisher.
