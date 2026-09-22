# Approve -- Kubernetes demo

A self-contained demo of [Approve](https://github.com/paxanimae/approve-auth),
for a local cluster (kind, minikube, Docker Desktop Kubernetes). **Not a
production deployment** -- see `deploy/helm/approve-auth` for that. Every
secret here is a fixed, publicly-known demo value; TLS is self-signed and
regenerated on every install; Keycloak runs as a sidecar container in the
same Pod as `approve-auth` (see `templates/deployment.yaml`'s own comment
for why -- it avoids a split-DNS problem a demo chart shouldn't solve by
patching your cluster's CoreDNS).

This chart bundles Traefik itself (the official chart, as a dependency)
with its CRDs, since the production chart deliberately assumes Traefik is
already installed cluster-wide.

## Install

```bash
helm repo add traefik https://traefik.github.io/charts
git clone https://github.com/paxanimae/approve-auth.git
cd approve-auth
helm install approve-demo deploy/helm/approve-auth-demo/
```

First boot takes 1-2 minutes (Keycloak's realm import + startup gates
`approve-auth`'s own container from starting until it's ready -- this is
normal, not a stuck install). Check progress with:

```bash
kubectl get pods
```

## Access it

No assumption of a real LoadBalancer/Ingress controller -- port-forward
instead, the standard cluster-agnostic way to reach a Service locally:

```bash
kubectl port-forward svc/approve-demo-traefik 8080:web 8443:websecure
kubectl port-forward svc/approve-demo-approve-auth-demo 8090:keycloak
```

Then open **http://localhost:8080/** -- the landing page links to the
admin console (`demo-admin`/`demo-admin`, `demo-viewer`/`demo-viewer`) and
four sample protected applications, each demonstrating a different
feature.

## Uninstall

```bash
helm uninstall approve-demo
kubectl delete secret approve-demo-approve-auth-demo-app-mtls approve-demo-approve-auth-demo-mtls-ca approve-demo-approve-auth-demo-mtls-client approve-demo-approve-auth-demo-traefik-tls
```

The second command is needed because the TLS/mTLS Secrets are created by
`templates/certgen-job.yaml`'s own `kubectl apply` call, not by Helm
directly (see that template's comment) -- Helm doesn't track them as part
of the release, so `helm uninstall` doesn't remove them.

## What's verified

Lint/template/kubeconform (same as the production chart's own CI `helm`
job) prove the templates render valid Kubernetes YAML, nothing more. This
chart has additionally been installed against a real kind cluster and
exercised end to end: the full OIDC login flow (Keycloak -> role resolved
via the `groups` claim), the per-app config differences rendering through
the real ForwardAuth pipeline, and both `helm install` and
`helm upgrade` completing cleanly.
