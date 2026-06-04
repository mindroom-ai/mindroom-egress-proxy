# MindRoom Egress Proxy

Network firewall and approval proxy for MindRoom worker environments.

MindRoom agents often need tools that can read docs, install packages, call
APIs, or inspect web pages. This service gives those workers a controlled path
to the internet without making outbound network access open-ended.

At a high level, it provides:

- a default-deny proxy for worker HTTP and HTTPS traffic
- a static allowlist for destinations that are always permitted
- temporary, human-approved grants for blocked hostnames
- DNS and private-address checks so approved hostnames cannot point back into
  cluster-local, metadata, loopback, or private networks

This repository is the enforcement layer. A MindRoom approval tool or plugin can
ask a human to approve access to a hostname, then call this proxy's policy API
to create a short-lived grant. The proxy still enforces the decision on every
connection.

## How It Works

The container runs Squid as an HTTP/CONNECT forward proxy and a small FastAPI
policy service for temporary dynamic grants. Squid allows traffic when either:

- the requested hostname matches the mounted static allowlist
- the policy API has an active grant for the worker key or agent resolved from
  the source worker pod

The proxy fails closed for malformed helper requests, unsupported ports,
internal hostnames, private or metadata address ranges, and unresolved worker
identity.

## MindRoom Approval Flow

One common setup is:

1. Worker traffic is routed through this proxy with `HTTP_PROXY` and
   `HTTPS_PROXY`.
2. NetworkPolicy or equivalent cluster policy prevents workers from bypassing
   the proxy.
3. MindRoom exposes a `request_network_access(hostname, ttl_minutes, reason)`
   tool to agents.
4. MindRoom's tool approval system asks a human to approve that tool call.
5. After approval, the tool posts a temporary grant to this proxy's policy API.
6. Squid checks each request against the static allowlist and active grants.

The approval tool improves user experience; this proxy is the network security
boundary.

## Runtime

Default ports:

- `3128`: HTTP/CONNECT proxy
- `8080`: policy API

Required environment:

- `MINDROOM_APPROVED_EGRESS_TOKEN`: bearer token for policy API calls

Common environment:

- `POD_NAMESPACE`: Kubernetes namespace for worker metadata lookup
- `MINDROOM_EGRESS_NAMESPACE`: fallback namespace when `POD_NAMESPACE` is absent
- `MINDROOM_EGRESS_ALLOWLIST_PATH`: static Squid-style domain allowlist
- `MINDROOM_EGRESS_DB_PATH`: SQLite grant database path
- `MINDROOM_APPROVED_EGRESS_MAX_TTL_SECONDS`: maximum dynamic grant lifetime
- `MINDROOM_EGRESS_SQUID_CONFIG_PATH`: Squid config path

## API

Create a dynamic grant:

```bash
curl -sS -X POST "http://localhost:8080/grants" \
  -H "authorization: Bearer $MINDROOM_APPROVED_EGRESS_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "hostname": "docs.example.com",
    "subject_type": "worker_key",
    "subject": "v1:default:user_agent:@user:server:assistant",
    "ttl_seconds": 300,
    "reason": "Need documentation"
  }'
```

List active grants:

```bash
curl -sS "http://localhost:8080/grants" \
  -H "authorization: Bearer $MINDROOM_APPROVED_EGRESS_TOKEN"
```

Health check:

```bash
curl -sS "http://localhost:8080/healthz"
```

## Development

```bash
uv sync
uv run pre-commit install
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

Build image:

```bash
docker build -t mindroom-egress-proxy:local .
```

Tag releases publish the container image to GHCR and upload Python package
artifacts to the matching GitHub release.

## Deployment Boundary

This repository contains only reusable proxy runtime code and neutral defaults.
Cluster manifests, image registry names, domain allowlists, tokens, service
names, and environment-specific routing belong in deployment repositories.
