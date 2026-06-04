# MindRoom Egress Proxy

Approved egress proxy for MindRoom worker environments.

The container runs Squid as an HTTP/CONNECT forward proxy and a small FastAPI
policy service for temporary dynamic grants. Squid allows traffic when either:

- the requested hostname matches the mounted static allowlist
- the policy API has an active grant for the worker key or agent resolved from
  the source worker pod

The proxy fails closed for malformed helper requests, unsupported ports,
internal hostnames, private or metadata address ranges, and unresolved worker
identity.

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
uv run ruff check .
uv run python -m unittest -v
```

Build image:

```bash
docker build -t mindroom-egress-proxy:local .
```

## Deployment Boundary

This repository contains only reusable proxy runtime code and neutral defaults.
Cluster manifests, image registry names, domain allowlists, tokens, service
names, and environment-specific routing belong in deployment repositories.
