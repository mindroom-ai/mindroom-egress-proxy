# Approved Egress

MindRoom plugin that lets an agent request human-approved temporary worker
egress to one exact external hostname.

The plugin is a client for the approved egress policy API. It is not the
network security boundary. The proxy must still enforce static allowlist rules,
dynamic grants, DNS checks, and private-address blocking on every request.

## Tool

The plugin exposes the `approved_egress` toolkit with:

```text
request_network_access(hostname, ttl_minutes, reason)
```

Before enabling the plugin for an agent, configure MindRoom tool approval to
require approval for `request_network_access`. After approval, MindRoom runs the
tool and the plugin creates a short-lived grant through the policy API.

If the requested hostname already matches the configured static allowlist, the
tool reports that no dynamic grant is needed and does not call the policy API.

## Environment

Required:

- `MINDROOM_APPROVED_EGRESS_API_URL`: base URL for the policy API
- `MINDROOM_APPROVED_EGRESS_TOKEN`: bearer token accepted by that API

Optional:

- `MINDROOM_APPROVED_EGRESS_MAX_TTL_SECONDS`: maximum requested grant lifetime;
  defaults to six hours
- `MINDROOM_APPROVED_EGRESS_ALLOWLIST_PATH`: path to the static allowlist file
- `MINDROOM_APPROVED_EGRESS_ALLOWLIST`: comma- or newline-separated inline
  allowlist; this takes precedence over the file path

The static allowlist format matches Squid `dstdomain` entries:

```text
example.com
.docs.example.com
```

Hostnames are exact fully-qualified DNS names only. Schemes, ports, wildcards,
paths, IP literals, single-label names, localhost, cluster-local names, and
metadata hostnames are rejected before the policy API request.

## Grant Subjects

The plugin uses the MindRoom runtime context to choose the grant subject:

- `user_agent` scope creates a `worker_key` grant for the exact requester-owned
  worker.
- shared or unscoped agents create an `agent` grant for the shared worker name.
- `user` scope is rejected because one user-scoped worker can serve multiple
  agents.

The proxy must also enforce this split. In particular, `agent` grants should be
honored only for shared or unscoped worker identities.
