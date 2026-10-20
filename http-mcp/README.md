# HA MCP

A small stateless Streamable HTTP MCP service for registered Home Assistant entities. This source milestone uses synthetic acceptance fixtures. Nothing here enrolls an Authentik client or HA account, deploys a service, or qualifies physical devices.

## Tools and authority

The maximum catalog is four tools:

| Tool | Arguments | Required signed scope/action |
| --- | --- | --- |
| get_entity | id | ha.read / state.read |
| list_entities | optional offset and limit | ha.read / state.read |
| set_light | id, power on/off, optional integer brightness_percent | ha.control / light.control |
| set_switch | id, power on/off | ha.control / switch.control |

The server verifies each HTTP MCP request. Every tool handler intersects that request's signed scopes, ha_entities and ha_actions with the operator registry. It also builds the advertised catalog from the same intersection. Prior discovery, a session ID, or a matching subject grants nothing. A control-only token receives no read tools or state projections.

Access JWTs must use RS256, the exact configured issuer including its trailing slash, and exactly one audience equal to resource_url. Required claims are sub, iat, exp, scope, ha_entities and ha_actions. Lifetime must be positive and at most 300 seconds; clock skew is 10 seconds. Optional nbf must precede exp. Scope is a space-separated string containing ha.read, ha.control, or both, without duplicates or extra scopes. ha_entities is a nonempty array of at most 64 distinct explicit supported IDs. ha_actions is a nonempty array of distinct state.read, light.control and/or switch.control. Missing, empty, malformed, duplicate or wildcard grants fail closed. Action and scope ceilings are independent; granting an action without its scope does not authorize it.

Synthetic claim shape:

```json
{
  "iss": "https://auth.example/application/o/ha-mcp/",
  "aud": "https://ha.mcp.ryzhkov.dev/mcp",
  "sub": "dedicated-service-identity",
  "iat": 1792430400,
  "exp": 1792430700,
  "scope": "ha.read ha.control",
  "ha_entities": ["light.qualified_lamp"],
  "ha_actions": ["state.read", "light.control"]
}
```

No tool accepts area, device, group, floor, label, wildcard, arbitrary service, scene, script, automation, Assist, URL or API selectors. There are no state database edits or arbitrary trigger/replay mechanisms.

## Configuration and HA custody

Run ha-mcp -config /etc/ha-mcp/config.json using the shape in config.example.json. Unknown fields, including nested fields and inline/environment secret selectors, are refused. There are no ambient credential, operator CLI, keyring, SOPS or login fallbacks. Configuration is read once at startup; restart to change policy or rotate the backend credential.

The registry accepts 1..64 individual IDs in light, switch, sensor and binary_sensor. Each ID consists of its domain, a dot and 1..96 lowercase ASCII letters, digits or underscores. Names are operator-approved output, bounded to 128 bytes. Each entity explicitly lists permitted actions. light.control and switch.control must match the domain and require control_qualified: true.

control_qualified is an operator assertion, not automatic device analysis. Enrollment must separately qualify the entity's group/aggregate membership, integration behavior, defaults, automations and other indirect effects. An arbitrary light or switch ID does not prove a physically single device. Default profiles and previous HA brightness can affect turn_on when brightness is omitted.

brightness is optional registry configuration for light.control only, with inclusive integer min_percent/max_percent bounds within 0..100. Without this enrollment, supplying brightness is refused. Bounds constrain the supplied parameter, not unobserved physical output or HA defaults. Supplied brightness is allowed only with power on. The server sends brightness = round(percent * 255 / 100). A value of 0 sends HA brightness 0 and can turn the light off even though the requested service is light.turn_on. Omitting brightness sends only entity_id.

The fixed backend_token_file must be an absolute path to a regular nonsymlink file, mode 0600, owned by the actual runtime UID. It contains one bounded bearer string, with an optional final newline. The file is opened with O_NOFOLLOW and ownership/mode are checked on the descriptor. Parent directories and config are operator-owned and protected from agent writes. The token never appears in tool output. The executable refuses UID 0.

Use a dedicated nonadministrator HA account. At the qualified HA source revision, the standard read-only group allows reads of all entities and cannot control them. The ordinary user group has all-entity permissions. For these setters, the account needs actual light/switch control rights, plus read rights if readers are enabled. If a separately qualified narrower HA policy is unavailable, the ordinary nonadmin account remains broad inside HA; this service's registry and signed grants enforce the agent ceiling. A read-only HA token does not support writes. Protect backend custody and network access accordingly. No account is created by this project.

## HTTP and deployment contract

The binary listens on listen over internal HTTP. resource_url must be a canonical HTTPS URL ending exactly in /mcp. issuer_url and jwks_url are pinned HTTPS URLs; issuer_url requires its slash. ha_url is one fixed HTTP or HTTPS origin without a path, credentials, query or fragment.

Route these exact paths through existing Traefik:

- /mcp, authenticated Streamable HTTP with JSON responses and no retained sessions.
- /.well-known/oauth-protected-resource/mcp, public OAuth protected-resource metadata.
- /healthz, optional liveness returning only ok without any backend/issuer request.

Preserve the exact configured public Host and Origin. Requests with another Host, another Origin when present, a query or encoded path are refused. Forwarded headers do not establish trust. Health probes must set that public Host. The SDK's localhost heuristic is disabled because this wrapper enforces the exact pinned Host even over loopback. Public TLS remains Traefik's responsibility. No browser SSO redirect is a substitute for bearer verification.

JWKS and HA clients ignore environment proxies and refuse redirects. JWT headers cannot select key URLs, embedded keys or algorithms. JWKS is bounded to 64 KiB and 16 usable RSA public keys of 2048..4096 bits, cached for one minute with a five-second refresh floor. A required refresh failure refuses authentication, including when an expired key was cached. Issuance revocation does not instantly revoke an already issued offline-verified JWT.

Request bodies, JSON MCP replies and HA bodies are bounded to 64 KiB; JWTs to 8 KiB. Oversized MCP replies produce a fixed refusal before any partial output is released; a caller must treat a lost write response as uncertain. Each HTTP POST accepts one JSON-RPC object; legacy batches are refused before dispatch. There are at most 32 concurrent MCP requests and 16 HTTP connections per outbound host. JWKS fetch timeout is 3 seconds; each HA operation is 4 seconds; each tool call is 8 seconds. Each MCP HTTP request has a 12-second context deadline. Server header/read/write/idle deadlines are 3/10/15/30 seconds. Incoming cancellation propagates to HA, including older supported MCP protocol versions. No request, token, subject, raw HA error or service payload is logged. Startup/runtime stderr uses fixed messages.

list_entities first filters configured IDs by signed grants, then counts and paginates the resulting sorted list. Limit defaults to 10, maximum 20. Offset is recomputed against the current request's grants; it is not a transferable grant. The service never calls GET /api/states. Each selected entity uses GET /api/states/{id}. A page fails uniformly if a selected entity is unavailable.

Readers return only approved ID/name/state, light brightness, sensor unit, and valid state timestamps. Raw attributes, context, relations, backend names, URLs and user IDs are discarded. Denied, unknown, missing and failed reads share entity unavailable. Writes POST only to light.turn_on/off or switch.turn_on/off with one validated entity_id and optional brightness. The raw changed-state service response is discarded. An HTTP 200 means outcome accepted, physical_state_confirmed false. A timeout, failed body read, oversized response or other backend failure means outcome uncertain. HA may continue an accepted service call after disconnect. The server never retries a write or reads state as a side effect. Reconcile explicit desired state using a separately authorized read.

## Build and checks

Session builds/tests run through Chaldea:

```sh
chaldea exec --host agent-a -- make check
chaldea exec --host agent-a --artifact bin/ha-mcp -- make build
```

The Git-independent Makefile asserts scratch HOME/TMPDIR under the job checkout's .cache/ha-impl before creating files. Every go test sets HUYANG_FRICTION=0. make check runs the official SDK HTTP initialize/list/call acceptance suite against synthetic HA and TLS JWKS, with the race detector, a static binary build, gofmt and go vet. Dependencies and GitHub action revisions are pinned. CI runs the same make target in its isolated runner. Session scratch lives at ~/.cache/ov-ha-authentik-a63e197f/ha-impl; Chaldea job scratch stays inside each job checkout.

The minimal Dockerfile requires an operator-reviewed immutable GO_IMAGE build argument, for example a supported golang image by digest. Its scratch runtime carries the CA bundle and uses UID:GID 65532:65532. Bind-mount config read-only and a protected token file with numeric owner 65532:65532 and mode 0600. A root-owned Swarm secret is insufficient. Use a read-only root filesystem, drop all capabilities, set no-new-privileges, and apply resource/log limits in the deployment role. The future deployer must verify actual nonroot UID, mount ownership, DNS/CA access, fixed HTTPS JWKS reachability and Traefik routing in the running image. Container build/runtime and these deployment properties are not proven by Go acceptance tests.

## Source evidence and limits

The design follows the full Jocasta Authentik authoring guide tooling/guides/web-mcp-authentik-authoring-2026-10-19.md, fetched from Jocasta during implementation. The verifier structure follows the maintained-library approach in the [Jocasta verifier](https://github.com/iryzhkov/jocasta/blob/694b498be231268bd88452d2eed1e6c180f5221b/internal/server/oidc.go). Policy stays local to this module.

The qualified HA research input was live version 2026.10.2 matching source 8d7fd8b68677c2585be36ec86043308f403875b8. These are inputs from the parent research, not a live-version check performed by this service. Primary sources checked for this implementation:

- [HA exact entity GET and service POST handlers](https://github.com/home-assistant/core/blob/8d7fd8b68677c2585be36ec86043308f403875b8/homeassistant/components/api/__init__.py).
- [HA system user/read-only policies](https://github.com/home-assistant/core/blob/8d7fd8b68677c2585be36ec86043308f403875b8/homeassistant/auth/permissions/system_policies.py).
- [HA light behavior](https://github.com/home-assistant/core/blob/8d7fd8b68677c2585be36ec86043308f403875b8/homeassistant/components/light/__init__.py).
- [Official Go MCP SDK v1.7.0 transport](https://github.com/modelcontextprotocol/go-sdk/blob/v1.7.0/mcp/streamable.go) and [JWT v5](https://pkg.go.dev/github.com/golang-jwt/jwt/v5).

Synthetic tests establish the service contract only. Real Authentik mappings, native private helpers, public HTTPS/TLS, nonroot container runtime, dedicated-account HA permissions, enrollment and physical effects remain unqualified. The service does not depend on unfinished Chaldea credential acquisition. The parent owns review, publication, CI qualification and any later authorized deployment.
