# MAESTRO SDK & CLI (BP11)

The SDK is the **library surface**; the CLI is the **process surface**.
Both drive the same live control plane (``/api/*``) the dashboards use, with
the same zero-trust boundary (signed bearer token + role + per-principal
rate limit + per-tenant structural isolation).

## Install

```bash
pip install -e ".[dev]"   # from the repo root (editable)
# The SDK lives at maestro.sdk; the CLI at `maestro`
```

## Quickstart (sync)

```python
from maestro.sdk import MaestroClient, AgentType, AlertIn

client = MaestroClient(
    base_url="http://127.0.0.1:8000",     # or https://api.maestro.example.com
    api_key="your-bearer-token",          # MAESTRO_API_KEY env also works
)

# Fleet
agent = client.agents.create(agent_type=AgentType.CODING, tenant="acme")
print(agent.agent_id, agent.intent_vocabulary)

# Drive the live loop
result = client.alerts.submit(AlertIn(cls="dos", severity=0.95, detail="flood from 198.51.100.7"))
print(result.decision, result.reason, result.decision_card["state"])

# Observability (ledger-derived, not self-reported)
print(client.ledger.verify())          # {intact, events, head_hash}
print(client.ledger.metrics())         # {authorization_rate, unsafe_action_rate …}

# Policy
print(client.policies.validate("version: 1\nallow_list: [noop]\n"))

# Memory (quarantine-aware)
print(client.memory.inspect(tenant="acme", include_untrusted=True, limit=10))

client.close()
```

## Quickstart (async)

```python
import asyncio
from maestro.sdk import MaestroClient, AgentType

async def main():
    async with MaestroClient(base_url="http://127.0.0.1:8000", api_key="...") as client:
        agent = await client.agents.acreate(agent_type=AgentType.RESEARCH, tenant="acme")
        # … same sub-clients with `a*` prefix

asyncio.run(main())
```

## Auth

```
Bearer <token>   # value of MAESTRO_API_KEY / --api-key / ~/.maestro/credentials
```

* Every ``/api`` route requires a bearer token whose ``role`` (``viewer < operator < admin``)
  meets the route's minimum, and whose ``tenant`` claim scopes the request to its own
  partition (cross-tenant access is 403, except ADMIN tenant-admin routes).
* ``MAESTRO_SIGNING_KEY`` is the HMAC key that signs both capability tokens and the
  audit ledger. Unset → an ephemeral per-process key (fine offline; capabilities are
  process-scoped).

## CLI

```bash
maestro --help
maestro agent create --type coding --output json
maestro agent list --output table
maestro agent logs <agent-id> --limit 100
maestro agent delete <agent-id>

maestro policy validate policy.yaml
maestro memory inspect --limit 50
maestro memory promote <record-id>
maestro memory quarantine <record-id>

maestro ledger verify
maestro ledger export --limit 100
maestro ledger audit

maestro tenant create <tenant-id>
maestro tenant isolate <tenant-id>
maestro tenant audit <tenant-id>
```

Common flags: ``--control-plane URL`` (or ``MAESTRO_CONTROL_PLANE`` env),
``--api-key TOKEN`` (or ``MAESTRO_API_KEY`` env / ``~/.maestro/credentials``),
``--tenant ID``, ``--output json|table|yaml``.

## Control-plane endpoints the SDK covers

| SDK call | HTTP |
|---|---|
| ``agents.create / list / get / delete / logs`` | ``POST /api/agents``, ``GET /api/agents``, ``GET /api/agents/{id}``, ``DELETE /api/agents/{id}``, ``GET /api/agents/{id}/logs`` |
| ``alerts.submit`` | ``POST /api/alert`` (also ``POST /api/agents/{id}/alert`` for a fleet agent) |
| ``perimeter.scan`` | ``POST /api/perimeter`` |
| ``critique.evaluate`` | ``POST /api/critique`` |
| ``memory.inspect / promote / quarantine`` | ``GET /api/memory``, ``POST /api/memory/promote``, ``POST /api/memory/quarantine`` |
| ``ledger.verify / export / metrics`` | ``GET /api/ledger/verify``, ``GET /api/ledger/export``, ``GET /api/metrics`` |
| ``tenants.create / list / get / isolate`` | ``POST /api/tenants``, ``GET /api/tenants``, ``GET /api/tenants/{id}``, ``POST /api/tenants/{id}/isolate`` |
| ``policies.validate`` | ``POST /api/policies/validate`` |
| ``control_plane.state / halt / resume / reset`` | ``GET /api/state``, ``POST /api/halt``, ``POST /api/resume``, ``POST /api/reset`` |

All ``/api`` routes are ``VIEWER`` at minimum; fleet/tenant mutations are
``OPERATOR``; tenant create/isolate + ``/api/reset`` are ``ADMIN``; every
route is per-principal rate-limited.

## Typed errors

```python
from maestro.sdk.exceptions import NotFound, Unauthorized, ValidationError, RateLimited

try:
    client.tenants.get("no-such-tenant")
except NotFound as exc:
    print(exc.status_code, exc.request_id)
```

* ``ValidationError`` (400/422), ``Unauthorized`` (401/403), ``NotFound`` (404),
  ``Conflict`` (409), ``RateLimited`` (429, ``exc.retry_after``), ``ServerError`` (5xx).

## Testing

```bash
pytest tests/test_sdk.py tests/test_cli_integration.py -q
```

``test_sdk.py`` contains both unit tests (model/error mapping via
``httpx.MockTransport``) and live-control-plane integration tests (ASGI
transport, ADMIN token). ``test_cli_integration.py`` drives ``maestro.cli.main``
against the same in-process app.

## Adding an SDK call

1. Add the Pydantic request/response models in ``maestro/sdk/models.py``.
2. Add the ``GET/POST`` method in ``maestro/sdk/http_client.py`` (plus ``async`` twin).
3. Expose it through a sub-client in ``maestro/sdk/client.py``.
4. Add a CLI command that constructs the model and prints via ``_print_output``.
5. Cover it in ``tests/test_sdk.py`` (and ``test_cli_integration.py`` if CLI-visible).

## Seams (production)

* OIDC/SSO login + external RBAC/ABAC (today: HMAC bearer).
* Shared rate-limit store (Redis) so 429 holds across replicas.
* Postgres RLS as the single-DB variant of the per-tenant partition.
