# Maestro Model Connector System

A production-ready abstraction that unifies access to LLM providers behind a
single interface, plus a web dashboard to configure, test, log, and verify
agent behavior across backends — online (cloud APIs) and offline (local
models / deterministic stub).

- **Code:** `src/maestro/connectors/`
- **Web API + dashboard:** `src/maestro/server/connectors_api.py`, `/playground`
- **Config:** `configs/connectors.yaml`
- **Agent integration:** `src/maestro/agent/reasoning.py` (`ConnectorReasoner`)

---

## 1. Architecture

```
        ChatRequest ─────────────► ModelConnector.chat() ─────────────► ChatResponse
                                          │                              (text, model,
   messages[], params, model             │  times · normalizes errors    provider, usage,
                                          │  · estimates usage            latency_ms)
                                          ▼
     ┌───────────┬───────────┬───────────┬───────────┬────────────────┐
     │ Stub      │ OpenAI    │ Anthropic │ Ollama    │ Custom          │
     │ (offline) │ /chat/... │ /v1/msgs  │ local     │ URL + key       │
     └───────────┴───────────┴───────────┴───────────┴────────────────┘
                                          ▲
                                ConnectorRegistry (register/enable/disable/resolve)
                                          ▲
                                FallbackConnector (ordered graceful degradation)
```

### Key types (`maestro.connectors`)

| Type | Role |
|---|---|
| `ChatMessage`, `ChatRequest`, `ChatParams` | Normalized request. `ChatRequest.of(prompt, system=…, **params)` is the quick builder. |
| `ChatResponse`, `Usage` | Normalized response with `latency_ms` and token usage (`estimated=True` when a provider omits usage). |
| `ModelConnector` | Abstract base. Subclasses implement `_generate`; the base handles timing, error normalization, and usage estimation. `chat()` is the only method callers use. |
| `StubConnector` | Deterministic, offline, no key — used for tests/demos and as the default. |
| `OpenAIConnector`, `AnthropicConnector`, `OllamaConnector`, `CustomConnector` | Concrete providers over an injectable `httpx.Client`. |
| `FallbackConnector` | Tries an ordered chain; advances past retryable failures (rate limit / unavailable / disabled), raises non-retryable ones (bad request / auth) immediately. |
| `ConnectorRegistry` | Name-keyed set: `register` / `register_provider` / `enable` / `disable` / `resolve` / `set_default`. |
| `build_registry(path)` / `default_registry()` | Build a registry from YAML / a sensible offline default. |

### Error hierarchy

`ConnectorError` → `AuthenticationError` (401/403), `InvalidRequestError` (4xx),
`RateLimitError` (429, `retryable`), `ProviderUnavailableError` (5xx / network,
`retryable`). Fallback and callers branch on the class, never on message text.

### Design choices (and why)

- **One raw-`httpx` layer for every provider**, not per-provider SDKs. This is
  what makes the interface uniform, lets users register arbitrary external
  providers with just a URL + key, and — crucially — makes the whole stack
  **testable offline** by injecting `httpx.MockTransport`. No network, no keys
  in tests.
- **Sampling params are opt-in for Anthropic.** Modern Claude models (e.g.
  `claude-opus-4-8`) reject `temperature`/`top_p` with a 400, so the Anthropic
  connector omits them by default; pass `params.extra["temperature"]` to opt in
  for an older model.
- **Usage is always populated**: measured when the provider returns it, else a
  provider-neutral estimate (`~4 chars/token`) flagged `estimated=True`.

---

## 2. Quick start (library)

```python
from maestro.connectors import ChatRequest, build_registry

registry = build_registry()                 # loads configs/connectors.yaml
connector = registry.resolve()              # the default connector (offline stub)
resp = connector.chat(ChatRequest.of("Summarize MAESTRO in one line.",
                                     system="You are concise.", max_tokens=64))
print(resp.text, resp.latency_ms, resp.usage.total_tokens)
```

### Fallback (cloud → local)

```python
from maestro.connectors import FallbackConnector

primary = registry.get("openai")            # cloud
backup  = registry.get("stub")              # always-on offline safety net
chain = FallbackConnector("cloud-then-stub", [primary, backup])
resp = chain.chat(ChatRequest.of("hello"))  # uses backup if openai is down/rate-limited
```

---

## 3. Web testing interface

Start the server and open the dashboard:

```bash
uvicorn maestro.server.app:app --port 8000
# → http://127.0.0.1:8000/playground
```

The dashboard (self-contained, responsive, light/dark) lets you:

- **Manage connectors** — enable/disable, set default, health-check, delete, and
  **register an external provider** (name, provider kind, model, base URL, key,
  auth header).
- **Run prompts** against any connector with **live parameter control**
  (temperature, max tokens, top_p) between runs — no restart.
- **Compare** outputs from all enabled connectors **side by side**.
- **Fallback** — route a run through the fallback chain.
- **Log** every request/response with latency + token metrics, and tick a
  **manual verification** checkmark per result/log row.
- **Save / replay / delete test cases** (system + prompt + params + connector).

### REST API (`/api`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/connectors` | List connectors + default |
| `POST` | `/api/connectors` | Register a provider `{name, provider, model, base_url?, api_key?, auth_header?}` |
| `DELETE` | `/api/connectors/{name}` | Remove |
| `POST` | `/api/connectors/{name}/enable` \| `/disable` \| `/default` | Toggle / set default |
| `POST` | `/api/connectors/{name}/health` | Liveness probe |
| `POST` | `/api/chat` | Run `{prompt, system?, connector?, compare?[], fallback?, params, model?}` |
| `GET`/`DELETE` | `/api/logs` | List / clear request logs |
| `POST` | `/api/logs/{id}/verify` | Set verification checkmark |
| `GET`/`POST` | `/api/testcases` | List / save |
| `POST` | `/api/testcases/{id}/replay` | Replay |
| `DELETE` | `/api/testcases/{id}` | Delete |

---

## 4. Adding a new provider

### Option A — register at runtime (no code)

Any OpenAI-compatible endpoint works out of the box via the `custom` provider —
from the dashboard's **Register provider** form, or the API/YAML:

```yaml
# configs/connectors.yaml
connectors:
  - name: my-provider
    provider: custom
    model: my-model
    base_url: https://api.example.com/v1
    api_key_env: MY_PROVIDER_KEY   # read from the environment; never store keys in the file
    auth_header: authorization     # or e.g. x-api-key for non-Bearer auth
```

```python
registry.register_provider(name="my-provider", provider="custom",
                           model="my-model", base_url="https://api.example.com/v1",
                           api_key="…", auth_header="x-api-key")
```

### Option B — a new provider class (different wire format)

For a provider that is **not** OpenAI-compatible, subclass `HttpConnector`,
implement `_build_payload` + `_generate`, and register the class:

```python
from maestro.connectors.providers.http_base import HttpConnector
from maestro.connectors.base import ChatRequest, GenerationResult, Usage

class MyConnector(HttpConnector):
    provider = "myprovider"

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        payload = {"model": model, "input": request.messages[-1].content,
                   "max_tokens": request.params.max_tokens}
        data = self._post_json("/v1/generate", payload)   # error mapping is handled here
        return GenerationResult(
            text=data["output"], model=model,
            usage=Usage(prompt_tokens=data.get("in", 0), completion_tokens=data.get("out", 0)),
            finish_reason=data.get("stop"), raw=data,
        )

# make it available to register_provider / YAML:
from maestro.connectors.registry import PROVIDER_CLASSES
PROVIDER_CLASSES["myprovider"] = MyConnector
```

Override `_headers()` for custom auth. Accept `http_client` (via `**kw`) so the
connector stays offline-testable with `httpx.MockTransport`.

**Test it offline** (the pattern all provider tests use):

```python
import httpx
from maestro.connectors import ChatRequest

def handler(request):
    return httpx.Response(200, json={"output": "hi", "in": 3, "out": 1})

c = MyConnector("mine", "m", base_url="https://x/v1",
                http_client=httpx.Client(transport=httpx.MockTransport(handler)))
assert c.chat(ChatRequest.of("hello")).text == "hi"
```

---

## 5. Framework integration

The agent's LLM call site routes through the connector via `ConnectorReasoner`
(`src/maestro/agent/reasoning.py`) — no provider SDK is called directly:

```python
from maestro.agent.reasoning import get_reasoner, reasoner_from_registry
from maestro.connectors import build_registry

reasoner = get_reasoner(provider="connector",
                        connector=build_registry().resolve("ollama"))
# or: reasoner = reasoner_from_registry("openai")
plan_input = reasoner.reason(alert)   # same Planner code, any backend
```

**Backward compatibility:** the existing `get_reasoner("stub")` /
`get_reasoner("openai")` paths and `StubReasoner` are unchanged — the connector
path is purely additive. Swap backends by changing config, not code.

---

## 6. Verification checklist (pre-deployment)

Run from a clean environment:

```bash
python -m pytest tests/test_connectors_base.py tests/test_connectors_providers.py \
  tests/test_connectors_fallback.py tests/test_connectors_registry.py \
  tests/test_connectors_api.py tests/test_reasoning_connector.py -q
ruff check .
mypy src
```

Then confirm the runtime surface:

- [ ] **Unit tests green** — providers (request shape + response parse + error
      mapping), fallback (retryable vs non-retryable, disabled skip, all-fail),
      registry (register/enable/disable/default/YAML), API (chat/compare/
      fallback/logs/verify/testcases), reasoner integration. All offline.
- [ ] **Lint + types clean** — `ruff check .` and `mypy src` pass.
- [ ] **Offline path works with no keys** — `build_registry()` yields a `stub`
      default; `/playground` runs prompts and logs metrics with no network.
- [ ] **Dashboard end-to-end** — `uvicorn maestro.server.app:app`; open
      `/playground`; register a provider, run a prompt, compare, toggle a verify
      checkmark, save + replay a test case.
- [ ] **Error mapping is correct** — 401/403 → `AuthenticationError`,
      429 → `RateLimitError`, 5xx/network → `ProviderUnavailableError`,
      other 4xx → `InvalidRequestError`.
- [ ] **Secrets hygiene** — API keys come from env (`api_key_env`) or the
      request; `describe()` never returns a key; keys are not written to
      `configs/connectors.yaml`.
- [ ] **No breaking changes** — the full existing suite (`python -m pytest -q`)
      stays green; existing agent definitions and `get_reasoner` behavior are
      unchanged.

### Live smoke test (optional, requires a key)

```bash
export OPENAI_API_KEY=…            # or ANTHROPIC_API_KEY
python -c "from maestro.connectors import build_registry, ChatRequest; \
r=build_registry().get('openai').chat(ChatRequest.of('ping', max_tokens=5)); print(r.text, r.latency_ms)"
```

---

## 7. Security notes & hardening

- **API authentication (opt-in).** Set `MAESTRO_API_TOKEN` and every `/api`
  request must carry `Authorization: Bearer <token>` (401 otherwise). Unset =
  open, for local dev. The dashboard's 🔑 button stores the token client-side.
  **Set a token for any deployment reachable beyond localhost** — the `custom`
  provider lets a caller register an arbitrary URL, so registration must be
  gated.
- **SSRF guard.** A `base_url` whose host is an IP literal in a link-local
  (incl. cloud metadata `169.254.169.254`), multicast, reserved, or unspecified
  range is rejected at connector construction (→ 400 via the API). Loopback and
  private LAN are allowed so local model servers (Ollama, self-hosted) work.
  Hostname-based DNS-rebinding is a documented residual risk — gate with the API
  token in untrusted deployments. Override with `MAESTRO_ALLOW_UNSAFE_HOSTS=1`.
- **Secrets hygiene.** API keys come from env (`api_key_env`) or the request;
  `describe()` never returns a key; keys are never written to
  `configs/connectors.yaml`. The in-memory log stores prompts/responses but not
  keys.
- **Untrusted content.** Connector inputs/outputs are untrusted model content —
  the dashboard escapes all rendered text; treat responses accordingly
  downstream.
- **Bind + limits.** Bind to `127.0.0.1` by default; put a reverse proxy /
  network policy in front for remote access. Request params are bounded
  (`max_tokens` ≤ 8192); per-provider HTTP timeout defaults to 60 s.

Deployment checklist: set `MAESTRO_API_TOKEN`, keep `MAESTRO_ALLOW_UNSAFE_HOSTS`
unset, provide only the provider keys you need as env vars, and run behind TLS.
