"""FastAPI router + in-memory stores for the model-testing dashboard.

Exposes a small REST surface under ``/api`` that the ``/playground`` dashboard
drives: manage connectors, run prompts (single or side-by-side compare), log
every request/response with latency + token metrics, save/replay test cases,
and record manual verification checkmarks.

Everything is offline by default — the registry is built from
``configs/connectors.yaml`` whose default is the deterministic stub, so the
dashboard is fully usable with no API key and no network.
"""
from __future__ import annotations

import itertools
import os
import time
from collections import deque
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from ..connectors import (
    ChatMessage,
    ChatParams,
    ChatRequest,
    ConnectorError,
    ConnectorRegistry,
    FallbackConnector,
    Role,
    build_registry,
)


# --------------------------------------------------------------------------- #
# In-memory stores
# --------------------------------------------------------------------------- #
class LogStore:
    """Bounded, newest-first store of request/response records."""

    def __init__(self, maxlen: int = 500):
        self._items: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._ids = itertools.count(1)

    def add(self, record: dict[str, Any]) -> dict[str, Any]:
        record = {"id": next(self._ids), "ts": time.time(), "verified": False, **record}
        self._items.appendleft(record)
        return record

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(itertools.islice(self._items, limit))

    def get(self, log_id: int) -> dict[str, Any] | None:
        return next((r for r in self._items if r["id"] == log_id), None)

    def clear(self) -> None:
        self._items.clear()


class TestCaseStore:
    """Named, replayable test scenarios."""

    __test__ = False  # not a pytest test class despite the name

    def __init__(self) -> None:
        self._items: dict[int, dict[str, Any]] = {}
        self._ids = itertools.count(1)

    def add(self, case: dict[str, Any]) -> dict[str, Any]:
        cid = next(self._ids)
        record = {"id": cid, **case}
        self._items[cid] = record
        return record

    def list(self) -> list[dict[str, Any]]:
        return list(self._items.values())

    def get(self, cid: int) -> dict[str, Any] | None:
        return self._items.get(cid)

    def remove(self, cid: int) -> bool:
        return self._items.pop(cid, None) is not None


# --------------------------------------------------------------------------- #
# Request/response schemas
# --------------------------------------------------------------------------- #
class ParamsModel(BaseModel):
    temperature: float = 0.7
    max_tokens: int = Field(default=256, ge=1, le=8192)
    top_p: float | None = None
    stop: list[str] | None = None

    def to_params(self) -> ChatParams:
        return ChatParams(
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            top_p=self.top_p,
            stop=self.stop,
        )


class RegisterConnectorRequest(BaseModel):
    name: str
    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    auth_header: str | None = None
    enabled: bool = True
    default: bool = False


class ChatApiRequest(BaseModel):
    prompt: str
    system: str | None = None
    connector: str | None = None
    compare: list[str] | None = None
    fallback: bool = False
    params: ParamsModel = Field(default_factory=ParamsModel)
    model: str | None = None
    save_log: bool = True


class SaveTestCaseRequest(BaseModel):
    name: str
    prompt: str
    system: str | None = None
    connector: str | None = None
    params: ParamsModel = Field(default_factory=ParamsModel)


class VerifyRequest(BaseModel):
    verified: bool = True


# --------------------------------------------------------------------------- #
# Optional auth (env-gated; off by default so offline dev is unaffected)
# --------------------------------------------------------------------------- #
API_TOKEN_ENV = "MAESTRO_API_TOKEN"


def require_api_token(authorization: str | None = Header(default=None)) -> None:
    """Require ``Authorization: Bearer <token>`` when ``MAESTRO_API_TOKEN`` is
    set. When the env var is unset the API is open (local-dev default). Read at
    request time so the token can be rotated without a restart.

    Gating registration matters: the ``custom`` provider lets an operator point
    a connector at an arbitrary URL, so a token should protect any deployment
    reachable beyond localhost.
    """
    token = os.environ.get(API_TOKEN_ENV)
    if not token:
        return
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid or missing API token")


# --------------------------------------------------------------------------- #
# Router factory
# --------------------------------------------------------------------------- #
def create_connectors_router(
    registry: ConnectorRegistry,
    logs: LogStore,
    testcases: TestCaseStore,
) -> APIRouter:
    """Build the ``/api`` router bound to the given registry + stores."""
    router = APIRouter(prefix="/api", tags=["connectors"],
                       dependencies=[Depends(require_api_token)])

    def _build_request(req: ChatApiRequest) -> ChatRequest:
        messages: list[ChatMessage] = []
        if req.system:
            messages.append(ChatMessage(Role.SYSTEM, req.system))
        messages.append(ChatMessage(Role.USER, req.prompt))
        return ChatRequest(messages=messages, params=req.params.to_params(), model=req.model)

    def _run_one(target_name: str, chat_request: ChatRequest, save: bool,
                 *, raise_missing: bool = True) -> dict[str, Any]:
        """Run one connector; return a result dict, logging + capturing errors.

        ``raise_missing`` controls what happens when the connector name is
        unknown: single-run requests raise a 404 (the caller named one bad
        target), but compare/multi requests return a per-connector error so one
        stale name does not abort the whole comparison.
        """
        try:
            connector = registry.get(target_name)
        except KeyError as exc:
            if raise_missing:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            result = {"connector": target_name, "ok": False,
                      "error": {"type": "NotFound", "message": str(exc), "retryable": False}}
            if save:
                record = logs.add({"connector": target_name,
                                   "prompt": chat_request.messages[-1].content, **result})
                result["log_id"] = record["id"]
            return result
        try:
            response = connector.chat(chat_request)
            result = {"connector": target_name, "ok": True, "response": response.to_dict()}
        except ConnectorError as exc:
            result = {
                "connector": target_name,
                "ok": False,
                "error": {"type": type(exc).__name__, "message": str(exc),
                          "retryable": exc.retryable},
            }
        if save:
            record = logs.add({
                "connector": target_name,
                "prompt": chat_request.messages[-1].content,
                "system": chat_request.system_prompt() or None,
                **result,
            })
            result["log_id"] = record["id"]
        return result

    # -- connectors -------------------------------------------------------- #
    @router.get("/connectors")
    def list_connectors() -> dict[str, Any]:
        return {"connectors": registry.list_descriptions(), "default": registry.default_name}

    @router.post("/connectors")
    def register_connector(body: RegisterConnectorRequest) -> dict[str, Any]:
        extra: dict[str, Any] = {}
        if body.auth_header:
            extra["auth_header"] = body.auth_header
        try:
            connector = registry.register_provider(
                name=body.name,
                provider=body.provider,
                model=body.model,
                base_url=body.base_url,
                api_key=body.api_key,
                default=body.default,
                enabled=body.enabled,
                **extra,
            )
        except (ValueError, TypeError) as exc:
            # ValueError: duplicate name / unknown provider.
            # TypeError: missing a required field for the provider (e.g. a
            # custom provider registered without base_url).
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"connector": connector.describe()}

    @router.delete("/connectors/{name}")
    def delete_connector(name: str) -> dict[str, Any]:
        registry.remove(name)
        return {"removed": name}

    @router.post("/connectors/{name}/enable")
    def enable_connector(name: str) -> dict[str, Any]:
        return _set_enabled(name, True)

    @router.post("/connectors/{name}/disable")
    def disable_connector(name: str) -> dict[str, Any]:
        return _set_enabled(name, False)

    def _set_enabled(name: str, enabled: bool) -> dict[str, Any]:
        try:
            connector = registry.set_enabled(name, enabled)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"connector": connector.describe()}

    @router.post("/connectors/{name}/default")
    def make_default(name: str) -> dict[str, Any]:
        try:
            registry.set_default(name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"default": name}

    @router.post("/connectors/{name}/health")
    def health(name: str) -> dict[str, Any]:
        try:
            connector = registry.get(name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"connector": name, "ok": connector.health_check()}

    # -- chat -------------------------------------------------------------- #
    @router.post("/chat")
    def chat(body: ChatApiRequest) -> dict[str, Any]:
        chat_request = _build_request(body)

        # Side-by-side comparison across several connectors. A single unknown
        # name yields a per-connector error rather than failing the whole run.
        if body.compare:
            results = [_run_one(name, chat_request, body.save_log, raise_missing=False)
                       for name in body.compare]
            return {"mode": "compare", "results": results}

        target = body.connector or registry.default_name
        if target is None:
            raise HTTPException(status_code=400, detail="no connector available")

        # Fallback: try the target, then every other enabled connector in turn.
        if body.fallback:
            try:
                primary = registry.get(target)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            chain = [primary] + [
                c for n, c in _enabled_others(registry, target)
            ]
            fb = FallbackConnector(f"fallback:{target}", chain)
            try:
                response = fb.chat(chat_request)
                result: dict[str, Any] = {
                    "connector": response.connector, "ok": True,
                    "response": response.to_dict(), "via_fallback": True,
                }
            except ConnectorError as exc:
                result = {
                    "connector": target, "ok": False, "via_fallback": True,
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                }
            if body.save_log:
                record = logs.add({"connector": result["connector"],
                                   "prompt": body.prompt, "system": body.system, **result})
                result["log_id"] = record["id"]
            return {"mode": "fallback", "results": [result]}

        return {"mode": "single", "results": [_run_one(target, chat_request, body.save_log)]}

    # -- logs -------------------------------------------------------------- #
    @router.get("/logs")
    def get_logs(limit: int = 100) -> dict[str, Any]:
        return {"logs": logs.list(limit)}

    @router.delete("/logs")
    def clear_logs() -> dict[str, Any]:
        logs.clear()
        return {"cleared": True}

    @router.post("/logs/{log_id}/verify")
    def verify_log(log_id: int, body: VerifyRequest) -> dict[str, Any]:
        record = logs.get(log_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no log {log_id}")
        record["verified"] = body.verified
        return {"log": record}

    # -- test cases -------------------------------------------------------- #
    @router.get("/testcases")
    def list_testcases() -> dict[str, Any]:
        return {"testcases": testcases.list()}

    @router.post("/testcases")
    def save_testcase(body: SaveTestCaseRequest) -> dict[str, Any]:
        record = testcases.add(body.model_dump())
        return {"testcase": record}

    @router.delete("/testcases/{cid}")
    def delete_testcase(cid: int) -> dict[str, Any]:
        if not testcases.remove(cid):
            raise HTTPException(status_code=404, detail=f"no testcase {cid}")
        return {"removed": cid}

    @router.post("/testcases/{cid}/replay")
    def replay_testcase(cid: int) -> dict[str, Any]:
        case = testcases.get(cid)
        if case is None:
            raise HTTPException(status_code=404, detail=f"no testcase {cid}")
        req = ChatApiRequest(
            prompt=case["prompt"],
            system=case.get("system"),
            connector=case.get("connector"),
            params=ParamsModel(**(case.get("params") or {})),
        )
        return chat(req)

    return router


def _enabled_others(registry: ConnectorRegistry, exclude: str) -> list[tuple[str, Any]]:
    out = []
    for name in registry.names():
        if name == exclude:
            continue
        connector = registry.get(name)
        if connector.enabled:
            out.append((name, connector))
    return out


# --------------------------------------------------------------------------- #
# Module-level defaults (used by the app; tests may build their own)
# --------------------------------------------------------------------------- #
default_registry_instance = build_registry()
default_logs = LogStore()
default_testcases = TestCaseStore()
router = create_connectors_router(default_registry_instance, default_logs, default_testcases)
