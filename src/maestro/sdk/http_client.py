"""HTTP client for MAESTRO Control Plane API."""
from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from typing import Any

import httpx
from httpx import Response

from maestro.sdk.exceptions import (
    ConfigurationError,
    Conflict,
    MaestroError,
    NotFound,
    RateLimited,
    ServerError,
    TimeoutError,
    Unauthorized,
    ValidationError,
)
from maestro.sdk.models import (
    AgentCreateRequest,
    AgentInfo,
    AgentListResponse,
    AlertIn,
    AlertOut,
    BlastRadiusResponse,
    ControlPlaneState,
    CritiqueIn,
    CritiqueOut,
    HaltResponse,
    LedgerExportResponse,
    LedgerVerifyResponse,
    MemoryInspectRequest,
    MemoryInspectResponse,
    MemoryPromoteRequest,
    MemoryQuarantineRequest,
    MetricsResponse,
    PerimeterIn,
    PerimeterResult,
    PolicyValidateRequest,
    PolicyValidateResponse,
    TenantCreateRequest,
    TenantInfo,
)


class ControlPlaneClient:
    """Client for communicating with the MAESTRO Control Plane API.
    
    Provides both synchronous and asynchronous interfaces with:
    - Automatic retry with exponential backoff
    - Proper error mapping to typed exceptions
    - Request/response logging
    - Authentication header management
    """
    
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_backoff: float = 1.0,
    ):
        """Initialize the control plane client.
        
        Args:
            base_url: Base URL of the MAESTRO control plane (e.g., https://api.maestro.example.com)
            api_key: API key for authentication (Bearer token)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts for transient errors
            retry_backoff: Base backoff factor for exponential retry
        """
        if not base_url:
            raise ConfigurationError("base_url is required")
        
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None
    
    @property
    def sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._sync_client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._sync_client
    
    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._async_client
    
    def close(self) -> None:
        """Close synchronous client."""
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None
    
    async def aclose(self) -> None:
        """Close asynchronous client."""
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None
    
    def __enter__(self) -> ControlPlaneClient:
        return self
    
    def __exit__(self, *args) -> None:
        self.close()
    
    async def __aenter__(self) -> ControlPlaneClient:
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.aclose()
    
    # --- Error handling ---
    
    def _handle_response(self, response: Response) -> dict[str, Any]:
        """Handle response, raise typed exceptions for errors."""
        if response.is_success:
            return response.json()
        
        # Try to parse error response
        error_data = {}
        try:
            error_data = response.json()
        except Exception:
            error_data = {"error": "unknown", "message": response.text}
        
        request_id = response.headers.get("x-request-id")
        status_code = response.status_code
        
        if status_code in (400, 422):
            # FastAPI/Pydantic returns 422 for validation; treat like 400
            detail = error_data.get("message") or error_data.get("detail") or "Validation failed"
            if isinstance(detail, list):
                detail = "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail)
            raise ValidationError(
                detail,
                errors=error_data.get("details") or error_data.get("detail"),
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code == 401:
            raise Unauthorized(
                error_data.get("message", "Authentication required"),
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code == 403:
            raise Unauthorized(
                error_data.get("message", "Access denied"),
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code == 404:
            raise NotFound(
                error_data.get("message", "Resource not found"),
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code == 409:
            raise Conflict(
                error_data.get("message", "Resource conflict"),
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code == 429:
            retry_after = None
            if "retry-after" in response.headers:
                with suppress(ValueError):
                    retry_after = float(response.headers["retry-after"])
            raise RateLimited(
                error_data.get("message", "Rate limit exceeded"),
                retry_after=retry_after,
                request_id=request_id,
                status_code=status_code,
            )
        elif status_code >= 500:
            raise ServerError(
                error_data.get("message", "Internal server error"),
                request_id=request_id,
                status_code=status_code,
            )
        else:
            raise MaestroError(
                error_data.get("message", f"Request failed with status {status_code}"),
                request_id=request_id,
                status_code=status_code,
            )
    
    def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict[str, Any]:
        """Make request with retry logic."""
        last_error: Exception | None = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.sync_client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                )
                return self._handle_response(response)
            
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = TimeoutError(f"Request timeout/connection error: {e}")
            except (RateLimited, ServerError) as e:
                last_error = e
            except MaestroError:
                raise  # Don't retry client errors (4xx except 429)
            
            if attempt < self.max_retries:
                backoff = self.retry_backoff * (2 ** attempt)
                time.sleep(backoff)
        
        raise last_error or MaestroError("Max retries exceeded")
    
    async def _arequest_with_retry(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict[str, Any]:
        """Make async request with retry logic."""
        last_error: Exception | None = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = await self.async_client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                )
                return self._handle_response(response)
            
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = TimeoutError(f"Request timeout/connection error: {e}")
            except (RateLimited, ServerError) as e:
                last_error = e
            except MaestroError:
                raise
            
            if attempt < self.max_retries:
                backoff = self.retry_backoff * (2 ** attempt)
                await asyncio.sleep(backoff)
        
        raise last_error or MaestroError("Max retries exceeded")
    
    # --- Agent Management ---
    
    def create_agent(self, request: AgentCreateRequest) -> AgentInfo:
        """Create a new agent."""
        data = self._request_with_retry(
            "POST", "/api/agents",
            json=request.model_dump(exclude_none=True),
        )
        return AgentInfo(**data)
    
    async def acreate_agent(self, request: AgentCreateRequest) -> AgentInfo:
        data = await self._arequest_with_retry(
            "POST", "/api/agents",
            json=request.model_dump(exclude_none=True),
        )
        return AgentInfo(**data)
    
    def list_agents(self) -> AgentListResponse:
        """List the caller's tenant fleet (tenant derives from the token)."""
        data = self._request_with_retry("GET", "/api/agents")
        return AgentListResponse(**data)

    async def alist_agents(self) -> AgentListResponse:
        data = await self._arequest_with_retry("GET", "/api/agents")
        return AgentListResponse(**data)
    
    def get_agent(self, agent_id: str) -> AgentInfo:
        """Get agent details."""
        data = self._request_with_retry("GET", f"/api/agents/{agent_id}")
        return AgentInfo(**data)
    
    async def aget_agent(self, agent_id: str) -> AgentInfo:
        data = await self._arequest_with_retry("GET", f"/api/agents/{agent_id}")
        return AgentInfo(**data)
    
    def delete_agent(self, agent_id: str) -> dict[str, Any]:
        """Delete an agent."""
        return self._request_with_retry("DELETE", f"/api/agents/{agent_id}")
    
    async def adelete_agent(self, agent_id: str) -> dict[str, Any]:
        return await self._arequest_with_retry("DELETE", f"/api/agents/{agent_id}")
    
    def get_agent_logs(self, agent_id: str, limit: int = 100) -> list[dict]:
        """Get agent logs (its hash-chained ledger events, newest first)."""
        data = self._request_with_retry(
            "GET", f"/api/agents/{agent_id}/logs",
            params={"limit": limit},
        )
        return data.get("logs", [])

    async def aget_agent_logs(self, agent_id: str, limit: int = 100) -> list[dict]:
        data = await self._arequest_with_retry(
            "GET", f"/api/agents/{agent_id}/logs",
            params={"limit": limit},
        )
        return data.get("logs", [])

    def get_agent_blast_radius(self, agent_id: str) -> BlastRadiusResponse:
        """Get one fleet agent's blast radius."""
        data = self._request_with_retry("GET", f"/api/agents/{agent_id}/blast-radius")
        return BlastRadiusResponse(**data)

    async def aget_agent_blast_radius(self, agent_id: str) -> BlastRadiusResponse:
        data = await self._arequest_with_retry("GET", f"/api/agents/{agent_id}/blast-radius")
        return BlastRadiusResponse(**data)

    def submit_agent_alert(self, agent_id: str, alert: AlertIn) -> AlertOut:
        """Run one alert through a fleet agent's live loop."""
        data = self._request_with_retry(
            "POST", f"/api/agents/{agent_id}/alert",
            json=alert.model_dump(),
        )
        return AlertOut(**data)

    async def asubmit_agent_alert(self, agent_id: str, alert: AlertIn) -> AlertOut:
        data = await self._arequest_with_retry(
            "POST", f"/api/agents/{agent_id}/alert",
            json=alert.model_dump(),
        )
        return AlertOut(**data)

    def halt_agent(self, agent_id: str) -> HaltResponse:
        """Trip one fleet agent's kill switch."""
        data = self._request_with_retry("POST", f"/api/agents/{agent_id}/halt")
        return HaltResponse(**data)

    async def ahalt_agent(self, agent_id: str) -> HaltResponse:
        data = await self._arequest_with_retry("POST", f"/api/agents/{agent_id}/halt")
        return HaltResponse(**data)

    def resume_agent(self, agent_id: str) -> HaltResponse:
        """Clear one fleet agent's kill switch."""
        data = self._request_with_retry("POST", f"/api/agents/{agent_id}/resume")
        return HaltResponse(**data)

    async def aresume_agent(self, agent_id: str) -> HaltResponse:
        data = await self._arequest_with_retry("POST", f"/api/agents/{agent_id}/resume")
        return HaltResponse(**data)
    
    # --- Blast Radius ---
    
    def get_blast_radius(self) -> BlastRadiusResponse:
        """Get agent's blast radius."""
        data = self._request_with_retry("GET", "/api/blast-radius")
        return BlastRadiusResponse(**data)
    
    async def aget_blast_radius(self) -> BlastRadiusResponse:
        data = await self._arequest_with_retry("GET", "/api/blast-radius")
        return BlastRadiusResponse(**data)
    
    # --- Control Plane State ---
    
    def get_state(self) -> ControlPlaneState:
        """Get control plane state."""
        data = self._request_with_retry("GET", "/api/state")
        return ControlPlaneState(**data)
    
    async def aget_state(self) -> ControlPlaneState:
        data = await self._arequest_with_retry("GET", "/api/state")
        return ControlPlaneState(**data)
    
    def halt(self) -> HaltResponse:
        """Halt the agent (kill switch)."""
        data = self._request_with_retry("POST", "/api/halt")
        return HaltResponse(**data)
    
    async def ahalt(self) -> HaltResponse:
        data = await self._arequest_with_retry("POST", "/api/halt")
        return HaltResponse(**data)
    
    def resume(self) -> HaltResponse:
        """Resume the agent."""
        data = self._request_with_retry("POST", "/api/resume")
        return HaltResponse(**data)
    
    async def aresume(self) -> HaltResponse:
        data = await self._arequest_with_retry("POST", "/api/resume")
        return HaltResponse(**data)
    
    def reset(self, shadow: bool = False) -> dict[str, Any]:
        """Reset the control plane state."""
        return self._request_with_retry("POST", "/api/reset", json={"shadow": shadow})
    
    async def areset(self, shadow: bool = False) -> dict[str, Any]:
        return await self._arequest_with_retry("POST", "/api/reset", json={"shadow": shadow})
    
    # --- Perimeter ---
    
    def scan_perimeter(self, request: PerimeterIn) -> PerimeterResult:
        """Scan content through the dual-LLM perimeter."""
        data = self._request_with_retry(
            "POST", "/api/perimeter",
            json=request.model_dump(),
        )
        return PerimeterResult(**data)
    
    async def ascan_perimeter(self, request: PerimeterIn) -> PerimeterResult:
        data = await self._arequest_with_retry(
            "POST", "/api/perimeter",
            json=request.model_dump(),
        )
        return PerimeterResult(**data)
    
    # --- Critique ---
    
    def critique(self, request: CritiqueIn) -> CritiqueOut:
        """Run pre-execution critique gate."""
        data = self._request_with_retry(
            "POST", "/api/critique",
            json=request.model_dump(exclude_none=True),
        )
        return CritiqueOut(**data)

    async def acritique(self, request: CritiqueIn) -> CritiqueOut:
        data = await self._arequest_with_retry(
            "POST", "/api/critique",
            json=request.model_dump(exclude_none=True),
        )
        return CritiqueOut(**data)
    
    # --- Alert ---
    
    def submit_alert(self, alert: AlertIn) -> AlertOut:
        """Submit an alert for processing."""
        data = self._request_with_retry(
            "POST", "/api/alert",
            json=alert.model_dump(),
        )
        return AlertOut(**data)
    
    async def asubmit_alert(self, alert: AlertIn) -> AlertOut:
        data = await self._arequest_with_retry(
            "POST", "/api/alert",
            json=alert.model_dump(),
        )
        return AlertOut(**data)
    
    # --- Memory ---

    def inspect_memory(self, request: MemoryInspectRequest, tenant: str | None = None) -> MemoryInspectResponse:
        """Inspect memory records (the caller's tenant scope; structural)."""
        data = self._request_with_retry(
            "GET", "/api/memory",
            params=request.model_dump(exclude_none=True),
        )
        return MemoryInspectResponse(**data)

    async def ainspect_memory(self, request: MemoryInspectRequest, tenant: str | None = None) -> MemoryInspectResponse:
        data = await self._arequest_with_retry(
            "GET", "/api/memory",
            params=request.model_dump(exclude_none=True),
        )
        return MemoryInspectResponse(**data)

    def promote_memory(self, request: MemoryPromoteRequest, tenant: str | None = None) -> dict[str, Any]:
        """Promote a quarantined memory record to trusted."""
        return self._request_with_retry(
            "POST", "/api/memory/promote",
            json=request.model_dump(),
        )

    async def apromote_memory(self, request: MemoryPromoteRequest, tenant: str | None = None) -> dict[str, Any]:
        return await self._arequest_with_retry(
            "POST", "/api/memory/promote",
            json=request.model_dump(),
        )

    def quarantine_memory(self, request: MemoryQuarantineRequest, tenant: str | None = None) -> dict[str, Any]:
        """Quarantine a trusted memory record (demote to untrusted)."""
        return self._request_with_retry(
            "POST", "/api/memory/quarantine",
            json=request.model_dump(),
        )

    async def aquarantine_memory(self, request: MemoryQuarantineRequest, tenant: str | None = None) -> dict[str, Any]:
        return await self._arequest_with_retry(
            "POST", "/api/memory/quarantine",
            json=request.model_dump(),
        )
    
    # --- Ledger ---
    
    def verify_ledger(self) -> LedgerVerifyResponse:
        """Verify ledger integrity."""
        data = self._request_with_retry("GET", "/api/ledger/verify")
        return LedgerVerifyResponse(**data)
    
    async def averify_ledger(self) -> LedgerVerifyResponse:
        data = await self._arequest_with_retry("GET", "/api/ledger/verify")
        return LedgerVerifyResponse(**data)
    
    def export_ledger(self, limit: int | None = None) -> LedgerExportResponse:
        """Export ledger events."""
        params = {"limit": limit} if limit else None
        data = self._request_with_retry("GET", "/api/ledger/export", params=params)
        return LedgerExportResponse(**data)
    
    async def aexport_ledger(self, limit: int | None = None) -> LedgerExportResponse:
        params = {"limit": limit} if limit else None
        data = await self._arequest_with_retry("GET", "/api/ledger/export", params=params)
        return LedgerExportResponse(**data)
    
    # --- Metrics ---
    
    def get_metrics(self) -> MetricsResponse:
        """Get platform metrics."""
        data = self._request_with_retry("GET", "/api/metrics")
        return MetricsResponse(**data)
    
    async def aget_metrics(self) -> MetricsResponse:
        data = await self._arequest_with_retry("GET", "/api/metrics")
        return MetricsResponse(**data)
    
    # --- Tenant Management ---
    
    def create_tenant(self, request: TenantCreateRequest) -> TenantInfo:
        """Create a new tenant."""
        data = self._request_with_retry(
            "POST", "/api/tenants",
            json=request.model_dump(exclude_none=True),
        )
        return TenantInfo(**data)
    
    async def acreate_tenant(self, request: TenantCreateRequest) -> TenantInfo:
        data = await self._arequest_with_retry(
            "POST", "/api/tenants",
            json=request.model_dump(exclude_none=True),
        )
        return TenantInfo(**data)
    
    def list_tenants(self) -> list[TenantInfo]:
        """List all tenants."""
        data = self._request_with_retry("GET", "/api/tenants")
        return [TenantInfo(**t) for t in data.get("tenants", [])]
    
    async def alist_tenants(self) -> list[TenantInfo]:
        data = await self._arequest_with_retry("GET", "/api/tenants")
        return [TenantInfo(**t) for t in data.get("tenants", [])]
    
    def get_tenant(self, tenant_id: str) -> TenantInfo:
        """Get tenant details."""
        data = self._request_with_retry("GET", f"/api/tenants/{tenant_id}")
        return TenantInfo(**data)
    
    async def aget_tenant(self, tenant_id: str) -> TenantInfo:
        data = await self._arequest_with_retry("GET", f"/api/tenants/{tenant_id}")
        return TenantInfo(**data)
    
    def isolate_tenant(self, tenant_id: str) -> dict[str, Any]:
        """Enforce tenant isolation."""
        return self._request_with_retry("POST", f"/api/tenants/{tenant_id}/isolate")
    
    async def aisolate_tenant(self, tenant_id: str) -> dict[str, Any]:
        return await self._arequest_with_retry("POST", f"/api/tenants/{tenant_id}/isolate")
    
    # --- Policy Management ---
    
    def validate_policy(self, request: PolicyValidateRequest) -> PolicyValidateResponse:
        """Validate a policy bundle."""
        data = self._request_with_retry(
            "POST", "/api/policies/validate",
            json=request.model_dump(),
        )
        return PolicyValidateResponse(**data)
    
    async def avalidate_policy(self, request: PolicyValidateRequest) -> PolicyValidateResponse:
        data = await self._arequest_with_retry(
            "POST", "/api/policies/validate",
            json=request.model_dump(),
        )
        return PolicyValidateResponse(**data)
    
    def get_controls(self) -> dict[str, Any]:
        """Get control status report."""
        return self._request_with_retry("GET", "/api/controls")
    
    async def aget_controls(self) -> dict[str, Any]:
        return await self._arequest_with_retry("GET", "/api/controls")
    
    def get_layers(self) -> dict[str, Any]:
        """Get layer information."""
        return self._request_with_retry("GET", "/api/layers")
    
    async def aget_layers(self) -> dict[str, Any]:
        return await self._arequest_with_retry("GET", "/api/layers")