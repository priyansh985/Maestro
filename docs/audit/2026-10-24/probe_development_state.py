"""Read-only development audit probes; uses synthetic data and temporary files.

Run with the repository environment. This is evidence collection, not a test
suite or a production readiness check. It deliberately reports unsafe behavior.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import importlib.util
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))


def main() -> None:
    print(json.dumps({"python": sys.version, "executable": sys.executable}), flush=True)
    for module in ("pytest", "jose", "psycopg_pool", "temporalio"):
        print(json.dumps({"module": module, "available": importlib.util.find_spec(module) is not None}), flush=True)

    from maestro.security.action import parse_proposal
    from maestro.security.policy_bundle import PolicyBundle
    from maestro.security.policy_bundle_signed import (
        PolicyBundleSignature,
        PolicySigner,
        SignedPolicyBundle,
    )
    from maestro.security.release_gate import Gate, GateBundle, GateRegistry, ReleaseGateEvaluator

    registry = GateRegistry()
    registry.register(GateBundle(
        version="audit-only", agent_spec_hash="expected-spec",
        gates=(Gate("impossible", "No runner exists", 2.0),),
        signature="invalid", signed_by=("same", "same"), expires_at=1.0,
    ))
    result = ReleaseGateEvaluator(registry).evaluate({"different_spec": True}, "audit-only")
    print(json.dumps({"probe": "invalid_release_gate", "overall_passed": result.overall_passed,
                      "gate_results": [vars(g) for g in result.gate_results]}), flush=True)

    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"], limits={})
    try:
        PolicySigner("synthetic-audit-key", "audit-signer").sign(bundle)
        signer_result = "returned"
    except Exception as exc:
        signer_result = type(exc).__name__ + ": " + str(exc)
    print(json.dumps({"probe": "policy_signer", "result": signer_result}), flush=True)
    key = "synthetic-attacker-owned-key"
    sig = PolicyBundleSignature(
        signature=hmac.new(key.encode(), bundle.digest().encode(), hashlib.sha256).hexdigest(),
        signed_by="same-signer", public_key=key,
    )
    signed = SignedPolicyBundle(bundle, signatures=[sig, sig], requires_signatures=2)
    print(json.dumps({"probe": "duplicate_self_supplied_signatures", "accepted": signed.verify_signatures(),
                      "serialized_contains_hmac_key": key in json.dumps(signed.to_dict())}), flush=True)

    from maestro.hybrid import create_hybrid_runner
    runner = create_hybrid_runner(control_plane_url="http://127.0.0.1:1", tenant="audit")
    print(json.dumps({"probe": "unreachable_control_plane", "healthy": runner.check_control_plane_health(),
                      "mode": runner.mode.value}), flush=True)

    from maestro.agents.coding import create_coding_agent
    from maestro.agents.research import create_research_agent
    from maestro.telemetry.detection import Alert, AlertClass
    alert = Alert(ts=1.0, cls=AlertClass.ANOMALY, severity=0.1, detail="synthetic audit")
    for name, factory in (("coding", create_coding_agent), ("research", create_research_agent)):
        platform = factory(tenant="audit")
        result = platform.handle_alert(alert)
        print(json.dumps({"probe": "vertical_default_loop", "agent": name,
                          "proposed_action": result.proposed_action, "allowed": result.allowed,
                          "reason": result.reason, "output": result.enforcement.output}), flush=True)

    from maestro.orchestration.journal import Journal
    from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy
    proposal = parse_proposal({"intent": "noop", "target": "agent:self", "reason": "audit",
                               "evidence_ids": ["audit"], "requested_ttl_seconds": 1})
    def slow_adapter(p):
        time.sleep(0.15)
        return {"ok": True, "target": p.target}
    started = time.monotonic()
    try:
        ExecutionSandbox(policy=SandboxPolicy(timeout_s=0.01)).run(slow_adapter, proposal)
    except Exception as exc:
        print(json.dumps({"probe": "sandbox_timeout", "configured_seconds": 0.01,
                          "elapsed_seconds": round(time.monotonic() - started, 3),
                          "error": type(exc).__name__}), flush=True)

    with tempfile.TemporaryDirectory(prefix="maestro-audit-") as tmp:
        count = [0]
        def effect_then_die(p):
            count[0] += 1
            if count[0] == 1:
                raise SystemExit("synthetic process death after effect, before journal")
            return {"ok": True, "target": p.target}
        path = Path(tmp) / "journal.jsonl"
        with contextlib.suppress(SystemExit):
            ExecutionSandbox(journal=Journal(path)).run(effect_then_die, proposal, idempotency_key="audit-op")
        ExecutionSandbox(journal=Journal(path)).run(effect_then_die, proposal, idempotency_key="audit-op")
        print(json.dumps({"probe": "effect_before_journal_crash", "side_effect_count": count[0]}), flush=True)

    from maestro.critique.types import Candidate
    from maestro.domains.verifiers import CitationVerifier
    citation = CitationVerifier().verify(
        Candidate(text="The treatment is safe [invented-source]", family="audit"),
        {"sources": ["The treatment is not safe"]},
    )
    print(json.dumps({"probe": "citation_negation_and_fake_marker", "verified": citation.verified,
                      "reason": citation.reason}), flush=True)

    import gzip

    from maestro.dr.disaster_recovery import BackupManager, DRConfig
    from maestro.security.ledger import Ledger
    with tempfile.TemporaryDirectory(prefix="maestro-dr-audit-") as tmp:
        ledger = Ledger(key=b"synthetic-audit-key")
        ledger.append(event_type="audit", actor_identity="audit", decision="observe", input_hash="audit")
        backups = BackupManager(ledger, DRConfig(backup_dir=tmp), b"synthetic-audit-key")
        metadata = backups.create_backup(tenant="audit")
        restored = backups.restore_backup(metadata.backup_id)
        path = Path(tmp) / (metadata.backup_id + ".json.gz")
        with gzip.open(path, "rt") as handle:
            data = json.load(handle)
        data["ledger"][0]["decision"] = "tampered"
        with gzip.open(path, "wt") as handle:
            json.dump(data, handle)
        print(json.dumps({"probe": "backup_restore_and_integrity", "original_events": len(ledger),
                          "restored_events": len(restored),
                          "tampered_backup_verified": backups.verify_backup(metadata.backup_id)}), flush=True)

    import httpx

    from maestro.sdk.http_client import ControlPlaneClient
    effects = [0]
    def ambiguous_response(request):
        effects[0] += 1
        if effects[0] == 1:
            raise httpx.ReadTimeout("synthetic lost response after server effect", request=request)
        return httpx.Response(200, json={"ok": True})
    sdk = ControlPlaneClient("http://audit.invalid", max_retries=1, retry_backoff=0)
    sdk._sync_client = httpx.Client(base_url="http://audit.invalid", transport=httpx.MockTransport(ambiguous_response))
    try:
        sdk._request_with_retry("POST", "/api/agents", json={"type": "generic"})
    finally:
        sdk.close()
    print(json.dumps({"probe": "sdk_mutating_retry", "server_effect_count": effects[0]}), flush=True)

    from fastapi.testclient import TestClient

    from maestro.server.agent_registry import REGISTRY
    from maestro.server.app import create_app
    from maestro.server.auth import AuthService, Role, configure_auth
    from maestro.server.control_api import _ISOLATED, _PLANES, _TENANT_META
    app = create_app()
    service = AuthService(key=b"synthetic-audit-api-key")
    configure_auth(enforce=True, service=service)
    admin = service.issue("audit-admin", tenant="audit-admin", role=Role.ADMIN)
    operator = service.issue("audit-operator", tenant="audit-contained", role=Role.OPERATOR)
    with TestClient(app) as client:
        admin_headers = {"Authorization": "Bearer " + admin}
        operator_headers = {"Authorization": "Bearer " + operator}
        client.post("/api/tenants", headers=admin_headers, json={"tenant_id": "audit-contained"})
        client.post("/api/tenants/audit-contained/isolate", headers=admin_headers)
        created = client.post("/api/agents", headers=operator_headers,
                              json={"agent_id": "agent:audit:new", "type": "generic"})
        result = client.post("/api/agents/agent:audit:new/alert", headers=operator_headers,
                             json={"cls": "anomaly", "severity": 0.1, "detail": "synthetic audit"})
        print(json.dumps({"probe": "new_agent_after_tenant_containment", "create_status": created.status_code,
                          "new_agent_status": created.json().get("status"),
                          "alert_status": result.status_code, "alert_allowed": result.json().get("allowed"),
                          "isolation_flag": "audit-contained" in _ISOLATED}), flush=True)
    REGISTRY.clear()
    _PLANES.clear()
    _TENANT_META.clear()
    _ISOLATED.clear()


if __name__ == "__main__":
    main()
