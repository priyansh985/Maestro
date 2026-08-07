"""Signed Policy Bundles for Production Deployment (BP12).

Provides cosign/Notary signing, verification at load time, version pinning,
expiry, and exception tracking.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from maestro.security.policy_bundle import PolicyBundle, PolicyRegistry, ActivationRecord


@dataclass
class PolicyBundleSignature:
    """A cryptographic signature for a policy bundle."""
    algorithm: str = "sha256"
    signature: str = ""
    signed_by: str = ""  # Identity of signer
    signed_at: float = field(default_factory=time.time)
    public_key: str = ""  # Public key used for verification
    key_id: str = ""  # Key identifier


@dataclass
class SignedPolicyBundle:
    """A policy bundle with cryptographic signatures."""
    bundle: PolicyBundle
    signatures: list[PolicyBundleSignature] = field(default_factory=list)
    version: str = "1.0"
    requires_signatures: int = 2  # Two-person rule
    expires_at: float = 0.0
    
    def content_hash(self) -> str:
        """Get content hash of the inner bundle."""
        return self.bundle.digest()
    
    def add_signature(
        self,
        signature: str,
        signed_by: str,
        public_key: str,
        key_id: str,
        algorithm: str = "sha256",
    ) -> None:
        """Add a signature to the bundle."""
        sig = PolicyBundleSignature(
            algorithm=algorithm,
            signature=signature,
            signed_by=signed_by,
            public_key=public_key,
            key_id=key_id,
        )
        self.signatures.append(sig)
    
    def verify_signatures(self, required_signers: Optional[list[str]] = None) -> bool:
        """Verify all signatures on the bundle."""
        if len(self.signatures) < self.requires_signatures:
            return False
        
        if required_signers:
            signers = {sig.signed_by for sig in self.signatures}
            if not all(signer in signers for signer in required_signers):
                return False
        
        bundle_hash = self.content_hash()
        return all(self._verify_signature(bundle_hash, sig) for sig in self.signatures)
    
    def _verify_signature(self, data: str, sig: PolicyBundleSignature) -> bool:
        """Verify a single signature."""
        try:
            expected = hmac.new(
                sig.public_key.encode(),
                data.encode(),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected, sig.signature)
        except Exception:
            return False
    
    def is_expired(self) -> bool:
        """Check if bundle has expired."""
        if self.expires_at > 0:
            return time.time() > self.expires_at
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "bundle": self.bundle.as_dict(),
            "signatures": [asdict(sig) for sig in self.signatures],
            "version": self.version,
            "requires_signatures": self.requires_signatures,
            "expires_at": self.expires_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedPolicyBundle":
        """Deserialize from dictionary."""
        bundle = PolicyBundle(
            version=data["bundle"]["version"],
            allowed_intents=tuple(data["bundle"]["allowed_intents"]),
            limits=tuple(data["bundle"]["limits"]),
            parent_digest=data["bundle"].get("parent_digest"),
            created_at=data["bundle"].get("created_at", 0),
            provenance=data["bundle"].get("provenance", ""),
        )
        signatures = [
            PolicyBundleSignature(**sig) for sig in data.get("signatures", [])
        ]
        return cls(
            bundle=bundle,
            signatures=signatures,
            version=data.get("version", "1.0"),
            requires_signatures=data.get("requires_signatures", 2),
            expires_at=data.get("expires_at", 0.0),
        )


class PolicySigner:
    """Signs policy bundles using various backends."""
    
    def __init__(self, private_key: str, key_id: str, algorithm: str = "sha256"):
        self.private_key = private_key
        self.key_id = key_id
        self.algorithm = algorithm
    
    def sign(self, bundle: PolicyBundle) -> PolicyBundleSignature:
        """Sign a policy bundle."""
        data = bundle.content_hash()
        signature = self._create_signature(data)
        
        return PolicyBundleSignature(
            algorithm=self.algorithm,
            signature=signature,
            signed_by=self.key_id,
            public_key=self.private_key,  # In production, store public key separately
            key_id=self.key_id,
        )
    
    def _create_signature(self, data: str) -> str:
        """Create HMAC signature."""
        import hmac
        return hmac.new(
            self.private_key.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()


class CosignSigner:
    """Signs policy bundles using cosign (Sigstore)."""
    
    def __init__(
        self,
        key_path: str | Path,
        password: str | None = None,
        fulcio_url: str | None = None,
        rekor_url: str | None = None,
    ):
        self.key_path = Path(key_path)
        self.password = password
        self.fulcio_url = fulcio_url
        self.rekor_url = rekor_url
    
    def sign(self, bundle: PolicyBundle, output_path: Path) -> bool:
        """Sign bundle using cosign."""
        # Write bundle to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(bundle.to_dict(), f)
            bundle_file = Path(f.name)
        
        try:
            cmd = [
                "cosign", "sign-blob",
                "--key", str(self.key_path),
                "--output-signature", str(output_path),
                str(bundle_file),
            ]
            
            if self.password:
                env = {"COSIGN_PASSWORD": self.password}
            else:
                env = None
            
            if self.fulcio_url:
                cmd.extend(["--fulcio-url", self.fulcio_url])
            if self.rekor_url:
                cmd.extend(["--rekor-url", self.rekor_url])
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            return result.returncode == 0
        finally:
            bundle_file.unlink(missing_ok=True)
    
    def verify(self, bundle: PolicyBundle, signature_path: Path) -> bool:
        """Verify cosign signature."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(bundle.to_dict(), f)
            bundle_file = Path(f.name)
        
        try:
            cmd = [
                "cosign", "verify-blob",
                "--key", str(self.key_path),
                "--signature", str(signature_path),
                str(bundle_file),
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        finally:
            bundle_file.unlink(missing_ok=True)


class NotarySigner:
    """Signs policy bundles using Notary v2."""
    
    def __init__(self, server: str, repository: str):
        self.server = server
        self.repository = repository
    
    def sign(self, bundle: PolicyBundle, tag: str) -> bool:
        """Sign bundle using notary."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(bundle.to_dict(), f)
            bundle_file = Path(f.name)
        
        try:
            cmd = [
                "notary", "sign",
                "--server", self.server,
                "--repository", self.repository,
                "--tag", tag,
                str(bundle_file),
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        finally:
            bundle_file.unlink(missing_ok=True)
    
    def verify(self, tag: str) -> bool:
        """Verify notary signature."""
        cmd = [
            "notary", "verify",
            "--server", self.server,
            "--repository", self.repository,
            "--tag", tag,
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0


class SignedPolicyRegistry(PolicyRegistry):
    """Policy registry that only accepts signed bundles."""
    
    def __init__(
        self,
        path: str | Path | None = None,
        min_signatures: int = 2,
        trusted_signers: list[str] | None = None,
        cosign_key: str | None = None,
        notary_server: str | None = None,
        notary_repo: str | None = None,
    ):
        super().__init__(path)
        self.min_signatures = min_signatures
        self.trusted_signers = trusted_signers or []
        self.cosign_signer = CosignSigner(cosign_key) if cosign_key else None
        self.notary_signer = NotarySigner(notary_server, notary_repo) if notary_server else None
    
    def register(self, bundle: PolicyBundle) -> PolicyBundle:
        """Register a bundle - requires valid signatures."""
        if isinstance(bundle, SignedPolicyBundle):
            signed_bundle = bundle
        else:
            raise ValueError("Only SignedPolicyBundle can be registered in SignedPolicyRegistry")
        
        if not signed_bundle.verify_signatures(self.trusted_signers):
            raise ValueError("Bundle signatures verification failed")
        
        if len(signed_bundle.signatures) < self.min_signatures:
            raise ValueError(f"Bundle requires at least {self.min_signatures} signatures")
        
        if signed_bundle.is_expired():
            raise ValueError("Bundle has expired")
        
        return super().register(signed_bundle.bundle)
    
    def activate(self, version: str) -> PolicyBundle:
        """Activate a bundle version - requires signature verification."""
        bundle = super().activate(version)
        if not isinstance(bundle, SignedPolicyBundle):
            # Wrap existing bundle for signature tracking
            signed = SignedPolicyBundle(bundle=bundle, requires_signatures=self.min_signatures)
            if not signed.verify_signatures(self.trusted_signers):
                raise ValueError(f"Active bundle {version} has invalid signatures")
        return bundle


# --- Version Pinning ---

@dataclass
class VersionPin:
    """Pins a specific policy bundle version."""
    version: str
    bundle_hash: str
    pinned_at: float = field(default_factory=time.time)
    pinned_by: str = ""
    reason: str = ""


class VersionPinner:
    """Manages version pins for policy bundles."""
    
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.pins: dict[str, VersionPin] = {}
        if self.path and self.path.exists():
            self._load()
    
    def _load(self):
        with open(self.path) as f:
            data = json.load(f)
            self.pins = {k: VersionPin(**v) for k, v in data.items()}
    
    def _save(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.pins.items()}, f, indent=2)
    
    def pin(
        self,
        version: str,
        bundle: PolicyBundle,
        pinned_by: str,
        reason: str = "",
    ) -> VersionPin:
        """Pin a specific version."""
        pin = VersionPin(
            version=version,
            bundle_hash=bundle.content_hash(),
            pinned_by=pinned_by,
            reason=reason,
        )
        self.pins[version] = pin
        self._save()
        return pin
    
    def unpin(self, version: str) -> bool:
        """Remove a version pin."""
        if version in self.pins:
            del self.pins[version]
            self._save()
            return True
        return False
    
    def is_pinned(self, version: str) -> bool:
        return version in self.pins
    
    def get_pin(self, version: str) -> VersionPin | None:
        return self.pins.get(version)
    
    def list_pins(self) -> list[VersionPin]:
        return list(self.pins.values())


# --- Exception Tracking ---

@dataclass
class PolicyException:
    """An exception to policy rules with expiration and approval."""
    exception_id: str
    rule_id: str
    reason: str
    approved_by: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0  # 0 = no expiry
    scope: str = "global"  # global, tenant, agent
    scope_value: str = ""
    
    def is_valid(self, now: float | None = None) -> bool:
        at = now or time.time()
        if self.expires_at > 0 and at > self.expires_at:
            return False
        return True


class ExceptionTracker:
    """Tracks policy exceptions with approval workflow."""
    
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.exceptions: dict[str, PolicyException] = {}
        if self.path and self.path.exists():
            self._load()
    
    def _load(self):
        with open(self.path) as f:
            data = json.load(f)
            self.exceptions = {k: PolicyException(**v) for k, v in data.items()}
    
    def _save(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.exceptions.items()}, f, indent=2)
    
    def create_exception(
        self,
        rule_id: str,
        reason: str,
        approved_by: str,
        expires_in_seconds: float = 86400,  # 24 hours default
        scope: str = "global",
        scope_value: str = "",
    ) -> PolicyException:
        """Create a new policy exception."""
        import uuid
        exception_id = f"exc-{uuid.uuid4().hex[:12]}"
        expires_at = time.time() + expires_in_seconds if expires_in_seconds > 0 else 0
        
        exc = PolicyException(
            exception_id=exception_id,
            rule_id=rule_id,
            reason=reason,
            approved_by=approved_by,
            expires_at=expires_at,
            scope=scope,
            scope_value=scope_value,
        )
        
        self.exceptions[exception_id] = exc
        self._save()
        return exc
    
    def revoke_exception(self, exception_id: str) -> bool:
        """Revoke a policy exception."""
        if exception_id in self.exceptions:
            del self.exceptions[exception_id]
            self._save()
            return True
        return False
    
    def get_exception(self, exception_id: str) -> PolicyException | None:
        return self.exceptions.get(exception_id)
    
    def list_exceptions(
        self,
        rule_id: str | None = None,
        scope: str | None = None,
        scope_value: str | None = None,
        include_expired: bool = False,
    ) -> list[PolicyException]:
        now = time.time()
        result = []
        for exc in self.exceptions.values():
            if rule_id and exc.rule_id != rule_id:
                continue
            if scope and exc.scope != scope:
                continue
            if scope_value and exc.scope_value != scope_value:
                continue
            if not include_expired and not exc.is_valid(now):
                continue
            result.append(exc)
        return result
    
    def check_exception(
        self,
        rule_id: str,
        scope: str = "global",
        scope_value: str = "",
    ) -> PolicyException | None:
        """Check if there's a valid exception for a rule."""
        for exc in self.exceptions.values():
            if exc.rule_id == rule_id and exc.scope == scope:
                if scope_value and exc.scope_value != scope_value:
                    continue
                if exc.is_valid():
                    return exc
        return None