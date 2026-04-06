from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .exceptions import (
    RegistryFetchError,
    RegistryInstallError,
    RegistryVerificationError,
)

# Restrict transport to explicit web schemes to avoid local/file fetch surprises.
_ALLOWED_REGISTRY_SCHEMES = {"http", "https"}
# Keep pack names URL-safe and path-traversal resistant.
_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PolicyPack:
    """A signed policy pack fetched from a remote policy registry."""

    name: str
    version: str
    policy_yaml: str
    manifest: dict[str, Any]
    signature: bytes
    public_key: bytes
    source: Optional[str] = None

    @property
    def policy_sha256(self) -> str:
        """Return the SHA-256 hash of the raw policy YAML bytes."""
        return hashlib.sha256(self.policy_yaml.encode("utf-8")).hexdigest()

    @property
    def manifest_sha256(self) -> str:
        """Return the SHA-256 hash of canonical manifest JSON bytes."""
        canonical = json.dumps(self.manifest, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def signed_payload(self) -> bytes:
        """Return canonical bytes used for Ed25519 signature verification."""
        payload = {
            "name": self.name,
            "version": self.version,
            "policy_yaml": self.policy_yaml,
            "manifest": self.manifest,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return canonical.encode("utf-8")


@dataclass(frozen=True)
class PolicyAuditResult:
    """Audit result for one installed policy pack on local disk."""

    name: str
    ok: bool
    verified: bool
    expected_sha256: Optional[str]
    actual_sha256: Optional[str]
    issues: tuple[str, ...]


class RegistryClient:
    """Client for installing and verifying signed policy packs from a registry."""

    def __init__(
        self,
        registry_url: str,
        policies_dir: Optional[Path] = None,
        lockfile_path: Optional[Path] = None,
        timeout_seconds: float = 10.0,
    ):
        """Initialize a registry client with local install and lockfile paths."""
        self._registry_url = self._normalize_registry_url(registry_url)
        home = Path.home()
        self._policies_dir = policies_dir or (home / ".megent" / "policies")
        self._lockfile_path = lockfile_path or (Path.cwd() / "megent.lock")
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _normalize_registry_url(registry_url: str) -> str:
        # Canonicalize base URL once and enforce trusted endpoint shape up front.
        normalized = registry_url.rstrip("/") + "/"
        parsed = urlparse(normalized)
        if parsed.scheme not in _ALLOWED_REGISTRY_SCHEMES or not parsed.netloc:
            raise RegistryFetchError(
                "Registry URL must use http(s) with a valid host "
                f"(received: {registry_url!r})"
            )
        return normalized

    @staticmethod
    def _validate_policy_name(name: str) -> str:
        # Names become URL path segments, so reject anything outside safe characters.
        if not _POLICY_NAME_RE.fullmatch(name):
            raise RegistryFetchError(
                "Policy pack name contains unsupported characters; use letters, "
                "numbers, dots, underscores, or dashes."
            )
        return name

    def _build_policy_endpoint(self, name: str, version: Optional[str]) -> str:
        # Encode the pack name before joining so special characters cannot alter path layout.
        safe_name = quote(self._validate_policy_name(name), safe="")
        endpoint = urljoin(self._registry_url, f"policies/{safe_name}")
        if version:
            endpoint = f"{endpoint}?{urlencode({'version': version})}"

        parsed = urlparse(endpoint)
        if parsed.scheme not in _ALLOWED_REGISTRY_SCHEMES or not parsed.netloc:
            raise RegistryFetchError(f"Resolved registry endpoint is invalid: {endpoint!r}")
        return endpoint

    @property
    def policies_dir(self) -> Path:
        """Return the local directory where policy packs are installed."""
        return self._policies_dir

    @property
    def lockfile_path(self) -> Path:
        """Return the path to the Megent policy lockfile."""
        return self._lockfile_path

    def fetch(self, name: str, version: Optional[str] = None) -> PolicyPack:
        """Fetch a policy pack payload from the configured registry endpoint."""
        endpoint = self._build_policy_endpoint(name=name, version=version)

        try:
            # Endpoint scheme/host are validated above before network access.
            with urlopen(endpoint, timeout=self._timeout_seconds) as response:  # nosec B310
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001
            raise RegistryFetchError(f"Failed to fetch policy pack '{name}': {exc}") from exc

        try:
            fetched_name = str(payload.get("name") or name)
            fetched_version = str(payload.get("version") or version or "latest")
            policy_yaml = str(payload["policy_yaml"])
            manifest = payload.get("manifest") or {}
            if not isinstance(manifest, dict):
                raise ValueError("manifest must be an object")
            signature_b64 = payload["signature"]
            public_key_b64 = payload["public_key"]

            # validate=True rejects non-base64 garbage early instead of silently truncating.
            signature = base64.b64decode(signature_b64, validate=True)
            public_key = base64.b64decode(public_key_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise RegistryFetchError(
                f"Registry response for '{name}' is missing required fields"
            ) from exc

        return PolicyPack(
            name=fetched_name,
            version=fetched_version,
            policy_yaml=policy_yaml,
            manifest=manifest,
            signature=signature,
            public_key=public_key,
            source=endpoint,
        )

    def verify_signature(self, pack: PolicyPack) -> bool:
        """Verify an Ed25519 signature for the canonical policy pack payload."""
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pack.public_key)
            public_key.verify(pack.signature, pack.signed_payload())
            return True
        except Exception as exc:  # noqa: BLE001
            raise RegistryVerificationError(
                f"Signature verification failed for '{pack.name}@{pack.version}'"
            ) from exc

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        verify: bool = True,
    ) -> PolicyPack:
        """Fetch and install a policy pack locally, optionally verifying signature."""
        pack = self.fetch(name=name, version=version)
        if verify:
            self.verify_signature(pack)

        destination = self._policies_dir / pack.name
        try:
            self._policies_dir.mkdir(parents=True, exist_ok=True)
            destination.parent.mkdir(parents=True, exist_ok=True)

            with TemporaryDirectory(prefix="megent-policy-") as tmp_dir:
                tmp_path = Path(tmp_dir)
                policy_path = tmp_path / "policy.yaml"
                manifest_path = tmp_path / "manifest.json"
                verified_marker_path = tmp_path / "verified"

                install_manifest = dict(pack.manifest)
                install_manifest.update(
                    {
                        "name": pack.name,
                        "version": pack.version,
                        "verified": verify,
                        "policy_sha256": pack.policy_sha256,
                        "manifest_sha256": pack.manifest_sha256,
                        "installed_at": _utc_now_iso(),
                        "source": pack.source,
                    }
                )

                policy_path.write_text(pack.policy_yaml, encoding="utf-8")
                manifest_path.write_text(
                    json.dumps(install_manifest, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                if verify:
                    verified_marker_path.write_text(pack.policy_sha256, encoding="utf-8")

                if destination.exists():
                    if destination.is_dir():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
                destination.mkdir(parents=True, exist_ok=True)

                files = ["policy.yaml", "manifest.json"]
                if verify:
                    files.append("verified")

                for filename in files:
                    source = tmp_path / filename
                    target = destination / filename
                    os.replace(source, target)

            self._update_lockfile(pack)
        except RegistryInstallError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RegistryInstallError(
                f"Failed to install policy pack '{pack.name}@{pack.version}'"
            ) from exc

        return pack

    def list_installed(self) -> list[dict[str, Any]]:
        """List installed packs discovered under the local policies directory."""
        if not self._policies_dir.exists():
            return []

        installed: list[dict[str, Any]] = []
        for entry in sorted(self._policies_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue

            manifest_path = entry / "manifest.json"
            verified_marker = entry / "verified"
            policy_path = entry / "policy.yaml"

            if not manifest_path.exists() or not policy_path.exists():
                continue

            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise RegistryInstallError(
                    f"Installed manifest is invalid JSON: {manifest_path}"
                ) from exc

            installed.append(
                {
                    "name": str(manifest.get("name") or entry.name),
                    "version": str(manifest.get("version") or "unknown"),
                    "publisher": str(manifest.get("publisher") or "unknown"),
                    "path": str(entry),
                    "verified": verified_marker.exists(),
                    "policy_sha256": str(manifest.get("policy_sha256") or ""),
                }
            )

        return installed

    def verify_installed(self, name: str) -> bool:
        """Re-verify an installed pack against registry signature and pack contents."""
        destination = self._policies_dir / name
        policy_path = destination / "policy.yaml"
        manifest_path = destination / "manifest.json"

        if not policy_path.exists() or not manifest_path.exists():
            raise RegistryInstallError(
                f"Policy pack '{name}' is not installed at {destination}"
            )

        try:
            local_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RegistryInstallError(
                f"Installed manifest is invalid JSON: {manifest_path}"
            ) from exc

        version = local_manifest.get("version")
        local_policy = policy_path.read_text(encoding="utf-8")
        local_sha = hashlib.sha256(local_policy.encode("utf-8")).hexdigest()

        pack = self.fetch(name=name, version=str(version) if version else None)
        self.verify_signature(pack)

        if local_sha != pack.policy_sha256:
            raise RegistryVerificationError(
                f"Installed policy pack '{name}' does not match signed registry content"
            )

        verified_marker = destination / "verified"
        verified_marker.write_text(local_sha, encoding="utf-8")
        local_manifest["verified"] = True
        local_manifest["verified_at"] = _utc_now_iso()
        manifest_path.write_text(
            json.dumps(local_manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return True

    def remove(self, name: str) -> bool:
        """Remove an installed policy pack and corresponding lockfile entry."""
        destination = self._policies_dir / name
        if not destination.exists():
            return False

        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()

        if self._lockfile_path.exists():
            try:
                lock = json.loads(self._lockfile_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise RegistryInstallError(
                    f"Lockfile is invalid JSON: {self._lockfile_path}"
                ) from exc

            policies = lock.get("policies")
            if isinstance(policies, dict) and name in policies:
                del policies[name]
                lock["updated_at"] = _utc_now_iso()
                self._lockfile_path.write_text(
                    json.dumps(lock, indent=2, sort_keys=True),
                    encoding="utf-8",
                )

        return True

    def audit_installed(self) -> list[PolicyAuditResult]:
        """Audit installed packs for verification marker and lockfile SHA integrity."""
        if not self._policies_dir.exists():
            return []

        lock_policies: dict[str, Any] = {}
        lock_issue: Optional[str] = None
        if self._lockfile_path.exists():
            try:
                lock = json.loads(self._lockfile_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                lock_issue = f"lockfile invalid JSON: {self._lockfile_path}"
            else:
                policies = lock.get("policies")
                if isinstance(policies, dict):
                    lock_policies = policies
                else:
                    lock_issue = f"lockfile missing 'policies' mapping: {self._lockfile_path}"
        else:
            lock_issue = f"lockfile not found: {self._lockfile_path}"

        results: list[PolicyAuditResult] = []
        for entry in sorted(self._policies_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue

            issues: list[str] = []
            policy_path = entry / "policy.yaml"
            verified = (entry / "verified").exists()
            expected_sha: Optional[str] = None
            actual_sha: Optional[str] = None

            if not verified:
                issues.append("missing verified marker")

            if policy_path.exists():
                content = policy_path.read_text(encoding="utf-8")
                actual_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            else:
                issues.append("missing policy.yaml")

            if lock_issue is not None:
                issues.append(lock_issue)
            else:
                lock_entry = lock_policies.get(entry.name)
                if not isinstance(lock_entry, dict):
                    issues.append("missing lockfile entry")
                else:
                    sha = lock_entry.get("sha256")
                    if isinstance(sha, str) and sha:
                        expected_sha = sha
                    else:
                        issues.append("missing lockfile sha256")

            if expected_sha and actual_sha and expected_sha != actual_sha:
                issues.append("lockfile sha256 mismatch")

            results.append(
                PolicyAuditResult(
                    name=entry.name,
                    ok=len(issues) == 0,
                    verified=verified,
                    expected_sha256=expected_sha,
                    actual_sha256=actual_sha,
                    issues=tuple(issues),
                )
            )

        return results

    def _update_lockfile(self, pack: PolicyPack) -> None:
        """Update or create the policy lockfile for an installed pack."""
        lock = {
            "version": 1,
            "updated_at": _utc_now_iso(),
            "policies": {},
        }

        if self._lockfile_path.exists():
            try:
                lock = json.loads(self._lockfile_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise RegistryInstallError(
                    f"Lockfile is invalid JSON: {self._lockfile_path}"
                ) from exc

            if "policies" not in lock or not isinstance(lock["policies"], dict):
                lock["policies"] = {}

            lock["updated_at"] = _utc_now_iso()

        lock["policies"][pack.name] = {
            "version": pack.version,
            "sha256": pack.policy_sha256,
            "manifest_sha256": pack.manifest_sha256,
            "installed_at": _utc_now_iso(),
        }

        self._lockfile_path.parent.mkdir(parents=True, exist_ok=True)
        self._lockfile_path.write_text(
            json.dumps(lock, indent=2, sort_keys=True),
            encoding="utf-8",
        )