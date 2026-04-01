from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .exceptions import PolicyInstallError, PolicyVerificationError
from .policy import Policy, load_policy

REGISTRY_BASE_URL = "https://registry.megent.dev/v1"
POLICIES_DIRNAME = "policies"
LOCKFILE_NAME = "megent.lock"


@dataclass
class PolicyPack:
    name: str
    version: str
    publisher: str
    verified: bool
    policy: Policy
    signature: Optional[str]
    public_key: Optional[str]


class RegistryClient:
    BASE_URL = REGISTRY_BASE_URL

    def __init__(self, base_url: Optional[str] = None, policy_home: Optional[Path] = None):
        self.base_url = (base_url or self.BASE_URL).rstrip("/")
        self.policy_home = policy_home or (Path.home() / ".megent")

    @property
    def policies_dir(self) -> Path:
        return self.policy_home / POLICIES_DIRNAME

    @property
    def lockfile_path(self) -> Path:
        return self.policy_home / LOCKFILE_NAME

    def fetch(self, name: str, version: str = "latest") -> PolicyPack:
        url = f"{self.base_url}/policies/{name}/{version}.json"
        try:
            with urllib.request.urlopen(url) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise PolicyInstallError(f"Unable to fetch policy '{name}@{version}': {exc}") from exc
        try:
            yaml_text = str(payload["policy_yaml"])
        except KeyError as exc:
            raise PolicyInstallError(f"Invalid registry payload for '{name}@{version}'") from exc

        policy = load_policy_from_text(yaml_text)
        return PolicyPack(
            name=str(payload.get("name", name)),
            version=str(payload.get("version", version)),
            publisher=str(payload.get("publisher", "")),
            verified=False,
            policy=policy,
            signature=payload.get("signature"),
            public_key=payload.get("public_key"),
        )

    def verify_signature(self, pack: PolicyPack, policy_yaml: Optional[str] = None) -> bool:
        if not pack.signature or not pack.public_key:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise PolicyVerificationError("cryptography is required for policy verification")

        if policy_yaml is None:
            policy_path = self.policies_dir / pack.name / "policy.yaml"
            policy_yaml = policy_path.read_text(encoding="utf-8")

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pack.public_key))
        signature = bytes.fromhex(pack.signature)
        try:
            public_key.verify(signature, policy_yaml.encode("utf-8"))
            return True
        except Exception:
            return False

    def install(self, name: str, version: str = "latest", verify: bool = True) -> PolicyPack:
        pack, policy_yaml = self._fetch_with_yaml(name=name, version=version)
        if verify and not self.verify_signature(pack, policy_yaml=policy_yaml):
            raise PolicyVerificationError(f"Signature verification failed for policy '{name}'")

        target_dir = self.policies_dir / pack.name
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "policy.yaml").write_text(policy_yaml, encoding="utf-8")

        manifest = {
            "name": pack.name,
            "version": pack.version,
            "publisher": pack.publisher,
            "signature": pack.signature,
            "public_key": pack.public_key,
            "verified": bool(verify and self.verify_signature(pack, policy_yaml=policy_yaml)),
        }
        (target_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        verified_file = target_dir / "verified"
        if manifest["verified"]:
            verified_file.write_text("", encoding="utf-8")
        elif verified_file.exists():
            verified_file.unlink()

        installed_pack = self._pack_from_disk(pack.name)
        self._update_lock(installed_pack)
        return installed_pack

    def list_installed(self) -> list[PolicyPack]:
        if not self.policies_dir.exists():
            return []
        packs: list[PolicyPack] = []
        for entry in sorted(self.policies_dir.iterdir()):
            if entry.is_dir() and (entry / "manifest.json").exists() and (entry / "policy.yaml").exists():
                packs.append(self._pack_from_disk(entry.name))
        return packs

    def remove(self, name: str) -> bool:
        target_dir = self.policies_dir / name
        if not target_dir.exists():
            return False
        for child in sorted(target_dir.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            else:
                child.rmdir()
        target_dir.rmdir()
        self._remove_from_lock(name)
        return True

    def info(self, name: str) -> PolicyPack:
        return self._pack_from_disk(name)

    def verify_installed(self, name: str) -> bool:
        pack = self._pack_from_disk(name)
        return self.verify_signature(pack)

    def _fetch_with_yaml(self, name: str, version: str) -> tuple[PolicyPack, str]:
        url = f"{self.base_url}/policies/{name}/{version}.json"
        try:
            with urllib.request.urlopen(url) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise PolicyInstallError(f"Unable to fetch policy '{name}@{version}': {exc}") from exc
        if "policy_yaml" not in payload:
            raise PolicyInstallError(f"Invalid registry payload for '{name}@{version}'")
        policy_yaml = str(payload["policy_yaml"])
        policy = load_policy_from_text(policy_yaml)
        pack = PolicyPack(
            name=str(payload.get("name", name)),
            version=str(payload.get("version", version)),
            publisher=str(payload.get("publisher", "")),
            verified=False,
            policy=policy,
            signature=payload.get("signature"),
            public_key=payload.get("public_key"),
        )
        return pack, policy_yaml

    def _pack_from_disk(self, name: str) -> PolicyPack:
        policy_dir = self.policies_dir / name
        manifest_path = policy_dir / "manifest.json"
        policy_path = policy_dir / "policy.yaml"
        if not manifest_path.exists() or not policy_path.exists():
            raise PolicyInstallError(f"Policy '{name}' is not installed")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        policy = load_policy(str(policy_path))
        policy_yaml = policy_path.read_text(encoding="utf-8")
        verified = bool((policy_dir / "verified").exists())
        pack = PolicyPack(
            name=str(manifest.get("name", name)),
            version=str(manifest.get("version", "unknown")),
            publisher=str(manifest.get("publisher", "")),
            verified=verified,
            policy=policy,
            signature=manifest.get("signature"),
            public_key=manifest.get("public_key"),
        )
        if pack.signature and pack.public_key:
            pack.verified = self.verify_signature(pack, policy_yaml=policy_yaml)
        return pack

    def _update_lock(self, pack: PolicyPack) -> None:
        self.policy_home.mkdir(parents=True, exist_ok=True)
        lock_data = {"version": "1", "packages": {}}
        if self.lockfile_path.exists():
            try:
                lock_data = json.loads(self.lockfile_path.read_text(encoding="utf-8"))
            except Exception:
                lock_data = {"version": "1", "packages": {}}
        packages = lock_data.setdefault("packages", {})
        policy_path = self.policies_dir / pack.name / "policy.yaml"
        sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        packages[pack.name] = {
            "version": pack.version,
            "publisher": pack.publisher,
            "verified": pack.verified,
            "sha256": sha256,
        }
        self.lockfile_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")

    def _remove_from_lock(self, name: str) -> None:
        if not self.lockfile_path.exists():
            return
        try:
            lock_data = json.loads(self.lockfile_path.read_text(encoding="utf-8"))
        except Exception:
            return
        packages = lock_data.get("packages", {})
        if name in packages:
            del packages[name]
            self.lockfile_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")


def load_policy_from_text(text: str) -> Policy:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise PolicyInstallError("Install PyYAML: pip install pyyaml") from exc

    raw = yaml.safe_load(text) or {}
    tools_raw: dict[str, Any] = raw.get("tools", {})
    from .policy import _parse_tool

    tools = {tool_name: _parse_tool(tool_name, cfg) for tool_name, cfg in tools_raw.items()}
    return Policy(
        version=str(raw.get("version", "1")),
        default_action=raw.get("default_action", "deny"),
        tools=tools,
        pii_mask=raw.get("pii_mask", []),
    )
