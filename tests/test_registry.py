from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from megent.exceptions import RegistryVerificationError
from megent.registry import RegistryClient, PolicyPack


def _make_signed_pack(name: str = "stripe", version: str = "1.2.3") -> PolicyPack:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = {
        "publisher": "stripe",
        "description": "Official Stripe policy pack",
    }
    policy_yaml = "version: '1'\ndefault_action: deny\ntools:\n  charge_customer:\n    allow: true\n"

    unsigned = PolicyPack(
        name=name,
        version=version,
        policy_yaml=policy_yaml,
        manifest=manifest,
        signature=b"",
        public_key=public_key,
        source="https://registry.example/policies/stripe",
    )
    signature = private_key.sign(unsigned.signed_payload())
    return PolicyPack(
        name=name,
        version=version,
        policy_yaml=policy_yaml,
        manifest=manifest,
        signature=signature,
        public_key=public_key,
        source=unsigned.source,
    )


def test_install_happy_path_creates_policy_layout_and_lockfile(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )

    pack = _make_signed_pack()

    # Avoid network in test by stubbing fetch to return a deterministic signed pack.
    client.fetch = lambda name, version=None: pack  # type: ignore[method-assign]

    installed = client.install("stripe")

    assert installed.name == "stripe"
    assert installed.version == "1.2.3"

    installed_dir = policies_dir / "stripe"
    assert (installed_dir / "policy.yaml").exists()
    assert (installed_dir / "manifest.json").exists()
    assert (installed_dir / "verified").exists()

    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    assert lock["policies"]["stripe"]["version"] == "1.2.3"
    assert lock["policies"]["stripe"]["sha256"] == installed.policy_sha256

    installed_list = client.list_installed()
    assert len(installed_list) == 1
    assert installed_list[0]["name"] == "stripe"
    assert installed_list[0]["verified"] is True


def test_install_fails_closed_when_signature_verification_fails(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )

    pack = _make_signed_pack()
    tampered = PolicyPack(
        name=pack.name,
        version=pack.version,
        policy_yaml=pack.policy_yaml + "# tampered\n",
        manifest=pack.manifest,
        signature=pack.signature,
        public_key=pack.public_key,
        source=pack.source,
    )

    client.fetch = lambda name, version=None: tampered  # type: ignore[method-assign]

    with pytest.raises(RegistryVerificationError):
        client.install("stripe")

    assert not (policies_dir / "stripe").exists()
    assert not lockfile.exists()


def test_fetch_parses_registry_payload_from_http_response(monkeypatch: pytest.MonkeyPatch) -> None:
    pack = _make_signed_pack()
    payload = {
        "name": pack.name,
        "version": pack.version,
        "policy_yaml": pack.policy_yaml,
        "manifest": pack.manifest,
        "signature": base64.b64encode(pack.signature).decode("ascii"),
        "public_key": base64.b64encode(pack.public_key).decode("ascii"),
    }

    class _FakeResponse:
        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self, *args, **kwargs) -> bytes:
            return json.dumps(payload).encode("utf-8")

    def _fake_urlopen(endpoint: str, timeout: float) -> _FakeResponse:
        assert endpoint.startswith("https://registry.example/policies/stripe")
        assert timeout == 10.0
        return _FakeResponse()

    import megent.registry as registry_module

    monkeypatch.setattr(registry_module, "urlopen", _fake_urlopen)

    client = RegistryClient(registry_url="https://registry.example/")
    fetched = client.fetch("stripe")
    assert fetched.name == "stripe"
    assert fetched.version == "1.2.3"
    assert client.verify_signature(fetched) is True


def test_install_no_verify_skips_verified_marker(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )
    pack = _make_signed_pack()
    client.fetch = lambda name, version=None: pack  # type: ignore[method-assign]

    client.install("stripe", verify=False)

    installed_dir = policies_dir / "stripe"
    assert (installed_dir / "policy.yaml").exists()
    assert (installed_dir / "manifest.json").exists()
    assert not (installed_dir / "verified").exists()


def test_verify_installed_and_remove_update_local_state(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )
    pack = _make_signed_pack()
    client.fetch = lambda name, version=None: pack  # type: ignore[method-assign]

    client.install("stripe", verify=False)
    assert (policies_dir / "stripe" / "verified").exists() is False

    assert client.verify_installed("stripe") is True
    assert (policies_dir / "stripe" / "verified").exists() is True

    assert client.remove("stripe") is True
    assert not (policies_dir / "stripe").exists()

    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    assert "stripe" not in lock.get("policies", {})


def test_audit_installed_ok_when_verified_and_lock_sha_matches(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )
    pack = _make_signed_pack()
    client.fetch = lambda name, version=None: pack  # type: ignore[method-assign]
    client.install("stripe")

    results = client.audit_installed()
    assert len(results) == 1
    assert results[0].name == "stripe"
    assert results[0].ok is True
    assert results[0].issues == ()


def test_audit_installed_fails_for_missing_verified_and_sha_mismatch(tmp_path: Path) -> None:
    policies_dir = tmp_path / "policies"
    lockfile = tmp_path / "megent.lock"
    client = RegistryClient(
        registry_url="https://registry.example/",
        policies_dir=policies_dir,
        lockfile_path=lockfile,
    )
    pack = _make_signed_pack()
    client.fetch = lambda name, version=None: pack  # type: ignore[method-assign]
    client.install("stripe")

    # Break integrity: remove marker and mutate policy without updating lockfile.
    (policies_dir / "stripe" / "verified").unlink()
    (policies_dir / "stripe" / "policy.yaml").write_text(
        pack.policy_yaml + "# changed\n",
        encoding="utf-8",
    )

    results = client.audit_installed()
    assert len(results) == 1
    assert results[0].ok is False
    assert "missing verified marker" in results[0].issues
    assert "lockfile sha256 mismatch" in results[0].issues