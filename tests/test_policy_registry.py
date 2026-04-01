from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from megent.cli import main
from megent.exceptions import PolicyVerificationError
from megent.policy import load_policy
from megent.registry import RegistryClient


def _registry_payload(name: str, version: str = "1.2.0") -> tuple[dict[str, str], str]:
    policy_data = {
        "version": "1",
        "default_action": "deny",
        "tools": {"billing_agent": {"allow": True}},
        "pii_mask": ["email"],
    }
    policy_yaml = yaml.safe_dump(policy_data)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(policy_yaml.encode("utf-8"))
    payload = {
        "name": name,
        "version": version,
        "publisher": "stripe",
        "policy_yaml": policy_yaml,
        "signature": signature.hex(),
        "public_key": public_key.public_bytes_raw().hex(),
    }
    return payload, policy_yaml


class _FakeResponse:
    def __init__(self, payload: dict[str, str]):
        self._payload = payload

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, exc_type, exc, tb):  # type: ignore[no-untyped-def]
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_install_list_and_lockfile_updates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload, _ = _registry_payload("stripe")
    monkeypatch.setattr("urllib.request.urlopen", lambda url: _FakeResponse(payload))
    client = RegistryClient(policy_home=tmp_path / ".megent")

    pack = client.install("stripe", version="1.2.0")
    assert pack.name == "stripe"
    assert pack.verified is True

    installed = client.list_installed()
    assert len(installed) == 1
    assert installed[0].name == "stripe"
    assert installed[0].verified is True

    lock = json.loads((tmp_path / ".megent" / "megent.lock").read_text(encoding="utf-8"))
    assert lock["packages"]["stripe"]["version"] == "1.2.0"
    assert lock["packages"]["stripe"]["verified"] is True
    assert "sha256" in lock["packages"]["stripe"]


def test_named_policy_resolution_requires_verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    policy_dir = fake_home / ".megent" / "policies" / "stripe"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1", "default_action": "deny", "tools": {"billing_agent": {"allow": True}}}),
        encoding="utf-8",
    )
    (policy_dir / "manifest.json").write_text(
        json.dumps({"name": "stripe", "version": "1.0.0", "publisher": "stripe"}),
        encoding="utf-8",
    )

    with pytest.raises(PolicyVerificationError):
        load_policy("stripe")

    (policy_dir / "verified").write_text("", encoding="utf-8")
    policy = load_policy("stripe")
    assert policy.is_allowed("billing_agent") is True


def test_cli_policy_verify_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    payload, _ = _registry_payload("stripe")
    monkeypatch.setattr("urllib.request.urlopen", lambda url: _FakeResponse(payload))
    fake_home = tmp_path / "home"
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)

    assert main(["policy", "install", "stripe"]) == 0
    assert main(["policy", "verify", "stripe"]) == 0
    out = capsys.readouterr().out
    assert "installed stripe" in out
    assert "stripe: verified" in out

    policy_path = fake_home / ".megent" / "policies" / "stripe" / "policy.yaml"
    policy_path.write_text(policy_path.read_text(encoding="utf-8") + "\n# tampered", encoding="utf-8")
    assert main(["policy", "verify", "stripe"]) == 1
