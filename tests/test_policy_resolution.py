from __future__ import annotations

from pathlib import Path

import pytest

from megent.exceptions import PolicyLoadError
from megent.policy import compose_policies, load_policy


def test_load_policy_resolves_verified_named_pack(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    pack_dir = home / ".megent" / "policies" / "stripe"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "policy.yaml").write_text(
        "version: '1'\ndefault_action: deny\ntools:\n  charge:\n    allow: true\n",
        encoding="utf-8",
    )
    (pack_dir / "verified").write_text("ok", encoding="utf-8")

    monkeypatch.setattr(Path, "home", lambda: home)

    policy = load_policy("stripe")
    assert policy.is_allowed("charge") is True
    assert policy.is_allowed("delete_everything") is False


def test_load_policy_raises_for_unverified_named_pack(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    pack_dir = home / ".megent" / "policies" / "stripe"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "policy.yaml").write_text("default_action: deny\n", encoding="utf-8")

    monkeypatch.setattr(Path, "home", lambda: home)

    with pytest.raises(PolicyLoadError, match="not verified"):
        load_policy("stripe")


def test_load_policy_raises_for_unverified_direct_pack_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    pack_dir = home / ".megent" / "policies" / "stripe"
    pack_dir.mkdir(parents=True, exist_ok=True)
    policy_path = pack_dir / "policy.yaml"
    policy_path.write_text("default_action: deny\n", encoding="utf-8")

    monkeypatch.setattr(Path, "home", lambda: home)

    with pytest.raises(PolicyLoadError, match="not verified"):
        load_policy(str(policy_path))


def test_load_policy_env_var_named_pack(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    pack_dir = home / ".megent" / "policies" / "payments"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "policy.yaml").write_text(
        "default_action: allow\n",
        encoding="utf-8",
    )
    (pack_dir / "verified").write_text("ok", encoding="utf-8")

    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("MEGENT_POLICY", "payments")

    policy = load_policy()
    assert policy.is_allowed("anything") is True


def test_load_policy_raises_when_default_action_is_invalid(tmp_path: Path) -> None:
    policy_path = tmp_path / "bad-default.yaml"
    policy_path.write_text("default_action: maybe\n", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="default_action"):
        load_policy(str(policy_path))


def test_load_policy_raises_when_tools_is_not_mapping(tmp_path: Path) -> None:
    policy_path = tmp_path / "bad-tools.yaml"
    policy_path.write_text("tools:\n  - send_email\n", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="'tools' must be a mapping"):
        load_policy(str(policy_path))


def test_load_policy_raises_when_pii_mask_is_not_list(tmp_path: Path) -> None:
    policy_path = tmp_path / "bad-pii.yaml"
    policy_path.write_text("pii_mask: email\n", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="pii_mask"):
        load_policy(str(policy_path))


def test_load_policy_can_resolve_pack_from_external_policy_repo(tmp_path: Path) -> None:
description: Read only policy
    repo_root = tmp_path / "megent-policies"
    pack_dir = repo_root / "policies" / "access-control" / "read-only"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (repo_root / "registry.json").write_text(
        """
{
    "version": "1.0",
    "updated": "2026-04-17",
    "policies": [
        {
            "name": "access-control/read-only",
            "version": "0.1.0",
            "path": "policies/access-control/read-only"
        }
    ]
}
""".strip(),
        encoding="utf-8",
    )
    (pack_dir / "policy.yaml").write_text(
        """
megent: "1.0"
name: access-control/read-only
version: 0.1.0
description: Read only policy
rules:
  - id: deny-write
    tool: "megent:fs.write"
    action: deny
""".strip()
        + "\n",
        encoding="utf-8",
    )

    policy = load_policy(policy_name="access-control/read-only", policy_repo=str(repo_root))
    assert policy.name == "access-control/read-only"
    assert policy.is_allowed("fs.write") is False


def test_compose_policies_combines_multiple_packs(tmp_path: Path) -> None:
    repo_root = tmp_path / "megent-policies"
    access_pack = repo_root / "policies" / "access-control" / "read-only"
    pii_pack = repo_root / "policies" / "data-protection" / "pii-strict"
    access_pack.mkdir(parents=True, exist_ok=True)
    pii_pack.mkdir(parents=True, exist_ok=True)
    (repo_root / "registry.json").write_text(
        """
{
    "version": "1.0",
    "updated": "2026-04-17",
    "policies": [
        {"name": "access-control/read-only", "path": "policies/access-control/read-only"},
        {"name": "data-protection/pii-strict", "path": "policies/data-protection/pii-strict"}
    ]
}
""".strip(),
        encoding="utf-8",
    )
    (access_pack / "policy.yaml").write_text(
        """
megent: "1.0"
name: access-control/read-only
version: 0.1.0
rules:
  - id: deny-write
    tool: "megent:fs.write"
    action: deny
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (pii_pack / "policy.yaml").write_text(
        """
megent: "1.0"
name: data-protection/pii-strict
version: 0.1.0
rules:
  - id: mask-pii
    tool: "*"
    condition: input_contains_pii
    action: mask
    metadata:
      patterns: [email]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    policy = compose_policies(
        "access-control/read-only",
        "data-protection/pii-strict",
        policy_repo=str(repo_root),
    )

    assert policy.is_allowed("fs.write") is False
    masked = policy.evaluate("send_email", {"body": "person@example.com"})
    assert masked["action"] == "allow"
    assert "[REDACTED]" in str(masked["args"])