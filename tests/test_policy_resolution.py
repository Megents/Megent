from __future__ import annotations

from pathlib import Path

import pytest

from megent.exceptions import PolicyLoadError
from megent.policy import load_policy


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