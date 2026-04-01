from __future__ import annotations

from dataclasses import dataclass

import pytest

from megent.cli import main
from megent.exceptions import RegistryVerificationError


@dataclass
class _FakePack:
    name: str
    version: str


class _FakeClient:
    def __init__(self) -> None:
        self.install_calls: list[tuple[str, str | None, bool]] = []
        self.verify_should_fail = False
        self.audit_rows: list[object] = []

    def install(self, name: str, version: str | None = None, verify: bool = True) -> _FakePack:
        self.install_calls.append((name, version, verify))
        return _FakePack(name=name, version=version or "latest")

    def list_installed(self) -> list[dict[str, object]]:
        return []

    def verify_installed(self, name: str) -> bool:
        if self.verify_should_fail:
            raise RegistryVerificationError("invalid signature")
        return True

    def remove(self, name: str) -> bool:
        return True

    def audit_installed(self) -> list[object]:
        return self.audit_rows


@dataclass
class _FakeAuditRow:
    name: str
    ok: bool
    issues: tuple[str, ...]


def test_cli_policy_install_no_verify_passes_verify_false(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient()

    import megent.cli as cli_module

    monkeypatch.setattr(cli_module, "_client_for_args", lambda args: fake)

    exit_code = main(["policy", "install", "stripe", "--no-verify"])
    assert exit_code == 0
    assert fake.install_calls == [("stripe", None, False)]


def test_cli_policy_verify_returns_exit_code_1_for_invalid_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    fake.verify_should_fail = True

    import megent.cli as cli_module

    monkeypatch.setattr(cli_module, "_client_for_args", lambda args: fake)

    exit_code = main(["policy", "verify", "stripe"])
    assert exit_code == 1


def test_cli_policy_audit_returns_zero_when_all_rows_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    fake.audit_rows = [_FakeAuditRow(name="stripe", ok=True, issues=())]

    import megent.cli as cli_module

    monkeypatch.setattr(cli_module, "_client_for_args", lambda args: fake)

    exit_code = main(["policy", "audit"])
    assert exit_code == 0


def test_cli_policy_audit_returns_one_when_any_row_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    fake.audit_rows = [
        _FakeAuditRow(name="stripe", ok=True, issues=()),
        _FakeAuditRow(name="community", ok=False, issues=("missing verified marker",)),
    ]

    import megent.cli as cli_module

    monkeypatch.setattr(cli_module, "_client_for_args", lambda args: fake)

    exit_code = main(["policy", "audit"])
    assert exit_code == 1