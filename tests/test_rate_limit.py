from __future__ import annotations

import logging

import pytest

from megent import ratelimit
from megent.audit import AuditLogger
from megent.exceptions import PolicyViolation
from megent.policy import Policy
from megent.ratelimit import RateLimitPolicy
from megent.runtime import Runtime


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch):
    """A controllable clock for the sliding window."""
    state = {"t": 1000.0}
    monkeypatch.setattr(ratelimit, "_now", lambda: state["t"])
    return state


def test_allows_up_to_limit_then_denies(clock) -> None:
    rl = RateLimitPolicy(max_calls=3, window_seconds=60)

    assert rl.check("t", {}, "agent-a")["action"] == "allow"
    assert rl.check("t", {}, "agent-a")["action"] == "allow"
    assert rl.check("t", {}, "agent-a")["action"] == "allow"

    denied = rl.check("t", {}, "agent-a")
    assert denied["action"] == "deny"
    assert "rate limit exceeded" in denied["reason"]


def test_limit_is_per_identity(clock) -> None:
    rl = RateLimitPolicy(max_calls=1, window_seconds=60)

    assert rl.check("t", {}, "agent-a")["action"] == "allow"
    # A different identity has its own bucket.
    assert rl.check("t", {}, "agent-b")["action"] == "allow"
    # agent-a is now over its limit.
    assert rl.check("t", {}, "agent-a")["action"] == "deny"


def test_window_slides_forward(clock) -> None:
    rl = RateLimitPolicy(max_calls=2, window_seconds=60)

    assert rl.check("t", {}, "a")["action"] == "allow"  # at t=1000
    assert rl.check("t", {}, "a")["action"] == "allow"  # at t=1000
    assert rl.check("t", {}, "a")["action"] == "deny"

    # Advance past the window; the earlier calls fall out and calls resume.
    clock["t"] += 61
    assert rl.check("t", {}, "a")["action"] == "allow"


def test_denied_calls_do_not_extend_window(clock) -> None:
    rl = RateLimitPolicy(max_calls=1, window_seconds=60)

    assert rl.check("t", {}, "a")["action"] == "allow"  # t=1000
    clock["t"] += 30  # t=1030
    assert rl.check("t", {}, "a")["action"] == "deny"  # blocked, not recorded
    clock["t"] += 31  # t=1061, original call (t=1000) has aged out
    assert rl.check("t", {}, "a")["action"] == "allow"


def test_missing_identity_falls_back_to_default(clock) -> None:
    rl = RateLimitPolicy(max_calls=1, window_seconds=60)
    assert rl.check("t", {}, None)["action"] == "allow"
    assert rl.check("t", {}, None)["action"] == "deny"


def test_zero_max_calls_denies_everything(clock) -> None:
    rl = RateLimitPolicy(max_calls=0, window_seconds=60)
    assert rl.check("t", {}, "a")["action"] == "deny"


def test_invalid_config_rejected() -> None:
    with pytest.raises(ValueError):
        RateLimitPolicy(max_calls=-1)
    with pytest.raises(ValueError):
        RateLimitPolicy(max_calls=5, window_seconds=0)


def test_report_reflects_state(clock) -> None:
    rl = RateLimitPolicy(max_calls=2, window_seconds=60)
    rl.check("t", {}, "a")
    report = rl.report("a")
    assert report.count == 1
    assert report.exceeded is False

    rl.check("t", {}, "a")
    assert rl.report("a").exceeded is True


def test_reset_clears_bucket(clock) -> None:
    rl = RateLimitPolicy(max_calls=1, window_seconds=60)
    assert rl.check("t", {}, "a")["action"] == "allow"
    assert rl.check("t", {}, "a")["action"] == "deny"
    rl.reset("a")
    assert rl.check("t", {}, "a")["action"] == "allow"


# ---------------------------------------------------------------------------
# Runtime integration: deny-by-default + audit trail
# ---------------------------------------------------------------------------

def _allow_all_policy() -> Policy:
    return Policy(default_action="allow", tools={})


def test_runtime_enforces_rate_limit_and_audits_block(clock, caplog) -> None:
    audit = AuditLogger()
    runtime = Runtime(
        policy=_allow_all_policy(),
        audit=audit,
        rate_limit=RateLimitPolicy(max_calls=1, window_seconds=60),
    )

    # First call goes through.
    runtime.enforce("send_email", {"to": "ops@example.com"})

    # Second call is blocked by the rate limit and logged to the audit trail.
    with caplog.at_level(logging.INFO, logger="megent.audit"):
        with pytest.raises(PolicyViolation, match="rate limit exceeded"):
            runtime.enforce("send_email", {"to": "ops@example.com"})

    blocks = [r.getMessage() for r in caplog.records if '"event": "block"' in r.getMessage()]
    assert blocks, "expected a block audit event"
    assert "rate limit exceeded" in blocks[-1]


def test_runtime_rate_limit_masks_pii_in_audit(clock, caplog) -> None:
    policy = Policy(default_action="allow", pii_mask=["email"])
    runtime = Runtime(
        policy=policy,
        rate_limit=RateLimitPolicy(max_calls=1, window_seconds=60),
    )

    runtime.enforce("send_email", {"body": "reach me at jane@example.com"})
    with caplog.at_level(logging.INFO, logger="megent.audit"):
        with pytest.raises(PolicyViolation):
            runtime.enforce("send_email", {"body": "reach me at jane@example.com"})

    block_msgs = [r.getMessage() for r in caplog.records if '"event": "block"' in r.getMessage()]
    assert block_msgs
    assert "jane@example.com" not in block_msgs[-1]
