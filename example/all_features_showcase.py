"""Show all Megent examples in one runnable script.

This script demonstrates:
- a basic runtime lifecycle demo
- loading policy packs from an external policy repository
- composing multiple policies together
- Megent runtime features like awareness, budget, HITL, and graceful stop
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# When run as `python example/all_features_showcase.py`, Python only adds
# `example/` to sys.path, so we insert the project root first to load the
# local package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import megent as mg
from megent.audit import AuditEvent, AuditLogger
from megent.awareness import (
	AwarenessGuard,
	EscalationDetector,
	ExfiltrationDetector,
	LoopDetector,
	ShadowDetector,
)
from megent.budget import BudgetPolicy
from megent.exceptions import PolicyViolation
from megent.hitl import HITLPolicy, ReviewOutcome, ReviewRequest, ReviewVerdict
from megent.policy import compose_policies, load_policy
from megent.stop import GracefulStop


class ConsoleLifecycleLogger(AuditLogger):
	"""Print ordered runtime lifecycle events for each tool call."""

	def log(self, event: AuditEvent) -> None:
		print(
			"[lifecycle]"
			f" event={event.event}"
			f" tool={event.tool}"
			f" agent={event.agent_id}"
			f" masked={event.masked_fields}"
			f" reason={event.reason}"
		)
		print(f"[lifecycle] args={event.args}")


def _section(title: str) -> None:
	print(f"\n=== {title} ===")


def _write_policy_file(path: Path) -> None:
	policy_text = (
		"version: \"1\"\n"
		"default_action: deny\n"
		"\n"
		"tools:\n"
		"  send_email:\n"
		"    allow: true\n"
		"    pii_mask: [email, phone]\n"
		"  delete_all_data:\n"
		"    allow: false\n"
	)
	path.write_text(policy_text, encoding="utf-8")


def _candidate_policy_roots() -> list[Path]:
	candidates: list[Path] = []

	env_repo = os.environ.get("MEGENT_POLICY_REPO")
	if env_repo:
		candidates.append(Path(env_repo))

	candidates.extend(
		[
			Path.home() / "Downloads" / "megent-policies",
			Path.home() / "Downloads" / "megent-policy-workspace",
			Path(__file__).resolve().parents[2] / "megent-policies",
			Path(__file__).resolve().parents[2] / "megent-policy-workspace",
		]
	)

	unique_candidates: list[Path] = []
	for candidate in candidates:
		if candidate.exists() and candidate not in unique_candidates:
			unique_candidates.append(candidate)
	return unique_candidates


def _discover_policy_files(repo_root: Path) -> list[Path]:
	policies_dir = repo_root / "policies"
	if not policies_dir.exists():
		return []
	return sorted(policies_dir.rglob("policy.yaml"))


def _pack_name(policy_path: Path, repo_root: Path) -> str:
	rel_path = policy_path.parent.relative_to(repo_root / "policies")
	return "/".join(rel_path.parts)


def show_basic_lifecycle_demo() -> None:
	_section("Basic Lifecycle Demo")

	with tempfile.TemporaryDirectory() as temp_dir:
		policy_path = Path(temp_dir) / "megent.yaml"
		_write_policy_file(policy_path)

		runtime = mg.Runtime(policy_path=str(policy_path), audit=ConsoleLifecycleLogger())

		def send_email(to: str, body: str) -> str:
			print(f"[tool] send_email executed to={to}")
			return "ok"

		def delete_all_data(target: str) -> str:
			print(f"[tool] delete_all_data executed target={target}")
			return "deleted"

		safe_send = mg.wrap(send_email, runtime=runtime, tool_name="send_email")
		safe_delete = mg.wrap(delete_all_data, runtime=runtime, tool_name="delete_all_data")

		print("Allowed call with masking:")
		result = safe_send(
			"ops@example.com",
			"Contact me at jane.doe@example.com or +1 555 222 3333",
		)
		print("Result:", result)

		print("Blocked call:")
		try:
			safe_delete("prod-db")
		except PolicyViolation as exc:
			print("Blocked:", exc)


def show_policy_repo_examples() -> None:
	_section("Policy Repository Examples")

	roots = _candidate_policy_roots()
	if not roots:
		print("No external policy repository was found.")
		return

	for repo_root in roots:
		print(f"Policy repo: {repo_root}")
		policy_files = _discover_policy_files(repo_root)
		if not policy_files:
			print("  No policy.yaml files found.")
			continue

		for policy_path in policy_files:
			try:
				policy = load_policy(str(policy_path))
			except Exception as exc:  # noqa: BLE001
				print(f"  - {policy_path.relative_to(repo_root)} -> load failed: {exc}")
				continue

			print(
				f"  - {policy.name}"
				f" | version={policy.version}"
				f" | default={policy.default_action}"
				f" | source={policy_path.relative_to(repo_root)}"
			)

			example_path = policy_path.parent / "example.py"
			if example_path.exists():
				print(f"    example: {example_path.relative_to(repo_root)}")


def show_policy_composition() -> None:
	_section("Policy Composition")

	roots = _candidate_policy_roots()
	if not roots:
		print("No external policy repository found to compose.")
		return

	repo_root = roots[0]
	policy_files = _discover_policy_files(repo_root)
	if len(policy_files) < 2:
		print("Need at least two policy packs to demonstrate composition.")
		return

	pack_names = [_pack_name(path, repo_root) for path in policy_files[:2]]
	print("Composing:", ", ".join(pack_names))

	try:
		composed = compose_policies(*pack_names, policy_repo=str(repo_root))
	except Exception as exc:  # noqa: BLE001
		print("Compose failed:", exc)
		return

	print("Composed policy:", composed.name)
	print("Rules:", len(composed.rules))
	print("PII fields:", composed.pii_mask)


def show_runtime_features() -> None:
	_section("Runtime Features")

	awareness = AwarenessGuard(
		[ExfiltrationDetector(), LoopDetector(), EscalationDetector(), ShadowDetector()],
		on_alert="allow",
	)
	print("Awareness 1:", awareness.evaluate("get_customer_profile", {"customer": "jane@example.com"}))
	print("Awareness 2:", awareness.evaluate("send_email", {"body": "jane@example.com"}))

	budget = BudgetPolicy(max_calls=2, on_exceeded="stop")
	print("Budget 1:", budget.evaluate("send_email", {"body": "hello"}))
	print("Budget 2:", budget.evaluate("send_email", {"body": "hello again"}))

	def reviewer(request: ReviewRequest) -> ReviewOutcome:
		print(f"HITL review requested for {request.tool_name}")
		return ReviewOutcome(verdict=ReviewVerdict.ALLOW, feedback="approved in demo", reviewer="demo")

	hitl = HITLPolicy(["dangerous_call"], reviewer=reviewer)
	print("HITL:", hitl.evaluate("dangerous_call", {"target": "prod-db"}))

	stopper = GracefulStop(["delete_all_data"], reason="demo stop")
	print("Graceful stop:", stopper.evaluate("delete_all_data", {}))


def main() -> None:
	show_basic_lifecycle_demo()
	show_policy_repo_examples()
	show_policy_composition()
	show_runtime_features()


if __name__ == "__main__":
	main()
