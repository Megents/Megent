from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

from .exceptions import RegistryError, RegistryVerificationError
from .registry import RegistryClient

DEFAULT_REGISTRY_URL = "https://registry.megent.dev/"


def _registry_url_from_args(args: argparse.Namespace) -> str:
    """Return registry URL from CLI args or environment with a sane default."""
    if getattr(args, "registry_url", None):
        return str(args.registry_url)
    return os.environ.get("MEGENT_REGISTRY_URL", DEFAULT_REGISTRY_URL)


def _client_for_args(args: argparse.Namespace) -> RegistryClient:
    """Build a registry client from parsed CLI arguments."""
    return RegistryClient(registry_url=_registry_url_from_args(args))


def _cmd_policy_install(args: argparse.Namespace) -> int:
    """Handle `megent policy install` command."""
    client = _client_for_args(args)
    verify = not args.no_verify
    pack = client.install(name=args.name, version=args.version, verify=verify)

    if verify:
        print(f"Installed and verified {pack.name}@{pack.version}")
    else:
        print(
            f"Installed {pack.name}@{pack.version} without verification. "
            f"Run `megent policy verify {pack.name}` before runtime usage."
        )
    return 0


def _cmd_policy_list(args: argparse.Namespace) -> int:
    """Handle `megent policy list` command."""
    client = _client_for_args(args)
    rows = client.list_installed()
    if not rows:
        print("No policy packs installed.")
        return 0

    print("NAME\tVERSION\tPUBLISHER\tVERIFIED")
    for row in rows:
        verified = "yes" if row.get("verified") else "no"
        print(
            f"{row.get('name', 'unknown')}\t"
            f"{row.get('version', 'unknown')}\t"
            f"{row.get('publisher', 'unknown')}\t"
            f"{verified}"
        )
    return 0


def _cmd_policy_verify(args: argparse.Namespace) -> int:
    """Handle `megent policy verify` command."""
    client = _client_for_args(args)
    client.verify_installed(args.name)
    print(f"Policy pack '{args.name}' verified successfully.")
    return 0


def _cmd_policy_remove(args: argparse.Namespace) -> int:
    """Handle `megent policy remove` command."""
    client = _client_for_args(args)
    removed = client.remove(args.name)
    if removed:
        print(f"Removed policy pack '{args.name}'.")
    else:
        print(f"Policy pack '{args.name}' is not installed.")
    return 0


def _cmd_policy_audit(args: argparse.Namespace) -> int:
    """Handle `megent policy audit` command."""
    client = _client_for_args(args)
    results = client.audit_installed()
    if not results:
        print("AUDIT_OK no installed policy packs found")
        return 0

    failed = 0
    for result in results:
        if result.ok:
            print(
                f"AUDIT_OK {result.name} verified=yes sha256=match"
            )
            continue

        failed += 1
        issues = "; ".join(result.issues)
        print(f"AUDIT_FAIL {result.name} {issues}")

    passed = len(results) - failed
    print(f"AUDIT_SUMMARY total={len(results)} passed={passed} failed={failed}")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the Megent CLI argument parser."""
    parser = argparse.ArgumentParser(prog="megent")
    subcommands = parser.add_subparsers(dest="command", required=True)

    policy_parser = subcommands.add_parser("policy", help="Manage policy packs")
    policy_parser.add_argument(
        "--registry-url",
        default=None,
        help="Registry base URL (default: MEGENT_REGISTRY_URL or built-in default)",
    )
    policy_subcommands = policy_parser.add_subparsers(dest="policy_command", required=True)

    install_parser = policy_subcommands.add_parser("install", help="Install a policy pack")
    install_parser.add_argument("name", help="Policy pack name")
    install_parser.add_argument("--version", default=None, help="Policy pack version")
    install_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Install without signature verification",
    )
    install_parser.set_defaults(handler=_cmd_policy_install)

    list_parser = policy_subcommands.add_parser("list", help="List installed policy packs")
    list_parser.set_defaults(handler=_cmd_policy_list)

    verify_parser = policy_subcommands.add_parser("verify", help="Verify an installed policy pack")
    verify_parser.add_argument("name", help="Policy pack name")
    verify_parser.set_defaults(handler=_cmd_policy_verify)

    remove_parser = policy_subcommands.add_parser("remove", help="Remove an installed policy pack")
    remove_parser.add_argument("name", help="Policy pack name")
    remove_parser.set_defaults(handler=_cmd_policy_remove)

    audit_parser = policy_subcommands.add_parser("audit", help="Audit installed policy packs")
    audit_parser.set_defaults(handler=_cmd_policy_audit)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the Megent CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.handler(args))
    except RegistryVerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RegistryError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())