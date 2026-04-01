from __future__ import annotations

import argparse
import json
from typing import Sequence

from .exceptions import PolicyInstallError, PolicyVerificationError
from .registry import RegistryClient


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="megent")
    subparsers = parser.add_subparsers(dest="command")

    policy_parser = subparsers.add_parser("policy")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    install_parser = policy_sub.add_parser("install")
    install_parser.add_argument("name")
    install_parser.add_argument("--version", default="latest")
    install_parser.add_argument("--no-verify", action="store_true")

    policy_sub.add_parser("list")

    remove_parser = policy_sub.add_parser("remove")
    remove_parser.add_argument("name")

    verify_parser = policy_sub.add_parser("verify")
    verify_parser.add_argument("name")

    info_parser = policy_sub.add_parser("info")
    info_parser.add_argument("name")

    args = parser.parse_args(argv)
    client = RegistryClient()

    if args.command != "policy" or args.policy_command is None:
        parser.print_help()
        return 1

    if args.policy_command == "install":
        pack = client.install(args.name, version=args.version, verify=not args.no_verify)
        status = "verified" if pack.verified else "unverified"
        print(f"installed {pack.name}@{pack.version} ({status})")
        return 0

    if args.policy_command == "list":
        packs = client.list_installed()
        for pack in packs:
            badge = "[verified]" if pack.verified else "[unverified]"
            print(f"{pack.name}\t{pack.version}\t{pack.publisher}\t{badge}")
        return 0

    if args.policy_command == "remove":
        removed = client.remove(args.name)
        if not removed:
            print(f"policy not installed: {args.name}")
            return 1
        print(f"removed {args.name}")
        return 0

    if args.policy_command == "verify":
        valid = client.verify_installed(args.name)
        if valid:
            print(f"{args.name}: verified")
            return 0
        print(f"{args.name}: verification failed")
        return 1

    if args.policy_command == "info":
        pack = client.info(args.name)
        payload = {
            "name": pack.name,
            "version": pack.version,
            "publisher": pack.publisher,
            "verified": pack.verified,
            "signature": pack.signature,
            "public_key": pack.public_key,
        }
        print(json.dumps(payload, indent=2))
        return 0

    raise PolicyInstallError(f"Unknown policy command: {args.policy_command}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
