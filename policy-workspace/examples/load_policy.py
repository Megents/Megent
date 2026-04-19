from pathlib import Path

from megent.policy import load_policy


if __name__ == "__main__":
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "read-only.yaml"
    policy = load_policy(str(policy_path))
    print(policy.name)
