# Contributing to Megent

Thanks for your interest in contributing.

## Development Setup

```bash
git clone https://github.com/Megents/Megent.git
cd megent
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Run Checks

```bash
pytest -q
ruff check .
bandit -r megent
```

## Pull Request Guidelines

1. Keep changes focused and small.
2. Add or update tests for behavior changes.
3. Ensure all checks pass before opening a PR.
4. Document user-facing changes in README when relevant.

## Security Issues

Please do not post sensitive vulnerabilities publicly.
Use GitHub Security Advisories for private disclosure when possible.
