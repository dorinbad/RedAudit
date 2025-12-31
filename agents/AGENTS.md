<!--
NOTE: This file is for contributor best practices (agentes humanos o no humanos) when working in this repository.
Keep it aligned with the repo root `AGENTS.md` and CI/pre-commit requirements.
-->

# Agent Instructions (RedAudit)

Follow the repository workflow in `AGENTS.md` (repo root). If there is any conflict, `AGENTS.md` is canonical.

Minimum expectations before opening a PR:

- Work on a branch; avoid committing directly to `main`.
- Run `pre-commit run --all-files` (or `python -m pre_commit run --all-files` in the venv).
- Run tests: `pytest tests/ -v`.
- Keep EN/ES documentation consistent when user-facing behavior changes.
