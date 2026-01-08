# RedAudit v4.3.2 - Hotfix: Release Integrity

This release resolves a critical version mismatch that affected the v4.3.1 release.

## Fixed

- **Release Integrity**: Addressed an inconsistency where `pyproject.toml` remained at version `4.3.0` while `VERSION` was updated to `4.3.1`, causing CI/CD pipeline failures during integrity checks.
- **Maintenance**: Supersedes release v4.3.1 (which was technically identical in code behavior but failed self-validation tests).
