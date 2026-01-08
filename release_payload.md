[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-green?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.3.2/docs/releases/RELEASE_NOTES_v4.3.2_ES.md)

# RedAudit v4.3.2 - Hotfix: Release Integrity

This release resolves a critical version mismatch that affected the v4.3.1 release.

## Fixed

- **Release Integrity**: Addressed an inconsistency where `pyproject.toml` remained at version `4.3.0` while `VERSION` was updated to `4.3.1`, causing CI/CD pipeline failures during integrity checks.
- **Maintenance**: Supersedes release v4.3.1 (which was technically identical in code behavior but failed self-validation tests).
