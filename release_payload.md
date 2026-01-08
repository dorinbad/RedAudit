# RedAudit v4.4.1 - CI Parity and Python 3.9 Compatibility

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espanol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.4.1/docs/releases/RELEASE_NOTES_v4.4.1_ES.md)

This release improves CI reliability for the Python 3.9 matrix and adds a local parity script to reproduce CI locally.

## Key Highlights

- Python 3.9 compatible dev lock markers for flake8 and pytest transitive dependencies to avoid resolver conflicts.
- Local CI parity script `scripts/ci_local.sh` to run pre-commit and pytest across Python 3.9-3.12.
- Faster unit tests for complete scan flows by disabling HyperScan-first only in tests.

**Full Release Notes**: https://github.com/dorinbadea/RedAudit/blob/v4.4.1/docs/releases/RELEASE_NOTES_v4.4.1.md
