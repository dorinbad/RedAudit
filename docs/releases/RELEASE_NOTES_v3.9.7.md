# RedAudit v3.9.7 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.7_ES.md)

**Release Date:** 2025-12-29

## Audit Quality Improvements

This hotfix focuses on **reducing false positives** and **aligning vulnerability counts** across CLI and report artifacts.

### Nuclei False-Positive Filtering

- Suspected Nuclei findings are filtered before consolidation.
- The Nuclei summary now reports total vs suspected counts for transparency.

### Consistent Vulnerability Counts

- Summary + run_manifest now include **raw vs consolidated** counts.
- CLI shows a single consolidated total, with raw count when it differs.

### JSONL Findings Titles

- `findings.jsonl` now includes `descriptive_title` for better downstream display.

### Dynamic OS Banner

- CLI banner now reflects the detected OS name with a safe `LINUX` fallback.

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
