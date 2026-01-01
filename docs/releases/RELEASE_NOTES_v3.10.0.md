# RedAudit v3.10.0 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.10.0_ES.md)

**Release Date:** 2026-01-01

## SmartScan Governance & Phase0 Enrichment

This release adds opt-in identity enrichment and stricter escalation gating to keep deep scans conservative by default.

### Phase0 Low-Impact Enrichment (Opt-in)

- Optional, short-timeout probes for reverse DNS, mDNS unicast, and SNMP sysDescr.
- Best-effort only; no retries, no long waits, and no global socket timeout changes.

### Identity-Gated Escalation

- Identity scoring is now explicit and traceable in SmartScan.
- Deep scan triggers require weak identity relative to the configured threshold.
- UDP-priority reorder applies only to low-visibility, very low-identity hosts, and never in stealth.

### Governance Controls

- New flags to tune behavior without changing defaults:
  - `--low-impact-enrichment`
  - `--identity-threshold`
  - `--deep-scan-budget`
- Deep scan budget is enforced safely under concurrency.

### Wizard & Localization

- Express/Standard/Exhaustive/Custom wizard flows can enable Phase0 with persisted defaults.
- New flag help text is localized for English and Spanish.

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
